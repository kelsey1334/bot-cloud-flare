import asyncio
import os
import re
import ipaddress
import json
from io import BytesIO
from datetime import datetime

import pandas as pd
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
import aiohttp
import zipfile

load_dotenv()
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

CF_API = "https://api.cloudflare.com/client/v4"

# ========== Utils ==========
def normalize_domain(d: str) -> str:
    d = (d or "").strip().strip(".").lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    return d

def validate_ipv4(ip: str) -> str:
    ip = (ip or "").strip()
    try:
        return str(ipaddress.IPv4Address(ip))
    except Exception:
        raise ValueError(f"IPv4 không hợp lệ: {ip!r}")

async def cf(session: aiohttp.ClientSession, method: str, url: str, token: str, **kwargs):
    headers = kwargs.pop("headers", {})
    headers["Authorization"] = f"Bearer {token}"
    headers["Content-Type"] = "application/json"
    async with session.request(method, url, headers=headers, **kwargs) as r:
        txt = await r.text()
        try:
            data = json.loads(txt)
        except Exception:
            data = {"raw": txt}
        return r.status, data

# ========== Zone ==========
async def get_accounts(session, token):
    st, data = await cf(session, "GET", f"{CF_API}/accounts", token)
    if st != 200:
        raise RuntimeError(f"Lấy accounts thất bại ({st}): {data}")
    res = data.get("result") or []
    if not res:
        raise RuntimeError("Không có account nào cho token.")
    return res

async def find_zone(session, token, domain: str):
    st, data = await cf(session, "GET", f"{CF_API}/zones?name={domain}&status=all&per_page=50", token)
    if st != 200:
        raise RuntimeError(f"Tìm zone thất bại ({st}): {data}")
    items = data.get("result") or []
    if items:
        z = items[0]
        return z["id"], z
    return None, None

async def create_zone(session, token, domain: str):
    # Luôn kèm account.id để tạo zone trong account hiện tại
    acct_id = (await get_accounts(session, token))[0]["id"]
    payload = {"name": domain, "type": "full", "jump_start": False, "account": {"id": acct_id}}
    st, data = await cf(session, "POST", f"{CF_API}/zones", token, data=json.dumps(payload))
    if st not in (200, 201):
        raise RuntimeError(f"Create zone thất bại ({st}): {data}")
    return data["result"]["id"], data["result"]

async def get_zone(session, token, zone_id: str):
    st, data = await cf(session, "GET", f"{CF_API}/zones/{zone_id}", token)
    if st != 200:
        raise RuntimeError(f"Get zone thất bại ({st}): {data}")
    return data["result"]

def extract_nameservers(zone_obj: dict):
    return list(zone_obj.get("vanity_name_servers") or zone_obj.get("name_servers") or [])

# ========== DNS ==========
async def list_dns_records(session, token, zone_id: str):
    all_items = []
    page = 1
    per_page = 500
    while True:
        st, data = await cf(session, "GET",
                            f"{CF_API}/zones/{zone_id}/dns_records?per_page={per_page}&page={page}",
                            token)
        if st != 200:
            raise RuntimeError(f"List DNS thất bại ({st}): {data}")
        items = data.get("result") or []
        if not items:
            break
        all_items.extend(items)
        if len(items) < per_page:
            break
        page += 1
    return all_items

async def delete_all_dns_records(session, token, zone_id: str) -> int:
    items = await list_dns_records(session, token, zone_id)
    deleted = 0
    for r in items:
        rid = r["id"]
        st, data = await cf(session, "DELETE", f"{CF_API}/zones/{zone_id}/dns_records/{rid}", token)
        if st not in (200, 204):
            raise RuntimeError(f"Xoá record {rid} thất bại ({st}): {data}")
        deleted += 1
        await asyncio.sleep(0.05)
    # verify empty
    left = await list_dns_records(session, token, zone_id)
    if left:
        names = [f"{x['type']} {x['name']}" for x in left]
        raise RuntimeError(f"Vẫn còn DNS chưa xoá: {', '.join(names)[:300]}")
    return deleted

async def create_a_apex(session, token, zone_id: str, domain: str, ip: str):
    payload = {"type": "A", "name": domain, "content": ip, "ttl": 1, "proxied": False}
    st, data = await cf(session, "POST", f"{CF_API}/zones/{zone_id}/dns_records", token, data=json.dumps(payload))
    if st not in (200, 201):
        raise RuntimeError(f"Tạo A @ thất bại ({st}): {data}")
    return data["result"]["id"]

async def create_cname_www(session, token, zone_id: str, domain: str):
    payload = {"type": "CNAME", "name": "www", "content": domain, "ttl": 1, "proxied": False}
    st, data = await cf(session, "POST", f"{CF_API}/zones/{zone_id}/dns_records", token, data=json.dumps(payload))
    if st not in (200, 201):
        raise RuntimeError(f"Tạo CNAME www thất bại ({st}): {data}")
    return data["result"]["id"]

# ========== Origin CA (SSL) ==========
async def create_origin_cert(session, token, domain: str):
    # Endpoint đúng của Origin CA: KHÔNG theo /zones
    payload = {
        "hostnames": [domain, f"*.{domain}"],
        "request_type": "origin-rsa",
        "requested_validity": 3650
    }
    st, data = await cf(session, "POST", f"{CF_API}/certificates", token, data=json.dumps(payload))
    if st not in (200, 201):
        raise RuntimeError(f"Tạo SSL thất bại ({st}): {data}")
    return data["result"]

# ========== Per-row: đúng thứ tự yêu cầu ==========
async def process_row(session, row: dict) -> dict:
    domain_raw = str(row.get("domain", "")).strip()
    ip_raw = str(row.get("ip_server", "")).strip()
    token = str(row.get("cloudflare_token", "")).strip()

    if not domain_raw or not ip_raw or not token:
        return {"domain": domain_raw or "(trống)", "ok": False, "error": "Thiếu domain/ip_server/cloudflare_token"}

    domain = normalize_domain(domain_raw)
    try:
        ip = validate_ipv4(ip_raw)
    except Exception as e:
        return {"domain": domain, "ok": False, "error": str(e)}

    try:
        # 1) ADD ZONE (find or create)
        zone_id, zone_obj = await find_zone(session, token, domain)
        if not zone_id:
            zone_id, zone_obj = await create_zone(session, token, domain)

        # 2) DELETE ALL RECORDS (verify empty)
        await delete_all_dns_records(session, token, zone_id)

        # 3) ADD RECORDS (A @, CNAME www) + verify
        a_id = await create_a_apex(session, token, zone_id, domain, ip)
        c_id = await create_cname_www(session, token, zone_id, domain)
        cur = await list_dns_records(session, token, zone_id)
        need = {("A", domain), ("CNAME", f"www.{domain}")}
        have = {(x["type"], x["name"]) for x in cur}
        missing = need - have
        if missing:
            raise RuntimeError(f"Bản ghi thiếu sau khi tạo: {missing}")

        # 4) GET NAMESERVERS
        zone_obj = await get_zone(session, token, zone_id)
        ns_list = extract_nameservers(zone_obj)

        # 5) CREATE SSL (Origin CA)
        cert_obj = await create_origin_cert(session, token, domain)

        return {
            "domain": domain,
            "ok": True,
            "nameservers": ns_list,
            "certificate": cert_obj.get("certificate", ""),
            "private_key": cert_obj.get("private_key", ""),
            "dns_created": {"A_id": a_id, "CNAME_id": c_id},
            "error": ""
        }

    except Exception as e:
        return {"domain": domain, "ok": False, "error": str(e), "nameservers": [], "certificate": "", "private_key": ""}

# ========== Telegram ==========
START_TEXT = (
    "Gửi Excel (.xlsx): domain, ip_server, cloudflare_token.\n"
    "Quy trình: ADD ZONE → XOÁ TOÀN BỘ RECORD → THÊM RECORD → LẤY NAMESERVER → TẠO SSL (Origin CA)."
)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(START_TEXT)

def build_report(results):
    rows = []
    for r in results:
        ns = r.get("nameservers") or []
        rows.append({
            "domain": r.get("domain", ""),
            "status": "success" if r.get("ok") else "failed",
            "nameserver_1": ns[0] if len(ns) >= 1 else "",
            "nameserver_2": ns[1] if len(ns) >= 2 else "",
            "error": r.get("error", "")
        })
    df = pd.DataFrame(rows, columns=["domain", "status", "nameserver_1", "nameserver_2", "error"])
    bio = BytesIO()
    with pd.ExcelWriter(bio, engine="openpyxl") as w:
        df.to_excel(w, index=False, sheet_name="report")
    bio.seek(0)
    return bio

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    if not doc or not doc.file_name.lower().endswith(".xlsx"):
        await update.message.reply_text("Vui lòng gửi file Excel .xlsx")
        return

    await update.message.reply_text("Đang xử lý file…")

    file = await doc.get_file()
    excel_io = BytesIO(await file.download_as_bytearray())

    try:
        df = pd.read_excel(excel_io)
    except Exception as e:
        await update.message.reply_text(f"Không đọc được Excel: {e}")
        return

    df.columns = [str(c).strip().lower() for c in df.columns]
    required = {"domain", "ip_server", "cloudflare_token"}
    if not required.issubset(set(df.columns)):
        await update.message.reply_text("Thiếu cột: domain, ip_server, cloudflare_token")
        return

    results = []
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=240)) as session:
        for _, row in df.iterrows():
            row_dict = {k: ("" if pd.isna(v) else str(v)) for k, v in row.items()}
            res = await process_row(session, row_dict)
            results.append(res)

            if res.get("ok"):
                ns_list = res.get("nameservers") or []
                ns_msg = "\n".join([f"- {ns}" for ns in ns_list[:2]]) if ns_list else "(chưa có NS)"
                priv_key = res.get("private_key", "")
                cert = res.get("certificate", "")
                dns_created = res.get("dns_created", {})

                msg = (
                    f"✅ <b>{res['domain']}</b>\n"
                    f"<b>Nameservers:</b>\n{ns_msg}\n\n"
                    f"<b>DNS created:</b> A_id={dns_created.get('A_id')} | CNAME_id={dns_created.get('CNAME_id')}\n\n"
                    f"<b>Private Key:</b>\n<pre>{priv_key}</pre>\n"
                    f"<b>Certificate:</b>\n<pre>{cert}</pre>"
                )
                await update.message.reply_text(msg, parse_mode="HTML", disable_web_page_preview=True)

                # Gửi ZIP key + cert
                zip_buffer = BytesIO()
                with zipfile.ZipFile(zip_buffer, "w") as z:
                    z.writestr(f"{res['domain']}.key", priv_key)
                    z.writestr(f"{res['domain']}.crt", cert)
                zip_buffer.seek(0)
                await update.message.reply_document(
                    document=zip_buffer,
                    filename=f"{res['domain']}_ssl.zip",
                    caption=f"SSL files cho {res['domain']}"
                )
            else:
                await update.message.reply_text(f"❌ {res.get('domain','(n/a)')} - Lỗi: {res.get('error')}")
            await asyncio.sleep(0.4)

    report_io = build_report(results)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    await update.message.reply_document(
        document=report_io,
        filename=f"cloudflare_report_{ts}.xlsx",
        caption=f"Báo cáo Cloudflare ({ts})"
    )

    ok_count = sum(1 for r in results if r.get("ok"))
    fail_count = len(results) - ok_count
    await update.message.reply_text(f"Hoàn tất. Thành công: {ok_count} | Thất bại: {fail_count}")

def main():
    if not BOT_TOKEN:
        raise RuntimeError("Thiếu TELEGRAM_BOT_TOKEN trong .env")
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    print("Bot started.")
    app.run_polling(close_loop=False)

if __name__ == "__main__":
    main()
