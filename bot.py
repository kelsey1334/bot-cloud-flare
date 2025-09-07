\
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

CF_API_BASE = "https://api.cloudflare.com/client/v4"

# -------- Utilities --------
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

async def cf_request(session: aiohttp.ClientSession, method: str, url: str, token: str, **kwargs):
    headers = kwargs.pop("headers", {})
    headers["Authorization"] = f"Bearer {token}"
    headers["Content-Type"] = "application/json"
    async with session.request(method, url, headers=headers, **kwargs) as resp:
        text = await resp.text()
        try:
            data = json.loads(text)
        except Exception:
            data = {"raw": text}
        return resp.status, data

# ---- Zone helpers ----
async def find_zone_by_name(session, token, domain: str):
    status, data = await cf_request(
        session, "GET",
        f"{CF_API_BASE}/zones?name={domain}&status=all&per_page=50",
        token
    )
    if status != 200:
        raise RuntimeError(f"Tìm zone thất bại ({status}): {data}")
    result = data.get("result", [])
    if result:
        z = result[0]
        return z["id"], z.get("name_servers", [])
    return None, []

async def create_zone(session, token, domain: str):
    payload = {"name": domain, "type": "full", "jump_start": False}
    status, data = await cf_request(session, "POST", f"{CF_API_BASE}/zones", token, data=json.dumps(payload))
    if status == 400 and isinstance(data, dict) and data.get("errors"):
        # try with account id
        alt_status, accounts = await cf_request(session, "GET", f"{CF_API_BASE}/accounts", token)
        if alt_status == 200 and isinstance(accounts, dict) and accounts.get("result"):
            acct_id = accounts["result"][0]["id"]
            payload = {"name": domain, "type": "full", "jump_start": False, "account": {"id": acct_id}}
            status, data = await cf_request(session, "POST", f"{CF_API_BASE}/zones", token, data=json.dumps(payload))
    if status not in (200, 201):
        raise RuntimeError(f"Create zone thất bại ({status}): {data}")
    zone = data["result"]
    return zone["id"], zone.get("name_servers", [])

async def get_zone(session, token, zone_id: str):
    status, data = await cf_request(session, "GET", f"{CF_API_BASE}/zones/{zone_id}", token)
    if status != 200:
        raise RuntimeError(f"Get zone thất bại ({status}): {data}")
    return data["result"]

# ---- DNS helpers ----
async def delete_all_dns_records(session, token, zone_id: str):
    page = 1
    per_page = 5000
    to_delete = []
    while True:
        status, data = await cf_request(
            session, "GET",
            f"{CF_API_BASE}/zones/{zone_id}/dns_records?per_page={per_page}&page={page}",
            token
        )
        if status != 200:
            raise RuntimeError(f"Liệt kê DNS records thất bại ({status}): {data}")
        result = data.get("result", [])
        if not result:
            break
        to_delete.extend([r["id"] for r in result])
        if len(result) < per_page:
            break
        page += 1

    for rid in to_delete:
        await cf_request(session, "DELETE", f"{CF_API_BASE}/zones/{zone_id}/dns_records/{rid}", token)
    return len(to_delete)

async def create_a_record(session, token, zone_id: str, domain: str, ip: str):
    payload = {"type": "A", "name": domain, "content": ip, "ttl": 1, "proxied": False}
    status, data = await cf_request(session, "POST", f"{CF_API_BASE}/zones/{zone_id}/dns_records", token, data=json.dumps(payload))
    if status not in (200, 201):
        raise RuntimeError(f"Tạo A record thất bại ({status}): {data}")
    return data["result"]["id"]

async def create_cname_www(session, token, zone_id: str, target_domain: str):
    payload = {"type": "CNAME", "name": "www", "content": target_domain, "ttl": 1, "proxied": False}
    status, data = await cf_request(session, "POST", f"{CF_API_BASE}/zones/{zone_id}/dns_records", token, data=json.dumps(payload))
    if status not in (200, 201):
        raise RuntimeError(f"Tạo CNAME www thất bại ({status}): {data}")
    return data["result"]["id"]

async def set_free_plan_if_possible(session, token, zone_id: str):
    status, plans = await cf_request(session, "GET", f"{CF_API_BASE}/zones/{zone_id}/available_plans", token)
    if status != 200:
        return "skip"
    free_id = None
    for p in plans.get("result", []):
        if (p.get("legacy_id") == "free") or (str(p.get("name", "")).lower() == "free"):
            free_id = p["id"]
            break
    if not free_id:
        return "not_found"
    payload = {"rate_plan": {"id": free_id}}
    status, _ = await cf_request(session, "PUT", f"{CF_API_BASE}/zones/{zone_id}/subscription", token, data=json.dumps(payload))
    if status not in (200, 201):
        return "failed"
    return "ok"

# ---- SSL helpers ----
async def create_origin_cert(session, token, zone_id, domain: str):
    # Origin Client Certificate (RSA 10y)
    payload = {
        "hostnames": [domain, f"*.{domain}"],
        "request_type": "origin-rsa",
        "requested_validity": 3650
    }
    status, data = await cf_request(
        session, "POST",
        f"{CF_API_BASE}/zones/{zone_id}/origin_tls_client_auth/hostnames/certificates",
        token,
        data=json.dumps(payload)
    )
    if status not in (200, 201):
        raise RuntimeError(f"Tạo SSL thất bại ({status}): {data}")
    return data["result"]  # certificate, private_key, expires_on

# ---- Main per-row flow ----
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
        # find-or-create zone
        zone_id, nameservers = await find_zone_by_name(session, token, domain)
        created = False
        if not zone_id:
            zone_id, nameservers_init = await create_zone(session, token, domain)
            created = True
            zone = await get_zone(session, token, zone_id)
            nameservers = zone.get("name_servers", nameservers_init) or nameservers_init
        else:
            # refresh nameservers
            zone = await get_zone(session, token, zone_id)
            nameservers = zone.get("name_servers", nameservers) or nameservers

        # DNS reset
        await delete_all_dns_records(session, token, zone_id)
        await create_a_record(session, token, zone_id, domain, ip)
        await create_cname_www(session, token, zone_id, domain)

        # plan if new
        plan_status = "skip"
        if created:
            plan_status = await set_free_plan_if_possible(session, token, zone_id)

        # SSL
        cert_data = await create_origin_cert(session, token, zone_id, domain)
        certificate = cert_data.get("certificate", "")
        private_key = cert_data.get("private_key", "")

        return {
            "domain": domain,
            "ok": True,
            "nameservers": nameservers,
            "plan": plan_status,
            "certificate": certificate,
            "private_key": private_key,
            "error": ""
        }
    except Exception as e:
        return {"domain": domain, "ok": False, "error": str(e), "nameservers": [], "plan": "skip"}

# -------- Telegram Handlers --------
START_TEXT = (
    "Gửi file Excel (.xlsx): domain, ip_server, cloudflare_token.\n"
    "- Nếu zone đã có: bot chỉ reset DNS, tạo bản ghi mới, tạo SSL và trả về key/cert.\n"
    "- Nếu zone chưa có: bot tạo zone rồi làm các bước trên.\n"
    "- Mỗi domain gửi ZIP (key+cert) và tổng hợp báo cáo .xlsx."
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
            "plan_status": r.get("plan", ""),
            "error": r.get("error", "")
        })
    df = pd.DataFrame(rows, columns=["domain", "status", "nameserver_1", "nameserver_2", "plan_status", "error"])
    bio = BytesIO()
    with pd.ExcelWriter(bio, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="report")
    bio.seek(0)
    return bio

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    if not doc or not doc.file_name.lower().endswith(".xlsx"):
        await update.message.reply_text("Vui lòng gửi file Excel .xlsx")
        return

    await update.message.reply_text("Đang xử lý file, vui lòng đợi…")

    file = await doc.get_file()
    file_bytes = await file.download_as_bytearray()
    excel_io = BytesIO(file_bytes)

    try:
        df = pd.read_excel(excel_io)
    except Exception as e:
        await update.message.reply_text(f"Không đọc được Excel: {e}")
        return

    df.columns = [str(c).strip().lower() for c in df.columns]
    required = {"domain", "ip_server", "cloudflare_token"}
    if not required.issubset(set(df.columns)):
        await update.message.reply_text("Thiếu cột bắt buộc. Cần đủ: domain, ip_server, cloudflare_token")
        return

    results = []
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=180)) as session:
        for idx, row in df.iterrows():
            row_dict = {k: ("" if pd.isna(v) else str(v)) for k, v in row.items()}
            res = await process_row(session, row_dict)
            results.append(res)

            if res.get("ok"):
                ns_list = res.get("nameservers") or []
                ns_msg = "\n".join([f"- {ns}" for ns in ns_list[:2]]) if ns_list else "(Cloudflare chưa trả NS)"
                priv_key = res.get("private_key", "")
                cert = res.get("certificate", "")

                # HTML code blocks for copy
                msg = (
                    f"✅ <b>{res['domain']}</b>\n"
                    f"<b>Nameservers:</b>\n{ns_msg}\n\n"
                    f"<b>Private Key:</b>\n<pre>{priv_key}</pre>\n"
                    f"<b>Certificate:</b>\n<pre>{cert}</pre>"
                )
                await update.message.reply_text(msg, parse_mode="HTML", disable_web_page_preview=True)

                # Send ZIP with key+cert
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
                await update.message.reply_text(
                    f"❌ {res.get('domain','(n/a)')} - Lỗi: {res.get('error')}"
                )
            await asyncio.sleep(0.5)

    report_io = build_report(results)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cloudflare_report_{ts}.xlsx"
    await update.message.reply_document(
        document=report_io,
        filename=filename,
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
