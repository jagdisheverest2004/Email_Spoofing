import streamlit as st
import imaplib
import email
from email.utils import parseaddr
import re

IMAP_SERVER = "imap.gmail.com"

def extract_result(field, auth_text):
    pattern = rf"{field}\s*=\s*([\w\-]+)"
    match = re.search(pattern, auth_text, re.IGNORECASE)
    return match.group(1).lower() if match else "Not Found"

def extract_sender_ip(raw_email):
    ip_match = re.search(r"client-ip=([\d\.]+)", raw_email)
    return ip_match.group(1) if ip_match else "Unknown"

def extract_return_path(raw_email):
    match = re.search(r"Return-Path:\s*<(.+?)>", raw_email, re.IGNORECASE)
    return match.group(1).strip() if match else "Unknown"

def extract_authentication_results(raw_email):
    lines = raw_email.splitlines()
    auth_block = ""
    capturing = False
    for line in lines:
        if "Authentication-Results" in line:
            capturing = True
            auth_block += line.strip() + " "
        elif capturing:
            if line.startswith(" ") or line.startswith("\t"):
                auth_block += line.strip() + " "
            else:
                break
    return auth_block.strip()

def analyze_email(raw_email):
    msg = email.message_from_string(raw_email)
    from_email = parseaddr(msg.get('From') or "")[1] or "Unknown"
    subject = msg.get('Subject', "(No Subject)")
    sender_ip = extract_sender_ip(raw_email)
    return_path = extract_return_path(raw_email)
    auth_text = extract_authentication_results(raw_email)

    spf = extract_result("spf", auth_text)
    dkim = extract_result("dkim", auth_text)
    dmarc = extract_result("dmarc", auth_text)

    reasons = []
    if spf != "pass":
        reasons.append("SPF failed or missing")
    if dkim != "pass":
        reasons.append("DKIM failed or missing")
    if dmarc != "pass":
        reasons.append("DMARC failed or missing")
    if from_email.lower() != return_path.lower():
        if spf != "pass" or dkim != "pass" or dmarc != "pass":
            reasons.append(f"From ≠ Return-Path: {from_email} ≠ {return_path}")

    result = "Malicious" if reasons else "Benign"

    return {
        "From": from_email,
        "Return-Path": return_path,
        "Subject": subject,
        "Sender IP": sender_ip,
        "SPF Check": spf,
        "DKIM Check": dkim,
        "DMARC Check": dmarc,
        "Overall Result": result,
        "Reasons": reasons
    }

def fetch_latest_emails(email_addr, app_password, num_emails):
    reports = []
    imap = imaplib.IMAP4_SSL(IMAP_SERVER)
    imap.login(email_addr, app_password)
    imap.select("inbox")
    typ, data = imap.search(None, "ALL")
    email_ids = data[0].split()[-num_emails:]

    for eid in reversed(email_ids):
        typ, msg_data = imap.fetch(eid, "(RFC822)")
        # Ensure we are decoding the correct part of the fetched data
        if isinstance(msg_data[0], tuple):
            raw_email_bytes = msg_data[0][1]
        else:
            raw_email_bytes = msg_data[0]
        if raw_email_bytes is None:
            raw_email = ""
        elif isinstance(raw_email_bytes, memoryview):
            raw_email = raw_email_bytes.tobytes().decode(errors="ignore")
        elif isinstance(raw_email_bytes, bytes):
            raw_email = raw_email_bytes.decode(errors="ignore")
        else:
            raw_email = str(raw_email_bytes)
        report = analyze_email(raw_email)
        reports.append(report)

    imap.logout()
    return reports

# Streamlit UI
st.title("📧 Gmail Email Spoofing Scanner Dashboard")

email_addr = st.text_input("📨 Enter your Gmail address")
app_password = st.text_input("🔑 Enter Gmail App Password", type="password")
scan_mode = st.radio("Scan Mode", ["Scan Last N Emails", "Paste Raw Email Content"])
num_emails = st.number_input("📬 Number of recent emails to scan", min_value=1, max_value=20, value=5, disabled=(scan_mode == "Paste Raw Email Content"))

# Force-enable the raw email input based on radio selection
if scan_mode == "Paste Raw Email Content":
    raw_input_email = st.text_area("📄 Paste raw email message here (headers + body from Gmail's 'Show Original')", height=300)
else:
    raw_input_email = ""

if st.button("🚀 Scan Emails"):
    with st.spinner("🔍 Scanning emails..."):
        try:
            if scan_mode == "Scan Last N Emails":
                reports = fetch_latest_emails(email_addr, app_password, num_emails)
                for idx, report in enumerate(reports, 1):
                    st.subheader(f"📥 Email #{idx}: {report['Subject']}")
                    for key, value in report.items():
                        if isinstance(value, list):
                            st.write(f"**{key}**: {', '.join(value)}")
                        else:
                            st.write(f"**{key}**: {value}")
                    st.markdown("---")
            else:
                if raw_input_email.strip():
                    report = analyze_email(raw_input_email)
                    st.subheader(f"📥 Raw Email Analysis: {report['Subject']}")
                    for key, value in report.items():
                        if isinstance(value, list):
                            st.write(f"**{key}**: {', '.join(value)}")
                        else:
                            st.write(f"**{key}**: {value}")
                else:
                    st.warning("⚠️ Please paste a valid raw email to analyze.")
        except Exception as e:
            st.error(f"❌ Failed to scan emails: {e}")
