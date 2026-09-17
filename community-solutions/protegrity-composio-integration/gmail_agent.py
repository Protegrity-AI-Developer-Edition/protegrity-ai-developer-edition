"""
Gmail IMAP/SMTP agent using an App Password — no OAuth redirect URI needed.

Setup (one-time):
  1. Enable 2-Step Verification on your Google account:
     https://myaccount.google.com/security
  2. Generate an App Password:
     https://myaccount.google.com/apppasswords
     (Select app: Mail, device: Other → name it "ProtegrityDemo" → copy 16-char password)
  3. Enter your Gmail address and that 16-char password in the UI.
"""
from __future__ import annotations
import imaplib, smtplib, email as elib, logging, re
from datetime import datetime, timedelta, timezone
from email.header import decode_header as _dh
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

IMAP_HOST = "imap.gmail.com"
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587


def _decode(val: str) -> str:
    parts = _dh(val or "")
    out = []
    for part, enc in parts:
        if isinstance(part, bytes):
            out.append(part.decode(enc or "utf-8", errors="replace"))
        else:
            out.append(str(part))
    return " ".join(out).strip()


def _body(msg) -> str:
    """Extract the plaintext body from an email.Message."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and "attachment" not in str(part.get("Content-Disposition", "")):
                payload = part.get_payload(decode=True)
                return payload.decode(part.get_content_charset() or "utf-8", errors="replace") if payload else ""
    else:
        payload = msg.get_payload(decode=True)
        return payload.decode(msg.get_content_charset() or "utf-8", errors="replace") if payload else ""
    return ""


class GmailClient:
    def __init__(self, email_addr: str, app_password: str):
        self.email_addr = email_addr.strip()
        self.app_password = app_password.replace(" ", "").strip()

    def test_connection(self) -> Dict[str, Any]:
        try:
            with imaplib.IMAP4_SSL(IMAP_HOST) as imap:
                imap.login(self.email_addr, self.app_password)
                return {"ok": True, "email": self.email_addr}
        except imaplib.IMAP4.error as e:
            msg = str(e)
            if "AUTHENTICATIONFAILED" in msg or "Invalid credentials" in msg:
                return {"ok": False, "error": "Authentication failed. Check your App Password (not your regular Google password)."}
            return {"ok": False, "error": msg}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def fetch_unread_recent(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Return unread emails from the last `hours` hours (max 20)."""
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%d-%b-%Y")
        results = []
        with imaplib.IMAP4_SSL(IMAP_HOST) as imap:
            imap.login(self.email_addr, self.app_password)
            imap.select("INBOX")
            _, ids_raw = imap.search(None, f'(UNSEEN SINCE "{since}")')
            ids = ids_raw[0].split()
            logger.info("Found %d unread emails since %s", len(ids), since)
            for mid in ids[-20:]:  # newest last, cap at 20
                _, data = imap.fetch(mid, "(RFC822)")
                raw = data[0][1]
                msg = elib.message_from_bytes(raw)
                results.append({
                    "imap_id": mid.decode(),
                    "msg_id": msg.get("Message-ID", ""),
                    "from": _decode(msg.get("From", "")),
                    "subject": _decode(msg.get("Subject", "(no subject)")),
                    "body": _body(msg)[:2000],
                    "date": msg.get("Date", ""),
                })
        return results

    def send_reply(self, original: Dict[str, Any], body_text: str) -> None:
        reply = MIMEMultipart("alternative")
        reply["From"] = self.email_addr
        reply["To"] = original["from"]
        subj = original["subject"]
        reply["Subject"] = subj if subj.lower().startswith("re:") else f"Re: {subj}"
        reply["In-Reply-To"] = original.get("msg_id", "")
        reply["References"] = original.get("msg_id", "")
        reply.attach(MIMEText(body_text, "plain"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(self.email_addr, self.app_password)
            smtp.sendmail(self.email_addr, original["from"], reply.as_string())
        logger.info("Reply sent to %s re: %s", original["from"], original["subject"])

    def mark_as_read(self, imap_id: str) -> None:
        with imaplib.IMAP4_SSL(IMAP_HOST) as imap:
            imap.login(self.email_addr, self.app_password)
            imap.select("INBOX")
            imap.store(imap_id, "+FLAGS", "\\Seen")
