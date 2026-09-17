"""
Gmail REST API client — replaces IMAP/SMTP with Google's HTTPS APIs.

IMAP (port 993) is blocked in many cloud/corporate environments; this module
uses the Gmail REST API over HTTPS (port 443) instead.

OAuth2 setup (reuses the same Google Cloud project as Drive):
  1. Set GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET (.env or environment)
  2. Call /api/gmail/auth-url  → redirects user to Google consent page
  3. Google redirects to /api/gmail/callback → token saved in
     google_auth/gmail_token.json
  4. All subsequent calls (fetch / send / mark-read) use that saved token.

Enable in Google Cloud Console:
  - Gmail API  (APIs & Services → Library → Gmail API → Enable)
"""
from __future__ import annotations

import base64, json, logging, os
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

TOKEN_PATH = Path(__file__).parent / "google_auth" / "gmail_token.json"

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",   # read + mark read
    "https://www.googleapis.com/auth/gmail.send",      # send replies
]

DEFAULT_REDIRECT_URI = os.environ.get(
    "GMAIL_REDIRECT_URI", "http://localhost:8900/api/gmail/callback"
)


# ── OAuth helpers ─────────────────────────────────────────────────────────────

def _client_config(client_id: str, client_secret: str, redirect_uri: str) -> dict:
    return {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [redirect_uri],
        }
    }


def get_auth_url(
    client_id: str,
    client_secret: str,
    redirect_uri: Optional[str] = None,
) -> Tuple[str, str]:
    """Return (auth_url, state) for the Gmail OAuth2 consent page."""
    from google_auth_oauthlib.flow import Flow

    redirect_uri = redirect_uri or DEFAULT_REDIRECT_URI
    flow = Flow.from_client_config(
        _client_config(client_id, client_secret, redirect_uri),
        scopes=SCOPES,
        redirect_uri=redirect_uri,
    )
    url, state = flow.authorization_url(access_type="offline", prompt="consent")
    # Persist auth params so the callback can exchange the code
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    (TOKEN_PATH.parent / "gmail_state.json").write_text(
        json.dumps({"client_id": client_id, "client_secret": client_secret,
                    "state": state, "redirect_uri": redirect_uri})
    )
    return url, state


def exchange_code(code: str, state: str = "") -> Any:
    """Exchange a one-time authorization code for tokens (reads saved state file)."""
    from google_auth_oauthlib.flow import Flow

    state_path = TOKEN_PATH.parent / "gmail_state.json"
    if not state_path.exists():
        raise RuntimeError("Gmail OAuth state not found. Please start from /api/gmail/auth-url")
    saved = json.loads(state_path.read_text())
    client_id     = saved["client_id"]
    client_secret = saved["client_secret"]
    redirect_uri  = saved.get("redirect_uri", DEFAULT_REDIRECT_URI)

    flow = Flow.from_client_config(
        _client_config(client_id, client_secret, redirect_uri),
        scopes=SCOPES,
        state=saved.get("state"),
        redirect_uri=redirect_uri,
    )
    flow.fetch_token(code=code)
    creds = flow.credentials
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_PATH.write_text(
        json.dumps({
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": list(creds.scopes or SCOPES),
        })
    )
    logger.info("Gmail OAuth2 token saved to %s", TOKEN_PATH)
    return creds


def load_credentials() -> Optional[Any]:
    """Load stored Gmail OAuth credentials, refreshing if expired."""
    if not TOKEN_PATH.exists():
        return None
    data = json.loads(TOKEN_PATH.read_text())
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request

    creds = Credentials(
        token=data.get("token"),
        refresh_token=data.get("refresh_token"),
        token_uri=data.get("token_uri", "https://oauth2.googleapis.com/token"),
        client_id=data.get("client_id"),
        client_secret=data.get("client_secret"),
        scopes=data.get("scopes", SCOPES),
    )
    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            TOKEN_PATH.write_text(
                json.dumps({
                    "token": creds.token,
                    "refresh_token": creds.refresh_token,
                    "token_uri": creds.token_uri,
                    "client_id": creds.client_id,
                    "client_secret": creds.client_secret,
                    "scopes": list(creds.scopes or SCOPES),
                })
            )
        except Exception as e:
            logger.warning("Gmail token refresh failed: %s", e)
            return None
    return creds if creds.valid else None


def is_connected() -> bool:
    return load_credentials() is not None


def get_connected_email() -> Optional[str]:
    """Return the Gmail address of the connected account, or None."""
    try:
        creds = load_credentials()
        if not creds:
            return None
        from googleapiclient.discovery import build
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        profile = service.users().getProfile(userId="me").execute()
        return profile.get("emailAddress")
    except Exception:
        return None


def disconnect():
    if TOKEN_PATH.exists():
        TOKEN_PATH.unlink()


# ── Gmail REST API client ─────────────────────────────────────────────────────

class GmailAPIClient:
    """
    Implements the same interface as the old GmailClient (IMAP) but talks to
    the Gmail REST API over HTTPS — no port-993 dependency.

    Used by email_pipeline.run_email_pipeline() unchanged.
    """

    def __init__(self, creds=None):
        from googleapiclient.discovery import build

        if creds is None:
            creds = load_credentials()
        if creds is None:
            raise RuntimeError(
                "Gmail not connected — please authorize via /api/gmail/auth-url"
            )
        self.creds = creds
        self.service = build("gmail", "v1", credentials=creds, cache_discovery=False)

    # ── public interface (matches old GmailClient) ────────────────────────────

    def test_connection(self) -> Dict[str, Any]:
        try:
            profile = self.service.users().getProfile(userId="me").execute()
            return {"ok": True, "email": profile.get("emailAddress", "")}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def fetch_unread_recent(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Fetch unread messages from the last `hours` hours (max 20)."""
        since_ts = int(
            (datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp()
        )
        query = f"is:unread after:{since_ts}"
        resp = self.service.users().messages().list(
            userId="me", q=query, maxResults=20
        ).execute()

        results: List[Dict[str, Any]] = []
        for m in resp.get("messages", []):
            msg = self.service.users().messages().get(
                userId="me", id=m["id"], format="full"
            ).execute()
            hdrs = {
                h["name"].lower(): h["value"]
                for h in msg.get("payload", {}).get("headers", [])
            }
            results.append({
                "imap_id": m["id"],          # key kept for email_pipeline.py compat
                "msg_id": hdrs.get("message-id", ""),
                "thread_id": msg.get("threadId", ""),
                "from": hdrs.get("from", ""),
                "subject": hdrs.get("subject", "(no subject)"),
                "body": self._plain_body(msg.get("payload", {}))[:2000],
                "date": hdrs.get("date", ""),
            })
        logger.info("Fetched %d unread messages via Gmail API", len(results))
        return results

    def send_reply(self, original: Dict[str, Any], body_text: str) -> None:
        reply = MIMEMultipart("alternative")
        reply["To"] = original["from"]
        subj = original.get("subject", "")
        reply["Subject"] = subj if subj.lower().startswith("re:") else f"Re: {subj}"
        if original.get("msg_id"):
            reply["In-Reply-To"] = original["msg_id"]
            reply["References"] = original["msg_id"]
        reply.attach(MIMEText(body_text, "plain"))

        raw = base64.urlsafe_b64encode(reply.as_bytes()).decode()
        body: Dict[str, Any] = {"raw": raw}
        if original.get("thread_id"):
            body["threadId"] = original["thread_id"]

        self.service.users().messages().send(userId="me", body=body).execute()
        logger.info("Reply sent to %s", original["from"])

    def mark_as_read(self, imap_id: str) -> None:
        self.service.users().messages().modify(
            userId="me",
            id=imap_id,
            body={"removeLabelIds": ["UNREAD"]},
        ).execute()

    # ── internal helpers ──────────────────────────────────────────────────────

    def _plain_body(self, payload: dict) -> str:
        mime = payload.get("mimeType", "")
        if mime == "text/plain":
            data = payload.get("body", {}).get("data", "")
            return (
                base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
                if data else ""
            )
        for part in payload.get("parts", []):
            if part.get("mimeType") == "text/plain":
                data = part.get("body", {}).get("data", "")
                return (
                    base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
                    if data else ""
                )
            # recurse into nested multipart
            if "parts" in part:
                result = self._plain_body(part)
                if result:
                    return result
        return ""
