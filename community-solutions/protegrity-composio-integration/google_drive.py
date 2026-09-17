"""
Google Drive / Sheets integration for the Protegrity-Composio demo.

OAuth2 flow (Web App credentials from Google Cloud Console):
  1. User provides GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET in .env
  2. /api/google/auth-url  → returns URL for user to open in browser
  3. User authorizes → Google redirects to http://localhost:8900/api/google/callback
  4. Token stored in google_auth/token.json — subsequent calls use it automatically

To set up:
  1. Go to https://console.cloud.google.com → APIs & Services → Credentials
  2. Create OAuth2 Client (Web application)
  3. Add http://localhost:8900/api/google/callback as an Authorized redirect URI
  4. Copy Client ID and Client Secret into .env
  5. Enable "Google Drive API" and "Google Sheets API" in the project
"""
from __future__ import annotations
import json, logging, os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

TOKEN_PATH = Path(__file__).parent / "google_auth" / "token.json"
SA_PATH    = Path(__file__).parent / "google_auth" / "service_account.json"
# Configurable via GOOGLE_REDIRECT_URI env var; overridden at runtime by the detected request URL
DEFAULT_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "http://localhost:8900/api/google/callback")

SCOPES = [
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/spreadsheets",
]


# ── Auth helpers ──────────────────────────────────────────────────────────────

def _client_config(client_id: str, client_secret: str, redirect_uri: str) -> Dict:
    return {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [redirect_uri],
        }
    }


def get_auth_url(client_id: str, client_secret: str, redirect_uri: Optional[str] = None) -> Tuple[str, str]:
    """Generate the Google OAuth2 authorization URL. Returns (url, state)."""
    from google_auth_oauthlib.flow import Flow
    redirect_uri = redirect_uri or DEFAULT_REDIRECT_URI
    flow = Flow.from_client_config(
        _client_config(client_id, client_secret, redirect_uri),
        scopes=SCOPES,
        redirect_uri=redirect_uri,
    )
    url, state = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        include_granted_scopes="true",
    )
    # Save state + redirect_uri to disk so the callback can use the exact same URI
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    (TOKEN_PATH.parent / "state.json").write_text(
        json.dumps({"client_id": client_id, "client_secret": client_secret,
                    "state": state, "redirect_uri": redirect_uri})
    )
    return url, state


def exchange_code(code: str, state: str):
    """Exchange the OAuth2 authorization code for credentials and save token."""
    from google_auth_oauthlib.flow import Flow
    state_path = TOKEN_PATH.parent / "state.json"
    if not state_path.exists():
        raise RuntimeError("OAuth state not found. Please start from /api/google/auth-url")
    saved = json.loads(state_path.read_text())
    redirect_uri = saved.get("redirect_uri", DEFAULT_REDIRECT_URI)
    flow = Flow.from_client_config(
        _client_config(saved["client_id"], saved["client_secret"], redirect_uri),
        scopes=SCOPES,
        state=saved["state"],
        redirect_uri=redirect_uri,
    )
    flow.fetch_token(code=code)
    creds = flow.credentials
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_PATH.write_text(creds.to_json())
    logger.info("Google OAuth2 token saved to %s", TOKEN_PATH)
    return creds


def load_credentials():
    """Load stored Google credentials (OAuth2 token or service account), refreshing if expired."""
    # Service account takes priority if present
    if SA_PATH.exists():
        return _load_service_account_creds()
    if not TOKEN_PATH.exists():
        return None
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request
    creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        TOKEN_PATH.write_text(creds.to_json())
    return creds if (creds and creds.valid) else None


def _load_service_account_creds():
    """Load a service account JSON key and return scoped credentials."""
    try:
        from google.oauth2 import service_account
        creds = service_account.Credentials.from_service_account_file(
            str(SA_PATH), scopes=SCOPES)
        return creds
    except Exception as e:
        logger.error("Service account load failed: %s", e)
        return None


def save_service_account(json_str: str):
    """Validate and save a service account JSON key string."""
    data = json.loads(json_str)  # raises if invalid JSON
    if data.get("type") != "service_account":
        raise ValueError("Not a service account JSON — 'type' must be 'service_account'")
    required = {"client_email", "private_key", "project_id"}
    missing = required - data.keys()
    if missing:
        raise ValueError(f"Missing fields in service account JSON: {missing}")
    SA_PATH.parent.mkdir(parents=True, exist_ok=True)
    SA_PATH.write_text(json_str)
    logger.info("Service account saved: %s", data.get("client_email"))
    return data.get("client_email")


def is_service_account() -> bool:
    return SA_PATH.exists()


def is_connected() -> bool:
    """Return True if valid Google credentials exist."""
    return load_credentials() is not None


# ── Sheets / Drive operations ─────────────────────────────────────────────────

def create_issues_spreadsheet(
    issues: List[Dict[str, Any]],
    title: str = "GitHub Issues — Protegrity Demo",
) -> Dict[str, Any]:
    """
    Create a Google Spreadsheet in the user's Drive with GitHub issue data.
    Returns {"spreadsheet_id": ..., "url": ..., "rows_written": ...}
    """
    from googleapiclient.discovery import build

    creds = load_credentials()
    if not creds:
        raise RuntimeError("Google Drive not connected. Authorize first via /api/google/auth-url")

    sheets = build("sheets", "v4", credentials=creds)

    # ── 1. Create the spreadsheet ──────────────────────────────────────────────
    spreadsheet = sheets.spreadsheets().create(body={
        "properties": {"title": title},
        "sheets": [{"properties": {"title": "Issues", "sheetId": 0}}],
    }).execute()
    sid = spreadsheet["spreadsheetId"]
    sheet_id = 0
    logger.info("Created spreadsheet %s", sid)

    # ── 2. Build rows ──────────────────────────────────────────────────────────
    headers = ["#", "Title", "Author", "State", "Created", "Labels", "URL", "Body Preview"]
    rows = [headers]
    for issue in issues:
        user = issue.get("user", {})
        login = user.get("login", "") if isinstance(user, dict) else str(user)
        labels = issue.get("labels", [])
        label_str = ", ".join(
            (lb.get("name", "") if isinstance(lb, dict) else str(lb))
            for lb in (labels or [])
        )
        body = (issue.get("body") or "")
        rows.append([
            str(issue.get("number", "")),
            issue.get("title", ""),
            login,
            issue.get("state", ""),
            (issue.get("created_at", "") or "")[:10],
            label_str,
            issue.get("html_url", ""),
            body[:300].replace("\n", " "),
        ])

    # ── 3. Write data ──────────────────────────────────────────────────────────
    sheets.spreadsheets().values().update(
        spreadsheetId=sid,
        range="Issues!A1",
        valueInputOption="RAW",
        body={"values": rows},
    ).execute()

    # ── 4. Style header row ────────────────────────────────────────────────────
    try:
        sheets.spreadsheets().batchUpdate(
            spreadsheetId=sid,
            body={"requests": [
                # Bold + colour header
                {"repeatCell": {
                    "range": {"sheetId": sheet_id, "startRowIndex": 0, "endRowIndex": 1},
                    "cell": {"userEnteredFormat": {
                        "backgroundColor": {"red": 0.12, "green": 0.27, "blue": 0.54},
                        "textFormat": {
                            "foregroundColor": {"red": 1, "green": 1, "blue": 1},
                            "bold": True,
                        },
                    }},
                    "fields": "userEnteredFormat(backgroundColor,textFormat)",
                }},
                # Freeze header row
                {"updateSheetProperties": {
                    "properties": {
                        "sheetId": sheet_id,
                        "gridProperties": {"frozenRowCount": 1},
                    },
                    "fields": "gridProperties.frozenRowCount",
                }},
                # Auto-resize columns
                {"autoResizeDimensions": {
                    "dimensions": {
                        "sheetId": sheet_id,
                        "dimension": "COLUMNS",
                        "startIndex": 0,
                        "endIndex": len(headers),
                    },
                }},
            ]},
        ).execute()
    except Exception as e:
        logger.warning("Formatting failed (non-fatal): %s", e)

    url = f"https://docs.google.com/spreadsheets/d/{sid}/edit"
    return {
        "spreadsheet_id": sid,
        "url": url,
        "rows_written": len(rows) - 1,
        "title": title,
    }
