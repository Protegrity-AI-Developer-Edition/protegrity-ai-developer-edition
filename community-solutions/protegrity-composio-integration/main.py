"""FastAPI backend - Protegrity x Composio Demo."""
from __future__ import annotations
import logging, os, sys
from pathlib import Path
from typing import Any, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, HTTPException, Request as StarletteRequest
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

from config import load_config
from agent import ProtegrityComposioAgent, RBAC_ROLES, get_connected_apps, COMPOSIO_CLI
import google_drive as gd
import pipeline as pl
import gmail_agent as ga
import gmail_api_client as gac
import email_pipeline as ep
import slack_pipeline as sp
import mock_demo_pipeline as mdp

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Protegrity x Composio Secure Data Bridge", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
_frontend = Path(__file__).parent / "frontend" / "index.html"
_static = Path(__file__).parent / "frontend" / "static"
if _static.is_dir():
    app.mount("/static", StaticFiles(directory=str(_static)), name="static")


class DemoRunRequest(BaseModel):
    repo: str
    github_token: Optional[str] = None
    rbac_role: str = "admin"
    spreadsheet_title: Optional[str] = None
    write_to_drive: bool = True

class TestGithubRequest(BaseModel):
    repo: str
    github_token: Optional[str] = None

class GoogleAuthRequest(BaseModel):
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    redirect_uri: Optional[str] = None  # user can override auto-detected URI

class ServiceAccountRequest(BaseModel):
    service_account_json: str

class GmailAuthRequest(BaseModel):
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    redirect_uri: Optional[str] = None

class GmailRunRequest(BaseModel):
    default_repo: str = ""
    github_token: Optional[str] = None
    dry_run: bool = False

class AskRequest(BaseModel):
    prompt: str

class RevealRequest(BaseModel):
    text: str
    role: str = "viewer"

class ConnectRequest(BaseModel):
    app_slug: str

class SlackRecipient(BaseModel):
    identifier: str          # Slack email, @username, or display name
    role: str = "viewer"     # "admin" (unprotected) | "viewer" (protected)
    display_name: Optional[str] = None

class SlackTestRequest(BaseModel):
    slack_token: str

class MockDemoRequest(BaseModel):
    run_guardrails: bool = True

class SlackRunRequest(BaseModel):
    slack_token: str
    repo: str
    github_token: Optional[str] = None
    recipients: list[SlackRecipient]
    dry_run: bool = False


@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    if _frontend.exists():
        return HTMLResponse(content=_frontend.read_text())
    return HTMLResponse("<h1>Frontend not found</h1>", 404)


@app.get("/api/health")
async def health():
    import requests as rlib, subprocess
    cfg = load_config()
    s: Dict[str, Any] = {
        "status": "ok",
        "protegrity": {"classify": False, "sgr": False},
        "composio": {"cli": False, "connected_apps": 0},
        "github": {"configured": bool(os.environ.get("GITHUB_TOKEN"))},
        "google_drive": {"connected": gd.is_connected()},
        "openai": {"configured": bool(cfg.openai_api_key)},
    }
    try:
        r = rlib.post(cfg.classify_url, json={"text": "test"}, timeout=3)
        s["protegrity"]["classify"] = r.status_code < 500
    except Exception as e:
        s["protegrity"]["classify_error"] = str(e)
    try:
        r = rlib.post(cfg.sgr_url,
                      json={"messages": [{"from": "user", "to": "ai", "content": "hello", "processors": []}]},
                      timeout=3)
        s["protegrity"]["sgr"] = r.status_code < 500
    except Exception as e:
        s["protegrity"]["sgr_error"] = str(e)
    try:
        r2 = subprocess.run([COMPOSIO_CLI, "--version"], capture_output=True, text=True, timeout=5)
        s["composio"]["cli"] = r2.returncode == 0
        s["composio"]["version"] = r2.stdout.strip()
        s["composio"]["connected_apps"] = len(get_connected_apps())
    except Exception as e:
        s["composio"]["cli_error"] = str(e)
    return s


@app.get("/api/roles")
async def get_roles():
    return {"roles": [{"id": k, **v} for k, v in RBAC_ROLES.items()]}


@app.post("/api/demo/test-github")
async def test_github(req: TestGithubRequest):
    import requests as rlib
    if not req.repo or "/" not in req.repo:
        raise HTTPException(400, "repo must be owner/repo")
    try:
        token = req.github_token or os.environ.get("GITHUB_TOKEN")
        hdrs = {"Accept": "application/vnd.github.v3+json", "User-Agent": "ProtegrityDemo/1.0"}
        if token:
            hdrs["Authorization"] = f"token {token}"
        r = rlib.get(f"https://api.github.com/repos/{req.repo}", headers=hdrs, timeout=10)
        if r.status_code == 404:
            return {"ok": False, "error": f"Repo '{req.repo}' not found."}
        if r.status_code == 401:
            return {"ok": False, "error": "Invalid GitHub token."}
        r.raise_for_status()
        d = r.json()
        return {"ok": True, "repo": d.get("full_name"), "description": d.get("description", ""),
                "open_issues": d.get("open_issues_count", 0), "private": d.get("private", False)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/api/demo/run")
async def demo_run(req: DemoRunRequest):
    if not req.repo or "/" not in req.repo:
        raise HTTPException(400, "repo must be owner/repo")
    github_token = req.github_token or os.environ.get("GITHUB_TOKEN") or None
    cfg = load_config()
    try:
        result = pl.run_full_pipeline(repo=req.repo, github_token=github_token,
                                      cfg=cfg, rbac_role=req.rbac_role)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        logger.exception("Pipeline error")
        raise HTTPException(500, f"Pipeline error: {e}")

    drive_result = None
    if req.write_to_drive:
        if not gd.is_connected():
            drive_result = {"ok": False,
                            "error": "Google Drive not connected. Connect Google Drive first."}
        else:
            try:
                title = req.spreadsheet_title or f"GitHub Issues — {req.repo.split('/')[-1]} — Protegrity Demo"
                drive_result = gd.create_issues_spreadsheet(result["stage_3_unprotect"]["issues"], title=title)
                drive_result["ok"] = True
            except Exception as e:
                logger.exception("Drive write failed")
                drive_result = {"ok": False, "error": str(e)}
    result["stage_4_drive"] = drive_result
    return result


@app.get("/api/google/status")
async def google_status(request: StarletteRequest):
    connected = gd.is_connected()
    cid = os.environ.get("GOOGLE_CLIENT_ID", "")
    cs  = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    return {
        "connected": connected,
        "credentials_configured": bool(cid and cs),
        "is_service_account": gd.is_service_account(),
        "redirect_uri": _detect_redirect_uri(request),
        "message": "Connected" if connected else "Not connected",
    }


@app.get("/api/google/redirect-uri")
async def google_redirect_uri(request: StarletteRequest):
    """Return the exact redirect URI this server will use — add it to Google Cloud Console."""
    return {"redirect_uri": _detect_redirect_uri(request)}


def _detect_redirect_uri(request: StarletteRequest) -> str:
    """Detect the public-facing URL, handling VS Code tunnels, ngrok, and direct access."""
    headers = request.headers
    # Check every common proxy/forwarding header in priority order
    host = (
        headers.get("x-forwarded-host")  # nginx / most proxies
        or headers.get("x-original-host")  # Azure App Service
        or headers.get("x-envoy-original-host")  # Envoy
        or None
    )
    # RFC 7239 Forwarded: host=xxx
    if not host:
        fwd = headers.get("forwarded", "")
        for part in fwd.split(";"):
            part = part.strip()
            if part.lower().startswith("host="):
                host = part[5:].strip('"')
                break
    # VS Code devtunnels set the tunnel hostname in the plain Host header
    # (request.url.netloc would be 0.0.0.0:8900 — the bind address, useless)
    if not host:
        h = headers.get("host", "")
        # Accept the host header only if it looks like a real hostname (not 0.0.0.0 / localhost)
        if h and not h.startswith("0.0.0.0") and not h.startswith("127.0.0"):
            host = h
    # Determine scheme: prefer x-forwarded-proto; devtunnels are always https
    scheme = headers.get("x-forwarded-proto") or headers.get("x-scheme") or "http"
    if host and ("devtunnels.ms" in host or "ngrok" in host or "tunnel" in host.lower()):
        scheme = "https"
    # Final fallback: whatever uvicorn saw
    if not host:
        host = request.url.netloc
        scheme = request.url.scheme
    # Strip duplicate ports (tunnel URLs don't need :8900)
    if ":" in host and not host.startswith("["):  # not IPv6
        hostname, port = host.rsplit(":", 1)
        # Only keep the port if this is a plain localhost/IP scenario
        if not any(x in hostname for x in (".",)):
            pass  # keep port for localhost
        else:
            host = hostname  # drop port for real hostnames
    return f"{scheme}://{host}/api/google/callback"


@app.post("/api/google/auth-url")
async def google_auth_url(req: GoogleAuthRequest, request: StarletteRequest):
    # Explicit values in the request always override the server env (allows credential correction)
    client_id     = req.client_id.strip()     if req.client_id     else os.environ.get("GOOGLE_CLIENT_ID", "")
    client_secret = req.client_secret.strip() if req.client_secret else os.environ.get("GOOGLE_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        raise HTTPException(400,
            "Provide Google client_id and client_secret. "
            "Create OAuth2 Web credentials at https://console.cloud.google.com "
            "and add redirect URI matching this server's URL.")
    os.environ["GOOGLE_CLIENT_ID"] = client_id
    os.environ["GOOGLE_CLIENT_SECRET"] = client_secret
    # Use explicit override from request, then auto-detect from headers
    redirect_uri = (req.redirect_uri.strip() if req.redirect_uri else None) or _detect_redirect_uri(request)
    try:
        url, state = gd.get_auth_url(client_id, client_secret, redirect_uri=redirect_uri)
        return {
            "auth_url": url,
            "redirect_uri": redirect_uri,
            "state": state,
            "instructions": (
                f"Add this exact URI to your Google Cloud OAuth2 client's "
                f"Authorized redirect URIs:\n  {redirect_uri}\n"
                "Then open auth_url in your browser to sign in."
            ),
        }
    except Exception as e:
        raise HTTPException(500, str(e))


def _html_page(title: str, body: str, ok: bool = True) -> str:
    color = "#4ade80" if ok else "#f87171"
    icon = "✅" if ok else "❌"
    return (f'<html><body style="font-family:sans-serif;background:#1e1e2e;color:#fff;'
            f'padding:40px;text-align:center"><h2 style="color:{color}">{icon} {title}</h2>'
            f'{body}<p style="margin-top:30px">'
            f'<a href="/" style="background:#6366f1;color:#fff;padding:10px 20px;'
            f'border-radius:8px;text-decoration:none">← Back to demo</a></p>'
            f'<script>setTimeout(()=>{{try{{window.close();}}catch(e){{}}window.location="/";}},3000);</script>'
            f'</body></html>')


@app.get("/api/google/callback", response_class=HTMLResponse)
async def google_callback(code: str = "", state: str = "", error: str = ""):
    if error:
        return HTMLResponse(_html_page("Authorization Failed", f"<p>Error: {error}</p>", ok=False), 400)
    if not code:
        raise HTTPException(400, "Missing authorization code.")
    try:
        gd.exchange_code(code=code, state=state)
        return HTMLResponse(_html_page("Google Drive Connected!",
            "<p>Your Google account is authorized. This tab will close automatically.</p>"))
    except Exception as e:
        logger.exception("OAuth callback error")
        return HTMLResponse(_html_page("Token Exchange Failed", f"<pre>{e}</pre>", ok=False), 500)


@app.delete("/api/google/disconnect")
async def google_disconnect():
    for p in [gd.TOKEN_PATH, gd.SA_PATH, gd.TOKEN_PATH.parent / "state.json"]:
        if p.exists():
            p.unlink()
    return {"ok": True, "message": "Google Drive disconnected."}


@app.post("/api/google/service-account")
async def google_service_account(req: ServiceAccountRequest):
    """
    Alternative to OAuth2: paste a Google Service Account JSON key.
    No redirect URI needed — works from any environment.
    Note: files will be created in the service account's Drive space and shared to
    the email in the key file. To see them in YOUR Drive, share a folder with the
    service account email shown after saving.
    """
    if not req.service_account_json.strip():
        raise HTTPException(400, "service_account_json is required")
    try:
        email = gd.save_service_account(req.service_account_json)
        # Remove any old OAuth2 token so service account takes over
        if gd.TOKEN_PATH.exists():
            gd.TOKEN_PATH.unlink()
        return {
            "ok": True,
            "service_account_email": email,
            "message": (
                f"Service account saved. Files will be created by '{email}'. "
                "To see them in your own Google Drive, share a Drive folder with that email address."
            ),
        }
    except (ValueError, KeyError) as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        logger.exception("Service account save failed")
        raise HTTPException(500, str(e))


@app.get("/api/connected-apps")
async def connected_apps():
    connected_raw = get_connected_apps()
    connected = [{"app": a.get("appName") or a.get("toolkit") or a.get("name", "unknown"),
                  "status": a.get("status", "active"), "id": a.get("id", "")}
                 for a in connected_raw]
    available = [
        {"slug": "github",     "name": "GitHub",     "description": "Repos, issues, PRs"},
        {"slug": "gmail",      "name": "Gmail",      "description": "Emails and contacts"},
        {"slug": "slack",      "name": "Slack",      "description": "Messages and channels"},
        {"slug": "hubspot",    "name": "HubSpot",    "description": "CRM contacts and deals"},
        {"slug": "salesforce", "name": "Salesforce", "description": "CRM leads and accounts"},
        {"slug": "notion",     "name": "Notion",     "description": "Pages and databases"},
    ]
    slugs = {a["app"].lower() for a in connected}
    for a in available:
        a["connected"] = a["slug"] in slugs
    return {"connected_accounts": connected, "available_apps": available,
            "mode": "live" if connected else "demo"}


@app.post("/api/connect")
async def connect_app(req: ConnectRequest):
    return {"connect_url": f"https://platform.composio.dev/connect/{req.app_slug}",
            "message": f"Open in browser to connect {req.app_slug} to Composio."}


@app.post("/api/ask")
async def ask(req: AskRequest):
    if not req.prompt or len(req.prompt.strip()) < 3:
        raise HTTPException(400, "Prompt too short.")
    cfg = load_config()
    try:
        return ProtegrityComposioAgent(cfg=cfg).run(req.prompt.strip())
    except Exception as e:
        logger.exception("Agent run failed")
        raise HTTPException(500, str(e))


@app.post("/api/reveal")
async def reveal(req: RevealRequest):
    if not req.text:
        raise HTTPException(400, "text required.")
    if req.role not in RBAC_ROLES:
        raise HTTPException(400, f"Unknown role '{req.role}'. Valid: {list(RBAC_ROLES)}")
    cfg = load_config()
    return ProtegrityComposioAgent(cfg=cfg).reveal(req.text, req.role)


@app.get("/api/gmail/status")
async def gmail_status(request: StarletteRequest):
    connected = gac.is_connected()
    email = gac.get_connected_email() if connected else None
    # Check Gmail-specific saved state — never inherit Drive/Composio GOOGLE_CLIENT_ID
    gmail_state_path = Path(__file__).parent / "google_auth" / "gmail_state.json"
    gmail_creds_saved = gmail_state_path.exists()
    redirect_uri = _detect_redirect_uri(request).replace("/api/google/callback", "/api/gmail/callback")
    return {
        "connected": connected,
        "email": email,
        "credentials_configured": gmail_creds_saved,
        "redirect_uri": redirect_uri,
    }


@app.post("/api/gmail/auth-url")
async def gmail_auth_url(req: GmailAuthRequest, request: StarletteRequest):
    # Use Gmail-specific env vars — NEVER fall back to GOOGLE_CLIENT_ID (could be Composio's)
    client_id     = (req.client_id or "").strip()     or os.environ.get("GMAIL_CLIENT_ID", "")
    client_secret = (req.client_secret or "").strip() or os.environ.get("GMAIL_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        raise HTTPException(400,
            "Provide YOUR OWN Google OAuth2 client_id and client_secret from your own Google Cloud project. "
            "Do NOT use Composio credentials. "
            "See https://console.cloud.google.com → APIs & Services → Credentials → Create OAuth2 Web Client. "
            "Enable Gmail API in the same project.")
    # Persist as Gmail-specific env vars
    os.environ["GMAIL_CLIENT_ID"] = client_id
    os.environ["GMAIL_CLIENT_SECRET"] = client_secret
    redirect_uri = (req.redirect_uri or "").strip() or \
        _detect_redirect_uri(request).replace("/api/google/callback", "/api/gmail/callback")
    try:
        url, state = gac.get_auth_url(client_id, client_secret, redirect_uri=redirect_uri)
        return {"auth_url": url, "redirect_uri": redirect_uri}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/api/gmail/callback", response_class=HTMLResponse)
async def gmail_callback(code: str = "", state: str = "", error: str = ""):
    if error:
        return HTMLResponse(_html_page("Gmail Authorization Failed",
            f"<p>Error: {error}</p>", ok=False), 400)
    if not code:
        raise HTTPException(400, "Missing authorization code.")
    try:
        gac.exchange_code(code=code, state=state)
        return HTMLResponse(_html_page("Gmail Connected!",
            "<p>Your Gmail account is authorized. This tab will close automatically.</p>"))
    except Exception as e:
        logger.exception("Gmail OAuth callback error")
        return HTMLResponse(_html_page("Gmail Token Exchange Failed",
            f"<pre>{e}</pre>", ok=False), 500)


@app.delete("/api/gmail/disconnect")
async def gmail_disconnect():
    gac.disconnect()
    # Also remove saved credentials state so the form reappears
    gmail_state = Path(__file__).parent / "google_auth" / "gmail_state.json"
    if gmail_state.exists():
        gmail_state.unlink()
    os.environ.pop("GMAIL_CLIENT_ID", None)
    os.environ.pop("GMAIL_CLIENT_SECRET", None)
    return {"ok": True, "message": "Gmail disconnected."}


@app.post("/api/gmail/test")
async def gmail_test():
    """Test Gmail REST API connection using the stored OAuth token."""
    if not gac.is_connected():
        return {"ok": False, "error": "Gmail not connected. Please authorize via Connect Gmail."}
    try:
        client = gac.GmailAPIClient()
        return client.test_connection()
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/api/gmail/preview")
async def gmail_preview(req: GmailRunRequest):
    """Dry-run: fetch emails + parse intent, but DO NOT send any replies."""
    if not gac.is_connected():
        raise HTTPException(400, "Gmail not connected. Please authorize via Connect Gmail.")
    cfg = load_config()
    github_token = req.github_token or os.environ.get("GITHUB_TOKEN") or None
    try:
        client = gac.GmailAPIClient()
        result = ep.run_email_pipeline(
            gmail_client=client, github_token=github_token,
            cfg=cfg, default_repo=req.default_repo, dry_run=True,
        )
        return result
    except Exception as e:
        logger.exception("Gmail preview failed")
        raise HTTPException(500, str(e))


@app.post("/api/gmail/run")
async def gmail_run(req: GmailRunRequest):
    """Full pipeline: read unread emails → parse intent → GitHub → Protegrity → send replies."""
    if not gac.is_connected():
        raise HTTPException(400, "Gmail not connected. Please authorize via Connect Gmail.")
    cfg = load_config()
    github_token = req.github_token or os.environ.get("GITHUB_TOKEN") or None
    try:
        client = gac.GmailAPIClient()
        result = ep.run_email_pipeline(
            gmail_client=client, github_token=github_token,
            cfg=cfg, default_repo=req.default_repo, dry_run=False,
        )
        return result
    except Exception as e:
        logger.exception("Gmail run failed")
        raise HTTPException(500, str(e))


# ── Slack endpoints ───────────────────────────────────────────────────────────

@app.post("/api/slack/test")
async def slack_test(req: SlackTestRequest):
    """Validate a Slack Bot Token and return workspace info."""
    return sp.test_slack_token(req.slack_token)


@app.post("/api/slack/run")
async def slack_run(req: SlackRunRequest):
    """
    Full pipeline:
      1. Fetch today's top-5 GitHub issues
      2. Protegrity protect (Gate 1)
      3. For each recipient: admin → unprotect (Gate 2) + send plain DM
                             viewer → send protected DM
    """
    if not req.recipients:
        raise HTTPException(400, "At least one recipient is required.")
    if not req.repo or "/" not in req.repo:
        raise HTTPException(400, "repo must be owner/repo")
    cfg = load_config()
    github_token = req.github_token or os.environ.get("GITHUB_TOKEN") or None
    try:
        result = sp.run_slack_pipeline(
            slack_token=req.slack_token,
            repo=req.repo,
            github_token=github_token,
            recipients=[r.model_dump() for r in req.recipients],
            cfg=cfg,
            dry_run=req.dry_run,
        )
        return result
    except Exception as e:
        logger.exception("Slack pipeline failed")
        raise HTTPException(500, str(e))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8900))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)

# ── Mock demo endpoint ────────────────────────────────────────────────────────

@app.post("/api/mock/run")
async def mock_run(req: MockDemoRequest):
    """
    Run the fully-mocked Composio demo pipeline:
      Inbound Email → GitHub Issues → Protegrity Gate 1 (protect)
      → Semantic Guardrails → Outbound Email → Google Drive Spreadsheet

    Real Protegrity APIs are called; everything else is mock data.
    """
    cfg = load_config()
    try:
        result = mdp.run_mock_pipeline(cfg=cfg, run_guardrails=req.run_guardrails)
        return result
    except Exception as e:
        logger.exception("Mock pipeline failed")
        raise HTTPException(500, str(e))
