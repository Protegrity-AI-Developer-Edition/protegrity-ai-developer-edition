"""
GitHub → Protegrity → Slack pipeline.

Flow:
  1.  Fetch the top 5 GitHub issues created/updated today
  2.  Protegrity Gate 1: find_and_protect  (tokenise all PII)
  3.  For each configured recipient:
        • RBAC role == "admin"  → Gate 2: find_and_unprotect  → send plain text
        • RBAC role == "viewer" → skip Gate 2              → send tokenised text
  4.  Deliver a formatted Slack DM to each recipient

Recipient is identified by Slack @username, display name, real name, or email.
A Slack Bot Token (xoxb-...) is required.  Create one at:
  https://api.slack.com/apps  →  OAuth & Permissions
Scopes needed:
  chat:write   im:write   users:read   users:read.email
Then install the app to your workspace and copy the Bot User OAuth Token.
"""
from __future__ import annotations

import json, logging, re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests as rlib
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from config import Config, load_config
import protegrity_bridge as pb
from pipeline import fetch_github_issues, _slim_issue

logger = logging.getLogger(__name__)

# ── issue helpers ─────────────────────────────────────────────────────────────

def fetch_today_issues(
    repo: str,
    github_token: Optional[str],
    limit: int = 5,
) -> List[Dict[str, Any]]:
    """
    Fetch up to `limit` issues created OR updated in the last 24 h.
    Falls back to the most-recent `limit` issues if none are from today.
    """
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ProtegrityDemo/1.0",
    }
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    now = datetime.now(timezone.utc)
    url = f"https://api.github.com/repos/{repo}/issues"
    resp = rlib.get(
        url,
        params={"state": "open", "sort": "updated", "direction": "desc", "per_page": 20},
        headers=headers,
        timeout=20,
    )
    resp.raise_for_status()
    issues = [i for i in resp.json() if "pull_request" not in i]

    # Try to return issues updated within the last 24 h
    today = [
        i for i in issues
        if _hours_ago(i.get("updated_at") or i.get("created_at", "")) <= 24
    ]
    chosen = today[:limit] if today else issues[:limit]
    return [_slim_issue(i) for i in chosen]


def _hours_ago(iso: str) -> float:
    """Return how many hours ago an ISO-8601 timestamp was. Returns inf on error."""
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        delta = datetime.now(timezone.utc) - dt
        return delta.total_seconds() / 3600
    except Exception:
        return float("inf")


# ── Slack helpers ─────────────────────────────────────────────────────────────

def _resolve_user_id(client: WebClient, identifier: str) -> Optional[str]:
    """
    Turn a Slack identifier (email, @username, display name, real name) into a Slack user ID.
    Returns None if not found.
    """
    identifier = identifier.strip().lstrip("@")

    # Try by email first (most reliable)
    if "@" in identifier and "." in identifier.split("@")[-1]:
        try:
            r = client.users_lookupByEmail(email=identifier)
            return r["user"]["id"]
        except SlackApiError:
            pass

    # Walk the members list and match display_name / real_name / name
    cursor = None
    while True:
        kwargs: Dict[str, Any] = {"limit": 200}
        if cursor:
            kwargs["cursor"] = cursor
        try:
            page = client.users_list(**kwargs)
        except SlackApiError as e:
            logger.warning("users_list error: %s", e)
            break
        for member in page.get("members", []):
            if member.get("deleted") or member.get("is_bot"):
                continue
            profile = member.get("profile", {})
            if (member.get("name", "").lower() == identifier.lower()
                    or profile.get("display_name", "").lower() == identifier.lower()
                    or profile.get("real_name", "").lower() == identifier.lower()):
                return member["id"]
        cursor = page.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break
    return None


def _open_dm(client: WebClient, user_id: str) -> str:
    """Open (or reuse) a DM channel with a user and return the channel ID."""
    r = client.conversations_open(users=[user_id])
    return r["channel"]["id"]


def _build_blocks(
    issues: List[Dict],
    repo: str,
    is_protected: bool,
    sender_note: str = "",
) -> List[Dict]:
    """Build Slack Block Kit message blocks."""
    status_emoji = "🔒" if is_protected else "🔓"
    status_label = "PII tokenised (protected)" if is_protected else "PII de-tokenised (plain text)"
    header_text = (
        f"{status_emoji} *Top GitHub issues from `{repo}`*\n"
        f"_{status_label}_"
    )
    blocks: List[Dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"GitHub Issues — {repo}", "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn", "text": header_text}},
        {"type": "divider"},
    ]

    for iss in issues:
        user = iss.get("user") or {}
        login = user.get("login", "unknown") if isinstance(user, dict) else str(user)
        labels = ", ".join(iss.get("labels") or []) or "none"
        preview = (iss.get("body") or "")[:200].replace("\n", " ").strip()
        state_emoji = "🟢" if iss.get("state") == "open" else "⚫"
        issue_text = (
            f"*#{iss.get('number')} — {iss.get('title', '')}*\n"
            f"{state_emoji} {iss.get('state', '')}  •  👤 {login}  •  🏷 {labels}\n"
            f"📅 {(iss.get('created_at') or '')[:10]}"
        )
        if preview:
            issue_text += f"\n> {preview[:180]}"
        url = iss.get("html_url", "")
        block: Dict[str, Any] = {
            "type": "section",
            "text": {"type": "mrkdwn", "text": issue_text},
        }
        if url:
            block["accessory"] = {
                "type": "button",
                "text": {"type": "plain_text", "text": "Open →", "emoji": True},
                "url": url,
                "action_id": f"issue_{iss.get('number')}",
            }
        blocks.append(block)
        blocks.append({"type": "divider"})

    footer = f"_Delivered by Protegrity × Composio Secure Data Bridge_"
    if sender_note:
        footer = f"_{sender_note}_\n{footer}"
    blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": footer}})
    return blocks


# ── main pipeline ─────────────────────────────────────────────────────────────

def run_slack_pipeline(
    slack_token: str,
    repo: str,
    github_token: Optional[str],
    recipients: List[Dict[str, str]],   # [{"identifier": "...", "role": "admin|viewer"}, ...]
    cfg: Optional[Config] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Run the full GitHub → Protegrity → Slack pipeline.

    Each recipient dict must have:
      identifier  — Slack email, @username, or display name
      role        — "admin" (see plain text) or "viewer" (see tokenised)

    Returns a result dict with per-recipient outcomes.
    """
    if cfg is None:
        cfg = load_config()

    # ── Stage 1: Fetch today's issues ─────────────────────────────────────────
    issues = fetch_today_issues(repo, github_token, limit=5)
    if not issues:
        return {
            "ok": False,
            "error": f"No issues found in {repo}",
            "issues_found": 0,
        }

    # ── Stage 2: Protegrity Gate 1 — protect each field individually ──────────
    # Treating the whole JSON blob as text causes numeric fields (issue numbers,
    # dates) to be mis-tagged and corrupted.  Protecting text fields one-by-one
    # gives the classifier proper context and preserves the JSON structure.
    def _protect_issue_fields(issue: dict) -> tuple:
        """Return a PII-protected copy of the issue + all elements detected."""
        p = dict(issue)
        elems: list = []
        for field in ("title", "body"):
            val = issue.get(field) or ""
            if val:
                r = pb.find_and_protect(val, cfg=cfg)
                p[field] = r.protected
                elems.extend(r.elements_found)
        user = issue.get("user") or {}
        if isinstance(user, dict):
            p_user = dict(user)
            for uf in ("login", "email"):
                if user.get(uf):
                    r = pb.find_and_protect(user[uf], cfg=cfg)
                    p_user[uf] = r.protected
                    elems.extend(r.elements_found)
            p["user"] = p_user
        return p, elems

    protected_issues: list = []
    all_elements: list = []
    for issue in issues:
        p_issue, elems = _protect_issue_fields(issue)
        protected_issues.append(p_issue)
        all_elements.extend(elems)

    protected_json = json.dumps(protected_issues, indent=2)
    pii_count = len(all_elements)

    # Cache the unprotected version (Gate 2) for admin recipients
    _unprotected: Dict[str, Any] = {}  # lazy: computed once if any admin exists

    def _get_unprotected() -> List[Dict]:
        nonlocal _unprotected
        if not _unprotected:
            r = pb.find_and_unprotect(protected_json, cfg=cfg)
            try:
                _unprotected["issues"] = json.loads(r.protected)
            except Exception:
                _unprotected["issues"] = issues  # fallback to raw
        return _unprotected["issues"]

    # ── Stage 3 + 4: Resolve users and send ───────────────────────────────────
    client = WebClient(token=slack_token)

    # Quick connection check
    try:
        auth = client.auth_test()
        bot_name = auth.get("user", "ProtegrityBot")
    except SlackApiError as e:
        return {"ok": False, "error": f"Slack auth failed: {e.response['error']}", "issues_found": len(issues)}

    results = []
    for rec in recipients:
        identifier = rec.get("identifier", "").strip()
        role = rec.get("role", "viewer")
        display_name = rec.get("display_name") or identifier

        rec_result: Dict[str, Any] = {
            "identifier": identifier,
            "display_name": display_name,
            "role": role,
            "user_id": None,
            "sent": False,
            "protected": role != "admin",
            "error": None,
        }

        if not identifier:
            rec_result["error"] = "Empty identifier — skipped"
            results.append(rec_result)
            continue

        # Resolve Slack user
        user_id = _resolve_user_id(client, identifier)
        if not user_id:
            rec_result["error"] = f"Could not find Slack user '{identifier}'"
            results.append(rec_result)
            continue
        rec_result["user_id"] = user_id

        # Choose PII visibility based on role
        if role == "admin":
            send_issues = _get_unprotected()
            is_protected = False
            sender_note = f"Sent to {display_name} as admin — PII de-tokenised"
        else:
            try:
                send_issues = json.loads(protected_json)
            except Exception:
                send_issues = issues
            is_protected = True
            sender_note = f"Sent to {display_name} as viewer — PII remains tokenised"

        blocks = _build_blocks(send_issues, repo, is_protected, sender_note)

        if not dry_run:
            try:
                channel_id = _open_dm(client, user_id)
                client.chat_postMessage(
                    channel=channel_id,
                    text=f"Top GitHub issues from {repo} ({('🔓 plain' if role == 'admin' else '🔒 protected')})",
                    blocks=blocks,
                )
                rec_result["sent"] = True
            except SlackApiError as e:
                rec_result["error"] = e.response.get("error", str(e))
        else:
            rec_result["sent"] = False  # dry run

        results.append(rec_result)

    return {
        "ok": True,
        "repo": repo,
        "issues_found": len(issues),
        "pii_count": pii_count,
        "issues": issues,
        "protected_json": protected_json,
        "dry_run": dry_run,
        "recipients": results,
        "sent_count": sum(1 for r in results if r["sent"]),
    }


def test_slack_token(slack_token: str) -> Dict[str, Any]:
    """Quick validation of a Slack Bot Token."""
    try:
        client = WebClient(token=slack_token)
        r = client.auth_test()
        return {
            "ok": True,
            "team": r.get("team"),
            "bot_user": r.get("user"),
            "workspace_url": r.get("url"),
        }
    except SlackApiError as e:
        err = e.response.get("error", str(e))
        if err == "invalid_auth":
            return {"ok": False, "error": "Invalid token — check you copied the full xoxb-… Bot Token"}
        return {"ok": False, "error": err}
    except Exception as e:
        return {"ok": False, "error": str(e)}
