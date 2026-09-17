"""
Email-driven agentic pipeline:
  1. Fetch unread Gmail from last 24h
  2. Parse intent  →  which GitHub repo / which issues are being asked for
  3. Fetch from GitHub
  4. Protegrity Gate 1: find_and_protect (tokenise PII in transit)
  5. Protegrity Gate 2: find_and_unprotect (RBAC admin — safe for reply)
  6. Compose and send email reply
  7. Mark email as read

Email intent examples the parser understands:
  "send me the last 3 issues from facebook/react"
  "please fetch issue #42 from microsoft/vscode"
  "get issues #10 and #11"   (uses default_repo if no repo in email)
  "show recent issues"        (uses default_repo, last 5)
"""
from __future__ import annotations
import json, logging, re
from typing import Any, Dict, List, Optional

import requests as rlib

from config import Config, load_config
import protegrity_bridge as pb
from gmail_agent import GmailClient
from pipeline import fetch_github_issues, _slim_issue

logger = logging.getLogger(__name__)

# ── intent patterns ───────────────────────────────────────────────
_ISSUE_NUM   = re.compile(r'#\s*(\d+)', re.I)
_LAST_N      = re.compile(r'last\s+(\d+)\s+issues?', re.I)
_COUNT_WORD  = re.compile(r'(\d+)\s+(?:recent\s+)?issues?', re.I)
_RECENT      = re.compile(r'recent|latest|newest|top', re.I)
_REPO        = re.compile(r'([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)')
_SEND_VERB   = re.compile(r'\b(send|get|fetch|show|give|list|provide)\b', re.I)


def parse_intent(subject: str, body: str) -> Dict[str, Any]:
    """Extract what GitHub action the emailer is requesting."""
    text = f"{subject}\n{body}"

    issue_nums = [int(m) for m in _ISSUE_NUM.findall(text)]

    count = 5
    m = _LAST_N.search(text)
    if m:
        count = min(int(m.group(1)), 10)
    else:
        m = _COUNT_WORD.search(text)
        if m:
            count = min(int(m.group(1)), 10)

    # Find repo mentions (owner/repo pattern) — exclude common false positives
    repos = [r for r in _REPO.findall(text)
             if "/" in r
             and not r.startswith("http")
             and "." not in r.split("/")[0]]   # skip domain-like things
    repo = repos[0] if repos else None

    action = "specific_issues" if issue_nums else "recent_issues"

    return {
        "action": action,
        "issue_numbers": issue_nums,
        "count": count,
        "repo": repo,
    }


def _fmt_issue(issue: Dict) -> str:
    user = issue.get("user") or {}
    login = user.get("login", "") if isinstance(user, dict) else str(user)
    labels = ", ".join(issue.get("labels") or []) or "(none)"
    body = (issue.get("body") or "")[:300].strip().replace("\n", " ")
    lines = [
        f"  Issue #{issue.get('number')}: {issue.get('title', '')}",
        f"  State:   {issue.get('state', '')}",
        f"  Author:  {login}",
        f"  Created: {(issue.get('created_at') or '')[:10]}",
        f"  Labels:  {labels}",
        f"  URL:     {issue.get('html_url', '')}",
    ]
    if body:
        lines.append(f"  Preview: {body[:200]}")
    return "\n".join(lines)


def _fetch_specific(repo: str, numbers: List[int], token: Optional[str]) -> List[Dict]:
    hdrs = {"Accept": "application/vnd.github.v3+json", "User-Agent": "ProtegrityDemo/1.0"}
    if token:
        hdrs["Authorization"] = f"token {token}"
    out = []
    for n in numbers[:5]:
        r = rlib.get(f"https://api.github.com/repos/{repo}/issues/{n}", headers=hdrs, timeout=10)
        if r.ok:
            out.append(r.json())
        else:
            logger.warning("Issue #%d from %s returned %s", n, repo, r.status_code)
    return out


def run_email_pipeline(
    gmail_client: GmailClient,
    github_token: Optional[str],
    cfg: Config,
    default_repo: str = "",
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Process every unread email from the last 24h.

    Returns:
      {
        "emails_found": int,
        "processed": [ { per-email result } ],
        "replies_sent": int,
        "errors": int,
      }
    """
    emails = gmail_client.fetch_unread_recent(hours=24)
    if not emails:
        return {"emails_found": 0, "processed": [],
                "replies_sent": 0, "errors": 0,
                "message": "No unread emails in the last 24 hours."}

    processed = []
    for em in emails:
        result: Dict[str, Any] = {
            "from": em["from"],
            "subject": em["subject"],
            "date": em["date"],
            "intent": None,
            "repo_used": None,
            "issues_fetched": 0,
            "pii_count": 0,
            "reply_sent": False,
            "reply_preview": "",
            "error": None,
        }
        try:
            # Stage 2 – intent
            intent = parse_intent(em["subject"], em["body"])
            result["intent"] = intent

            repo = intent["repo"] or default_repo
            if not repo or "/" not in repo:
                result["error"] = "No GitHub repo found in email. Set a default repo above or mention 'owner/repo' in the email."
                processed.append(result)
                continue
            result["repo_used"] = repo

            # Stage 3 – GitHub
            if intent["action"] == "specific_issues" and intent["issue_numbers"]:
                raw = _fetch_specific(repo, intent["issue_numbers"], github_token)
            else:
                raw = fetch_github_issues(repo, github_token, limit=intent["count"])

            issues = [_slim_issue(i) for i in raw]
            result["issues_fetched"] = len(issues)

            if not issues:
                result["error"] = f"No issues found in {repo}."
                processed.append(result)
                continue

            # Stage 4 – Protegrity protect
            raw_json = json.dumps(issues, indent=2)
            prot = pb.find_and_protect(raw_json, cfg=cfg)
            result["pii_count"] = len(prot.elements_found)
            result["protected_json"] = prot.protected

            # Stage 5 – Protegrity unprotect (admin RBAC)
            unprot = pb.find_and_unprotect(prot.protected, cfg=cfg)
            try:
                clean = json.loads(unprot.protected)
            except Exception:
                clean = issues

            # Stage 6 – compose reply
            sep = "─" * 60
            issue_block = f"\n{sep}\n".join(_fmt_issue(i) for i in clean)
            action_desc = (
                f"issue(s) #{', #'.join(str(n) for n in intent['issue_numbers'])}"
                if intent["action"] == "specific_issues"
                else f"last {len(clean)} issue(s)"
            )
            reply_body = (
                f"Hi,\n\n"
                f"Here are the {action_desc} from {repo}:\n\n"
                f"{sep}\n{issue_block}\n{sep}\n\n"
                f"Delivered by: Protegrity × Composio Secure Data Bridge\n"
                f"PII fields tokenised in transit: {result['pii_count']}\n"
            )
            result["reply_preview"] = reply_body[:600]

            # Stage 7 – send reply + mark read
            if not dry_run:
                gmail_client.send_reply(em, reply_body)
                gmail_client.mark_as_read(em["imap_id"])
                result["reply_sent"] = True

        except Exception as e:
            logger.exception("Error processing email id=%s", em.get("imap_id"))
            result["error"] = str(e)

        processed.append(result)

    return {
        "emails_found": len(emails),
        "processed": processed,
        "replies_sent": sum(1 for r in processed if r["reply_sent"]),
        "errors": sum(1 for r in processed if r["error"]),
    }
