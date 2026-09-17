"""
Real end-to-end pipeline:
  GitHub Issues → Protegrity Gate 1 (Protect) → Protegrity Gate 2 (Unprotect) → Google Sheets

Each stage is recorded so the UI can show raw / protected / unprotected side-by-side.
"""
from __future__ import annotations
import json, logging, re, sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests as req_lib

sys.path.insert(0, str(Path(__file__).parent))
from config import Config, load_config
import protegrity_bridge as pb

logger = logging.getLogger(__name__)


# ── GitHub ────────────────────────────────────────────────────────────────────

def fetch_github_issues(
    repo: str,
    github_token: Optional[str] = None,
    limit: int = 5,
) -> List[Dict[str, Any]]:
    """
    Fetch the last `limit` issues (any state) from a GitHub repository.
    repo format: "owner/repo-name"
    """
    if "/" not in repo:
        raise ValueError(f"repo must be 'owner/repo', got: {repo!r}")

    headers = {"Accept": "application/vnd.github.v3+json",
               "User-Agent": "ProtegrityDemo/1.0"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    url = f"https://api.github.com/repos/{repo}/issues"
    resp = req_lib.get(
        url,
        params={"state": "all", "per_page": limit, "page": 1},
        headers=headers,
        timeout=20,
    )
    if resp.status_code == 404:
        raise ValueError(f"Repository '{repo}' not found or not accessible.")
    if resp.status_code == 401:
        raise ValueError("GitHub token is invalid or expired.")
    resp.raise_for_status()

    issues = resp.json()
    # GitHub API includes PRs in /issues — filter them out
    issues = [i for i in issues if "pull_request" not in i]
    return issues[:limit]


def _slim_issue(issue: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only the fields we need to display and protect."""
    user = issue.get("user") or {}
    labels = issue.get("labels") or []
    return {
        "number": issue.get("number"),
        "title":  issue.get("title", ""),
        "state":  issue.get("state", ""),
        "user":   {"login": user.get("login", ""), "email": user.get("email", "")},
        "created_at": (issue.get("created_at") or "")[:10],
        "html_url": issue.get("html_url", ""),
        "labels": [lb.get("name", "") if isinstance(lb, dict) else str(lb) for lb in labels],
        "body": (issue.get("body") or "")[:500],
    }


# ── Pipeline ──────────────────────────────────────────────────────────────────

def run_full_pipeline(
    repo: str,
    github_token: Optional[str] = None,
    cfg: Optional[Config] = None,
    rbac_role: str = "admin",
) -> Dict[str, Any]:
    """
    Execute the full demo pipeline and return all stages.

    Returns:
        {
            "stage_1_fetch":       { issues: [...], json: "..." },
            "stage_2_protect":     { protected_json: "...", elements: [...] },
            "stage_3_unprotect":   { unprotected_json: "...", issues: [...] },
            "pii_count":           int,
            "repo":                str,
            "error":               None | str,
        }
    """
    cfg = cfg or load_config()

    # ── Stage 1: Fetch ────────────────────────────────────────────────────────
    logger.info("Stage 1: Fetching GitHub issues from %s", repo)
    raw_issues = fetch_github_issues(repo, github_token, limit=5)
    slimmed = [_slim_issue(i) for i in raw_issues]
    raw_json = json.dumps(slimmed, indent=2)
    logger.info("Fetched %d issues", len(slimmed))

    # ── Stage 2: Protegrity Gate 1 — Protect (tokenize PII) ──────────────────
    logger.info("Stage 2: Protegrity find_and_protect")
    protect_result = pb.find_and_protect(raw_json, cfg=cfg)
    protected_json = protect_result.protected
    elements = protect_result.elements_found
    logger.info("Gate 1 complete: %d PII elements found", len(elements))

    # ── Stage 3: Protegrity Gate 2 — Unprotect (detokenize for Drive output) ──
    can_reveal = rbac_role.lower() == "admin"
    if can_reveal:
        logger.info("Stage 3: Protegrity find_and_unprotect (role=%s)", rbac_role)
        unprotect_result = pb.find_and_unprotect(protected_json, cfg=cfg)
        unprotected_json = unprotect_result.protected
    else:
        logger.info("Stage 3: Redacted (role=%s has no reveal permission)", rbac_role)
        unprotect_result = pb.find_and_redact(protected_json, cfg=cfg)
        unprotected_json = unprotect_result.protected

    # Parse unprotected JSON back to list (best effort)
    try:
        unprotected_issues = json.loads(unprotected_json)
    except Exception:
        unprotected_issues = slimmed  # fallback to raw if parse fails
        logger.warning("Could not parse unprotected JSON; using raw issues for Drive write")

    return {
        "stage_1_fetch": {
            "issues": slimmed,
            "json": raw_json,
            "count": len(slimmed),
        },
        "stage_2_protect": {
            "protected_json": protected_json,
            "elements": elements,
            "pii_detected": protect_result.pii_detected,
        },
        "stage_3_unprotect": {
            "unprotected_json": unprotected_json,
            "issues": unprotected_issues,
            "rbac_role": rbac_role,
            "revealed": can_reveal,
        },
        "pii_count": len(elements),
        "repo": repo,
        "error": None,
    }
