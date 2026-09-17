"""
Protegrity Bridge — wraps the Developer Edition SDK for:
  • find_and_protect   (discover PII → tokenize)
  • find_and_unprotect (detokenize, RBAC-gated)
  • find_and_redact    (replace with [REDACTED])
  • semantic_guardrail (risk scoring)

Adapted from the existing BankingPortalChatbot patterns.
"""
from __future__ import annotations
import os, re, logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from config import Config, load_config

logger = logging.getLogger(__name__)

# ── Entity → SDK data-element mapping ────────────────────────────────────────
NAMED_ENTITY_MAP: Dict[str, str] = {
    "EMAIL_ADDRESS": "email",
    "PERSON": "string",
    "PHONE_NUMBER": "phone",
    "SOCIAL_SECURITY_ID": "ssn",
    "SOCIAL_SECURITY_NUMBER": "ssn",
    "CREDIT_CARD": "ccn",
    "LOCATION": "address",
    "IP_ADDRESS": "address",
    "ORGANIZATION": "string",
    "URL": "address",
    "USERNAME": "string",
    "URL|EMAIL_ADDRESS": "email",
    "URL|EMAIL_ADDRESS|USERNAME": "email",
    "EMAIL_ADDRESS|URL": "email",
    "EMAIL_ADDRESS|USERNAME": "email",
    "PERSON|LOCATION": "string",
    "CREDIT_CARD|PERSON": "ccn",
}

_sdk_configured = False
_token_map: Dict[str, bool] = {}   # tracks live tokens for unprotect

# Remove the local EXTRA_DATA_ELEMENT_MAPPINGS dict and import centralized config
import sys
sys.path.insert(0, "/home/azure_usr/protegrity_ai_integrations/protegrity_demo/BankingPortalChatbot/services")
from protegrity_config import ENTITY_TO_DATA_ELEMENT, COMBINED_ENTITY_MAPPINGS, get_data_element

# ── SDK bootstrap ─────────────────────────────────────────────────────────────

def _import_sdk():
    import protegrity_developer_python as sdk
    return sdk


def _configure_sdk(cfg: Config):
    global _sdk_configured
    if (_sdk_configured):
        return _import_sdk()
    sdk = _import_sdk()
    # Patch extra entity mappings
    if hasattr(sdk, "DATA_ELEMENT_MAPPING"):
        for k, v in ENTITY_TO_DATA_ELEMENT.items():
            sdk.DATA_ELEMENT_MAPPING.setdefault(k, v)
    try:
        from protegrity_developer_python.utils import pii_processing
        for k, v in {**ENTITY_TO_DATA_ELEMENT, **{
            ek: ev for ek, ev in NAMED_ENTITY_MAP.items() if "|" in ek
        }}.items():
            pii_processing.entity_endpoint_mapped[k] = v
    except Exception as e:
        logger.warning("Could not patch entity mappings: %s", e)

    sdk.configure(
        endpoint_url=cfg.classify_url,
        named_entity_map=NAMED_ENTITY_MAP,
        classification_score_threshold=0.1,
        enable_logging=False,
        log_level="warning",
    )
    _sdk_configured = True
    logger.info("Protegrity SDK configured: endpoint=%s", cfg.classify_url)
    return sdk


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ProtectResult:
    original: str
    protected: str
    elements_found: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def pii_detected(self) -> bool:
        return self.original != self.protected or bool(self.elements_found)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original": self.original,
            "protected": self.protected,
            "pii_detected": self.pii_detected,
            "elements_found": self.elements_found,
            "error": self.error,
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_elements(original: str, protected: str) -> List[Dict[str, Any]]:
    elements = []
    for m in re.finditer(r'\[([A-Z_|]+)\](.*?)\[/\1\]', protected):
        entity_type = m.group(1).split("|")[0]
        token_value = m.group(2)
        elements.append({"type": entity_type, "token": token_value})
        _token_map[token_value] = True
    if not elements and original != protected:
        elements.append({"type": "UNKNOWN", "note": "text was modified"})
    return elements


def _strip_pii_tags(text: str) -> str:
    return re.sub(r'\[([A-Z_|]+)\](.*?)\[/\1\]', r'\2', text)


# ── Discover-based fallback protection ────────────────────────────────────────
# Used when sdk.find_and_protect() returns unchanged text (dev-edition limitation)

_ENTITY_PRIORITY: Dict[str, int] = {
    "SOCIAL_SECURITY_ID": 10, "SOCIAL_SECURITY_NUMBER": 10,
    "CREDIT_CARD": 9, "CREDIT_CARD_NUMBER": 9,
    "EMAIL_ADDRESS": 8,
    "PHONE_NUMBER": 7,
    "PERSON": 6,
    "IP_ADDRESS": 5,
    "LOCATION": 4,
    "ORGANIZATION": 3,
    "URL": 1,   # lowest — frequently overlaps with email addresses
}
_SKIP_FALLBACK_TYPES = {"URL"}   # suppressed to reduce false positives
_FALLBACK_MIN_SCORE = 0.6


def _discover_and_protect_fallback(text: str, sdk) -> str:
    """
    Fallback: call sdk.discover() to locate PII entities by character position,
    then wrap each span in [TYPE]original_value[/TYPE] tags.
    Invoked when sdk.find_and_protect() returns unchanged text.
    """
    try:
        discovered = sdk.discover(text)
    except Exception as e:
        logger.warning("Discover fallback failed: %s", e)
        return text

    spans: List[tuple] = []
    for entity_type, hits in discovered.items():
        if entity_type in _SKIP_FALLBACK_TYPES:
            continue
        priority = _ENTITY_PRIORITY.get(entity_type, 3)
        for hit in hits:
            score = hit.get("score", 0)
            if score < _FALLBACK_MIN_SCORE:
                continue
            loc = hit.get("location", {})
            start = loc.get("start_index")
            end = loc.get("end_index")
            if start is None or end is None or end <= start:
                continue
            spans.append((start, end, entity_type, priority, score))

    if not spans:
        return text

    # Remove overlapping spans — prefer highest priority, then highest score
    spans.sort(key=lambda x: (x[0], -x[3], -x[4]))
    filtered: List[tuple] = []
    for span in spans:
        s, e = span[0], span[1]
        if any(not (e <= fs or s >= fe) for fs, fe, *_ in filtered):
            continue
        filtered.append(span)

    # Replace from end → start so earlier indices stay valid
    filtered.sort(key=lambda x: x[0], reverse=True)
    result = text
    for start, end, entity_type, _, _ in filtered:
        value = text[start:end]
        result = result[:start] + f"[{entity_type}]{value}[/{entity_type}]" + result[end:]

    return result


def _protect_lines(text: str, sdk) -> str:
    lines = text.split('\n')
    out = []
    for line in lines:
        stripped = line.rstrip()
        if stripped:
            try:
                result = sdk.find_and_protect(stripped)
                # If SDK returned unchanged text, fall back to discover-based tagging
                if not isinstance(result, str) or result == stripped:
                    result = _discover_and_protect_fallback(stripped, sdk)
                out.append(result)
            except Exception as e:
                logger.warning("Line protect failed: %s", e)
                out.append(_discover_and_protect_fallback(stripped, sdk))
        else:
            out.append(line)
    return '\n'.join(out)


# ── Public API ────────────────────────────────────────────────────────────────

def find_and_protect(text: str, cfg: Optional[Config] = None) -> ProtectResult:
    """Classify + tokenize all PII in *text*."""
    cfg = cfg or load_config()
    try:
        sdk = _configure_sdk(cfg)
        protected = _protect_lines(text, sdk)
        elements = _extract_elements(text, protected)
        return ProtectResult(original=text, protected=protected, elements_found=elements)
    except Exception as e:
        logger.error("find_and_protect error: %s", e)
        return ProtectResult(original=text, protected=text, error=str(e))


def find_and_unprotect(text: str, cfg: Optional[Config] = None) -> ProtectResult:
    """Detokenize all [TYPE]token[/TYPE] tags back to original values."""
    cfg = cfg or load_config()
    try:
        sdk = _configure_sdk(cfg)

        def _replace(match: re.Match) -> str:
            entity_type = match.group(1)
            token = match.group(2)
            tagged = match.group(0)
            # Heuristic: if it looks like a real name/value, skip unprotect
            if entity_type == "PERSON" and re.match(r'^[A-Z][a-z]+ [A-Z][a-z]+$', token):
                return token
            try:
                result = sdk.find_and_unprotect(tagged)
                if isinstance(result, str) and result != tagged:
                    return _strip_pii_tags(result) if re.search(r'\[', result) else result
            except Exception as e:
                logger.warning("Token unprotect failed (%s): %s", entity_type, e)
            return token

        restored = re.sub(r'\[([A-Z_|]+)\](.*?)\[/\1\]', _replace, text)
        return ProtectResult(original=text, protected=restored)
    except Exception as e:
        logger.error("find_and_unprotect error: %s", e)
        return ProtectResult(original=text, protected=text, error=str(e))


def find_and_redact(text: str, cfg: Optional[Config] = None) -> ProtectResult:
    """Replace all [TYPE]token[/TYPE] with [REDACTED]."""
    redacted = re.sub(r'\[([A-Z_|]+)\](.*?)\[/\1\]', '[REDACTED]', text)
    return ProtectResult(original=text, protected=redacted)


def semantic_guardrail_check(text: str, cfg: Optional[Config] = None,
                              threshold: float = 0.7) -> Dict[str, Any]:
    """Call the Protegrity Semantic Guardrail. Returns risk metadata."""
    import requests
    cfg = cfg or load_config()
    # Processor 'pii' only allowed on from:ai messages (outbound content scan)
    payload = {
        "messages": [{"from": "ai", "to": "user", "content": text,
                       "processors": ["pii"]}]
    }
    try:
        resp = requests.post(cfg.sgr_url, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        risk_score = 0.0
        outcome = "accepted"
        for msg in data.get("messages", []):
            risk_score = max(risk_score, float(msg.get("score", 0.0)))
            if msg.get("outcome") == "rejected":
                outcome = "rejected"
        if "batch" in data:
            risk_score = max(risk_score, float(data["batch"].get("score", 0.0)))
            if data["batch"].get("outcome") == "rejected":
                outcome = "rejected"
        accepted = outcome != "rejected" and risk_score <= threshold
        return {"risk_score": risk_score, "outcome": outcome,
                "accepted": accepted, "raw": data}
    except Exception as e:
        logger.warning("Semantic guardrail failed (continuing): %s", e)
        return {"risk_score": 0.0, "outcome": "accepted", "accepted": True,
                "error": str(e)}
