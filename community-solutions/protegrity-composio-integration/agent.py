"""
Composio Agent with embedded Protegrity gates.

Flow for every user request:
  1. Composio agent executes one or more platform tool calls (GitHub, Gmail, Slack…)
     – Uses the composio CLI binary (which handles auth) to execute tools
  2. After EACH tool response, Gate 1 runs: Protegrity find_and_protect tokenizes PII
  3. The agent continues working with protected (tokenized) data only
  4. The final answer is returned with PII protected throughout
  5. Separately, /api/reveal can run Gate 2 (find_and_unprotect) for authorized roles

This keeps real PII out of the LLM context and all downstream platforms.

Auth note: The composio CLI binary (/home/azure_usr/.composio/composio) is used
for API calls since the UAK (user-api-key from CLI login) works with the CLI's
own backend but not directly with the composio Python SDK (which requires a
project API key from platform.composio.dev). Generate a PAK at:
  https://platform.composio.dev → Settings → API Keys
and set COMPOSIO_API_KEY=pak_... in your .env to enable full SDK mode.
"""
from __future__ import annotations
import json, logging, sys, os, subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure parent dir on path so config/protegrity_bridge import correctly
sys.path.insert(0, str(Path(__file__).parent))

from config import Config, load_config
import protegrity_bridge as pb
import shutil

logger = logging.getLogger(__name__)

COMPOSIO_CLI = (
    shutil.which("composio")
    or str(Path.home() / "myenv" / "bin" / "composio")
    or str(Path.home() / ".composio" / "composio")
)


# ── RBAC roles ────────────────────────────────────────────────────────────────
# In a real deployment these would come from your IdP / Protegrity policy engine.
RBAC_ROLES = {
    "admin":   {"can_reveal": True,  "description": "Full access — can detokenize PII"},
    "analyst": {"can_reveal": False, "description": "Redacted view — no PII revealed"},
    "viewer":  {"can_reveal": False, "description": "Token view — sees Protegrity tokens"},
}


# ── Demo data with rich PII — used when no apps are connected ─────────────────
DEMO_SCENARIOS = {
    "github": [
        {
            "app": "GitHub",
            "action": "List Repositories",
            "raw": json.dumps({
                "repositories": [
                    {"name": "customer-portal", "owner": "john.smith@acme.com",
                     "description": "Portal for Alex Johnson (SSN: 123-45-6789)"},
                    {"name": "payroll-service", "owner": "sarah.doe@acme.com",
                     "description": "Payroll for US employees, CC: 4111-1111-1111-1111"},
                ]
            }, indent=2)
        },
        {
            "app": "GitHub",
            "action": "List Issues",
            "raw": json.dumps({
                "issues": [
                    {"id": 1, "title": "Bug in payment processing",
                     "assignee": "mike.williams@acme.com",
                     "body": "Contact: +1 (555) 867-5309 or mike.williams@acme.com. SSN: 987-65-4321"},
                    {"id": 2, "title": "Update customer record for DOB: 1990-03-15",
                     "assignee": "alice.johnson@corp.com",
                     "body": "Customer Alice Johnson, IP: 192.168.1.100 needs profile update"},
                ]
            }, indent=2)
        },
    ],
    "email": [
        {
            "app": "Gmail",
            "action": "Fetch Recent Emails",
            "raw": json.dumps({
                "messages": [
                    {"from": "hr@company.com", "to": "bob.brown@company.com",
                     "subject": "Salary Update",
                     "body": "Hi Bob Brown, your new salary has been updated. "
                             "SSN: 456-78-9012, Bank: 4532015112830366"},
                    {"from": "it@company.com", "to": "carol.white@company.com",
                     "subject": "VPN Credentials",
                     "body": "Carol White (carol.white@company.com), your temp password "
                             "is: P@ssw0rd123. Please call +1 (800) 555-0199 with issues."},
                ]
            }, indent=2)
        },
    ],
    "salesforce": [
        {
            "app": "Salesforce",
            "action": "Get Leads",
            "raw": json.dumps({
                "leads": [
                    {"name": "David Clark", "email": "d.clark@prospect.com",
                     "phone": "+1 (415) 555-2671",
                     "ssn": "321-54-9876",
                     "address": "123 Market St, San Francisco, CA 94105"},
                    {"name": "Emma Wilson", "email": "emma.w@leads.io",
                     "phone": "+44 20 7946 0958",
                     "dob": "1985-07-22",
                     "credit_card": "5500-0000-0000-0004"},
                ]
            }, indent=2)
        },
    ],
    "default": [
        {
            "app": "Platform API",
            "action": "Fetch Customer Data",
            "raw": json.dumps({
                "customers": [
                    {"id": "C001", "name": "Frank Harris",
                     "email": "frank.harris@example.com",
                     "phone": "+1 (212) 555-0147",
                     "ssn": "111-22-3333",
                     "cc": "4012-8888-8888-1881",
                     "dob": "1978-11-30"},
                    {"id": "C002", "name": "Grace Martinez",
                     "email": "grace.m@business.org",
                     "phone": "+1 (312) 555-9876",
                     "address": "456 Oak Ave, Chicago, IL 60601"},
                ]
            }, indent=2)
        },
        {
            "app": "CRM System",
            "action": "Enrich Profile",
            "raw": json.dumps({
                "enriched_profile": {
                    "name": "Frank Harris",
                    "linkedin": "linkedin.com/in/frankharris",
                    "company": "Acme Corp",
                    "additional_email": "f.harris@personal.com",
                    "ip_address": "203.0.113.42",
                    "last_purchase_cc": "4012-8888-8888-1881",
                }
            }, indent=2)
        },
    ],
}


def _get_demo_steps(prompt: str) -> List[Dict[str, str]]:
    """Choose demo scenario based on keywords in the prompt."""
    p = prompt.lower()
    if any(k in p for k in ["github", "repo", "issue", "pr", "code"]):
        return DEMO_SCENARIOS["github"]
    if any(k in p for k in ["email", "gmail", "mail", "inbox"]):
        return DEMO_SCENARIOS["email"]
    if any(k in p for k in ["salesforce", "lead", "crm", "contact"]):
        return DEMO_SCENARIOS["salesforce"]
    return DEMO_SCENARIOS["default"]


# ── CLI helper ────────────────────────────────────────────────────────────────

def _run_cli(*args: str, timeout: int = 15) -> Dict[str, Any]:
    """Run a composio CLI command and return parsed JSON output."""
    cmd = [COMPOSIO_CLI] + list(args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0 and result.stdout.strip():
            try:
                return {"ok": True, "data": json.loads(result.stdout)}
            except json.JSONDecodeError:
                return {"ok": True, "data": result.stdout.strip()}
        return {"ok": False, "error": result.stderr.strip() or "no output"}
    except FileNotFoundError:
        return {"ok": False, "error": f"composio CLI not found at {COMPOSIO_CLI}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "CLI timeout"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def get_connected_apps() -> List[Dict[str, Any]]:
    """Return list of connected Composio apps using the CLI binary."""
    result = _run_cli("connected-accounts", "list")
    if result["ok"] and isinstance(result.get("data"), list):
        return result["data"]
    return []


def get_available_toolkits() -> List[Dict[str, Any]]:
    """Return available toolkits from Composio CLI."""
    result = _run_cli("toolkits", "list")
    if result["ok"] and isinstance(result.get("data"), list):
        return result["data"]
    return []


# ── Pipeline step model ────────────────────────────────────────────────────────
class PipelineStep:
    def __init__(self, step_num: int, app: str, action: str,
                 raw: str, protected: str, elements: List[Dict]):
        self.step_num = step_num
        self.app = app
        self.action = action
        self.raw = raw
        self.protected = protected
        self.elements = elements

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step_num,
            "app": self.app,
            "action": self.action,
            "raw_data": self.raw,
            "protected_data": self.protected,
            "pii_elements": self.elements,
            "pii_detected": self.raw != self.protected or bool(self.elements),
        }


# ── Composio agent runner ─────────────────────────────────────────────────────

class ProtegrityComposioAgent:
    """
    An OpenAI + Composio agent that gates every tool response through Protegrity.

    Modes:
      Live mode  – Composio apps are connected; uses composio_openai SDK + real tools
      Demo mode  – No apps connected; uses synthetic PII data to demonstrate the pipeline
    """

    def __init__(self, cfg: Optional[Config] = None):
        self.cfg = cfg or load_config()
        self._pipeline_steps: List[PipelineStep] = []
        self._step_counter = 0

    def _protect_tool_result(self, app: str, action: str, raw_text: str) -> str:
        """Apply Protegrity Gate 1 on any data returned by a Composio tool."""
        result = pb.find_and_protect(raw_text, cfg=self.cfg)
        self._step_counter += 1
        step = PipelineStep(
            step_num=self._step_counter,
            app=app,
            action=action,
            raw=raw_text,
            protected=result.protected,
            elements=result.elements_found,
        )
        self._pipeline_steps.append(step)
        logger.info("Gate 1 applied [step %d]: %d PII elements found in %s/%s",
                    self._step_counter, len(result.elements_found), app, action)
        return result.protected

    def _run_demo_mode(self, user_prompt: str) -> Dict[str, Any]:
        """
        Demo pipeline: uses synthetic PII-rich data to show Gate 1 and Gate 2.
        Run when no Composio apps are connected.
        """
        demo_steps = _get_demo_steps(user_prompt)
        protected_pieces = []

        for step in demo_steps:
            protected = self._protect_tool_result(
                step["app"], step["action"], step["raw"]
            )
            protected_pieces.append(f"[{step['app']} - {step['action']}]\n{protected}")

        combined = "\n\n".join(protected_pieces)
        total_pii = sum(len(s.elements) for s in self._pipeline_steps)

        final_answer = (
            f"I completed the pipeline for: '{user_prompt}'\n\n"
            f"Data was fetched from {len(demo_steps)} sources.\n"
            f"Protegrity detected and tokenized {total_pii} PII entities across all fetched data.\n"
            f"All sensitive information has been replaced with Protegrity tokens.\n\n"
            f"Protected data summary:\n{combined}"
        )
        # Protect the final answer too
        final_result = pb.find_and_protect(final_answer, cfg=self.cfg)
        if final_result.pii_detected:
            self._step_counter += 1
            self._pipeline_steps.append(PipelineStep(
                step_num=self._step_counter,
                app="Summary",
                action="Final Answer",
                raw=final_answer,
                protected=final_result.protected,
                elements=final_result.elements_found,
            ))
            final_answer = final_result.protected

        return {
            "pipeline": [s.to_dict() for s in self._pipeline_steps],
            "final_answer": final_answer,
            "total_steps": self._step_counter,
            "mode": "demo",
            "error": None,
        }

    def _run_live_mode(self, user_prompt: str) -> Dict[str, Any]:
        """
        Live pipeline: uses OpenAI + Composio SDK to run real tools.
        Gate 1 applied to every tool response.
        """
        try:
            from openai import OpenAI
            from composio_openai import ComposioToolSet, App
        except ImportError as e:
            return {"error": f"Missing package: {e}", "pipeline": [], "final_answer": ""}

        os.environ["COMPOSIO_API_KEY"] = self.cfg.composio_api_key
        client = OpenAI(api_key=self.cfg.openai_api_key)

        # Get tools using SDK (requires PAK; falls back to empty if UAK)
        tools = []
        try:
            toolset = ComposioToolSet(api_key=self.cfg.composio_api_key)
            tools = toolset.get_tools(apps=[App.GITHUB])
        except Exception as e:
            logger.warning("SDK tool load failed (%s), falling back to demo mode", e)
            return self._run_demo_mode(user_prompt)

        system_prompt = (
            "You are a secure data-retrieval agent. "
            "When you fetch data from external platforms, summarize it clearly. "
            "Always use the available tools to fetch real data. "
            "Treat tokenized values like [EMAIL_ADDRESS]abc123[/EMAIL_ADDRESS] as opaque identifiers. "
            "Provide a clear summary of what you found."
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ]

        MAX_ITERATIONS = 8
        toolset_ref = toolset  # keep reference for execute_tool_call

        for iteration in range(MAX_ITERATIONS):
            response = client.chat.completions.create(
                model=self.cfg.openai_model,
                messages=messages,
                tools=tools if tools else None,
                tool_choice="auto" if tools else None,
            )
            msg = response.choices[0].message
            finish_reason = response.choices[0].finish_reason

            if finish_reason == "stop" or not msg.tool_calls:
                final_answer = msg.content or ""
                protected_answer_result = pb.find_and_protect(final_answer, cfg=self.cfg)
                if protected_answer_result.pii_detected:
                    self._step_counter += 1
                    self._pipeline_steps.append(PipelineStep(
                        step_num=self._step_counter,
                        app="LLM",
                        action="Final Answer",
                        raw=final_answer,
                        protected=protected_answer_result.protected,
                        elements=protected_answer_result.elements_found,
                    ))
                    final_answer = protected_answer_result.protected

                return {
                    "pipeline": [s.to_dict() for s in self._pipeline_steps],
                    "final_answer": final_answer,
                    "total_steps": self._step_counter,
                    "mode": "live",
                    "error": None,
                }

            messages.append(msg)
            for tc in msg.tool_calls:
                fn_name = tc.function.name
                app_name, action_name = _parse_tool_name(fn_name)
                logger.info("Calling tool: %s (app=%s action=%s)", fn_name, app_name, action_name)
                try:
                    tool_result = toolset_ref.execute_tool_call(tc, entity_id="default")
                    raw_text = _result_to_text(tool_result)
                except Exception as e:
                    raw_text = f"[Tool error: {e}]"
                    logger.warning("Tool %s failed: %s", fn_name, e)

                # ── Gate 1: Protect before putting result back into agent ──
                protected_text = self._protect_tool_result(app_name, action_name, raw_text)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": protected_text,
                })

        return {
            "pipeline": [s.to_dict() for s in self._pipeline_steps],
            "final_answer": "Maximum iterations reached.",
            "total_steps": self._step_counter,
            "mode": "live",
            "error": "max_iterations",
        }

    def run(self, user_prompt: str) -> Dict[str, Any]:
        """
        Execute the agent pipeline with full Protegrity protection.
        Auto-selects demo mode if no Composio apps are connected.
        Returns: pipeline steps + final protected answer.
        """
        self._pipeline_steps = []
        self._step_counter = 0

        # Check if we have real connected apps
        connected = get_connected_apps()
        if connected:
            logger.info("Live mode: %d connected apps found", len(connected))
            return self._run_live_mode(user_prompt)
        else:
            logger.info("Demo mode: no connected apps, using synthetic PII data")
            return self._run_demo_mode(user_prompt)

    def reveal(self, text: str, role: str) -> Dict[str, Any]:
        """Gate 2: Detokenize protected text if the RBAC role permits it."""
        role_info = RBAC_ROLES.get(role.lower(), RBAC_ROLES["viewer"])
        if not role_info["can_reveal"]:
            redacted = pb.find_and_redact(text, cfg=self.cfg)
            return {
                "revealed": False,
                "role": role,
                "text": redacted.protected,
                "reason": f"Role '{role}' cannot reveal PII. {role_info['description']}",
            }
        result = pb.find_and_unprotect(text, cfg=self.cfg)
        return {
            "revealed": True,
            "role": role,
            "text": result.protected,
            "reason": f"Role '{role}' authorized. Protegrity RBAC detokenize applied.",
        }


# ── Utilities ─────────────────────────────────────────────────────────────────

def _parse_tool_name(fn_name: str):
    """Split GITHUB_LIST_ISSUES → ('GitHub', 'List Issues')"""
    parts = fn_name.split("_", 1)
    app = parts[0].title() if parts else fn_name
    action = parts[1].replace("_", " ").title() if len(parts) > 1 else fn_name
    return app, action


def _result_to_text(tool_result: Any) -> str:
    """Convert a Composio tool result to a string for Protegrity processing."""
    if isinstance(tool_result, str):
        return tool_result
    if isinstance(tool_result, dict):
        # Extract the useful content; remove internal metadata if present
        data = tool_result.get("data") or tool_result.get("result") or tool_result
        try:
            return json.dumps(data, indent=2, default=str)
        except Exception:
            return str(data)
    try:
        return json.dumps(tool_result, indent=2, default=str)
    except Exception:
        return str(tool_result)
