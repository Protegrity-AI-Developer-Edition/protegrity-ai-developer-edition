#!/usr/bin/env python3
"""
CyberGuard AI — MCP server.
Exposes security tools as MCP tools so any MCP-capable model can
call them live instead of reading a static telemetry snapshot.

Run standalone:
    python src/mcp_server.py

Or register in Claude Code settings as a stdio server:
    {
      "mcpServers": {
        "cyberguard": {
          "command": "python",
          "args": ["/Users/dadsmacpro/CyberGuardAI/src/mcp_server.py"]
        }
      }
    }

The FastAPI backend (kerrigan_server.py) must be running on port 7432
for the DB/honeypot/firewall tools to return live data.
"""

import asyncio
import json
import re
import subprocess
import time
from pathlib import Path

import httpx
from fastmcp import FastMCP

BASE_URL = "http://localhost:7432"
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

mcp = FastMCP("CyberGuard AI", dependencies=["httpx"])


# ── helpers ──────────────────────────────────────────────────────────────────

async def _get(path: str, params: dict = None) -> dict:
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.get(f"{BASE_URL}{path}", params=params or {})
        return r.json()


async def _post(path: str, body: dict) -> dict:
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(f"{BASE_URL}{path}", json=body)
        return r.json()


# ── tools ─────────────────────────────────────────────────────────────────────

@mcp.tool()
async def system_status() -> str:
    """Return AI model status, memory count, and uptime of the CyberGuard backend."""
    data = await _get("/status")
    return json.dumps(data, indent=2)


@mcp.tool()
async def honeypot_counts() -> str:
    """Return live honeypot hit counts (SSH, web, DB, FTP, SMTP, RDP) and the 20 most recent attacker events."""
    data = await _get("/honeypot/counts")
    return json.dumps(data, indent=2)


@mcp.tool()
async def firewall_blocked() -> str:
    """List IPs currently blocked in the live pf firewall table."""
    data = await _get("/firewall/blocked")
    return json.dumps(data, indent=2)


@mcp.tool()
async def patcher_status() -> str:
    """Return fuzzer state, crash counts, PQC key status, and adaptive-defense rule counts."""
    data = await _get("/patcher/status")
    return json.dumps(data, indent=2)


@mcp.tool()
async def network_arp() -> str:
    """Return ARP table — all devices currently visible on the local network."""
    data = await _get("/network/arp")
    return json.dumps(data, indent=2)


@mcp.tool()
async def network_routes() -> str:
    """Return the routing table (up to 30 entries)."""
    data = await _get("/network/routes")
    return json.dumps(data, indent=2)


@mcp.tool()
async def port_scan(target: str = "127.0.0.1", ports: list[int] = None) -> str:
    """
    Async TCP port scan. Returns open ports with banners.
    Args:
        target: IP or hostname to scan (default: localhost).
        ports: list of port numbers (default: common service ports).
    """
    body = {"target": target}
    if ports:
        body["ports"] = ports
    data = await _post("/pentest/portscan", body)
    return json.dumps(data, indent=2)


@mcp.tool()
async def ssl_audit(host: str = "localhost", port: int = 443) -> str:
    """
    Check TLS/SSL configuration for a host — TLS version, weak ciphers, certificate validity.
    Args:
        host: hostname or IP.
        port: port number (default: 443).
    """
    data = await _get("/pentest/ssl", {"host": host, "port": port})
    return json.dumps(data, indent=2)


@mcp.tool()
async def header_audit(url: str = "http://localhost") -> str:
    """
    Check HTTP security headers for a URL (HSTS, CSP, X-Frame-Options, etc.).
    Args:
        url: full URL to check.
    """
    data = await _get("/pentest/headers", {"url": url})
    return json.dumps(data, indent=2)


@mcp.tool()
async def ssh_key_audit() -> str:
    """Audit SSH private keys in ~/.ssh — key type, bit strength, and weak-key warnings."""
    data = await _get("/pentest/ssh-audit")
    return json.dumps(data, indent=2)


@mcp.tool()
async def cve_lookup(query: str = "macos") -> str:
    """
    Search the NVD CVE database for vulnerabilities matching a keyword.
    Args:
        query: keyword (e.g. 'macos', 'openssh', 'nginx 1.24').
    """
    data = await _get("/scan/cve", {"q": query})
    return json.dumps(data, indent=2)


@mcp.tool()
async def threat_hunt(path: str = ".") -> str:
    """
    Run the Kerrigan threat hunter against a directory. Returns findings and risk score.
    Args:
        path: filesystem path to scan (default: current working directory).
    """
    data = await _post("/hunt", {"path": path})
    return json.dumps(data, indent=2)


@mcp.tool()
async def recent_crashes(limit: int = 20) -> str:
    """
    Return the most recent fuzzer crash records from the database.
    Args:
        limit: max records to return (default: 20).
    """
    data = await _get("/db/crashes", {"limit": limit})
    return json.dumps(data, indent=2)


@mcp.tool()
async def recent_memories(limit: int = 20) -> str:
    """
    Return the most recent Kerrigan memory entries (threat intel, learned patterns).
    Args:
        limit: max records (default: 20).
    """
    data = await _get("/db/memories", {"limit": limit})
    return json.dumps(data, indent=2)


@mcp.tool()
async def firewall_unblock(ip: str) -> str:
    """
    Remove an IP from the live pf block table (manual override).
    Args:
        ip: IPv4 address to unblock.
    """
    if not _IP_RE.match(ip):
        return json.dumps({"error": "invalid IP address"})
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.delete(f"{BASE_URL}/firewall/blocked/{ip}")
        return json.dumps(r.json(), indent=2)


if __name__ == "__main__":
    mcp.run()
