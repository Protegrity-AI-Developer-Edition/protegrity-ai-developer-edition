#!/usr/bin/env python3
"""
CyberGuard AI backend — FastAPI server on localhost:7432.
Killed when Electron closes.

Endpoints:
  POST /chat   { message, history } → { reply, blocked, model }
  GET  /status → { model, memory_count, uptime_s }
  POST /hunt   { path } → { findings, risk_score }
"""

import sys
import os
import re
import time
import json
import asyncio
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT = int(os.environ.get("DB_PORT", 3306))
DB_USER = os.environ.get("DB_USER", "root")
DB_PASS = os.environ.get("DB_PASS", "")
DB_NAME = os.environ.get("DB_NAME", "kerrigan_db")

# ── Add kerrigan-fantasma to path ─────────────────────────────────────────────
KERRIGAN_DIR = os.environ.get("KERRIGAN_PATH", str(Path(__file__).parent))
sys.path.insert(0, KERRIGAN_DIR)
os.chdir(KERRIGAN_DIR)

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn

# ── Lazy kerrigan imports (don't crash if deps missing) ──────────────────────
try:
    from router.abathur import Abathur
    from verifier.overmind import Overmind
    from memory.creep import Creep
    KERRIGAN_AVAILABLE = True
except Exception as e:
    print(f"[Server] AI modules not fully available: {e}")
    KERRIGAN_AVAILABLE = False

try:
    import ollama as _ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

@asynccontextmanager
async def lifespan(app):
    _init()
    _ensure_tables()
    _ensure_conversations_table()
    asyncio.create_task(_ssh_honeypot())
    asyncio.create_task(_web_honeypot())
    asyncio.create_task(_db_honeypot())
    asyncio.create_task(_ftp_honeypot())
    asyncio.create_task(_smtp_honeypot())
    asyncio.create_task(_rdp_honeypot())
    _start_fuzzer()
    print("CyberGuard AI server ready", flush=True)
    yield

app       = FastAPI(title="CyberGuard AI Server", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
_start    = time.time()
_router   = None
_overmind = None
_memory   = None
_model    = os.environ.get("KERRIGAN_MODEL", "kerrigan-fantasma:latest")

# ── Fuzzer agent state (written by background thread, read by /patcher/status) ─
import threading
_fuzzer_lock  = threading.Lock()
_fuzzer_state = {
    "running":            False,
    "phase":              "idle",      # idle|generating|compiling|fuzzing|triaging|analyzing|evolving
    "target":             "",
    "iteration":          0,
    "session_crashes":    0,
    "session_start":      None,
    "last_event":         "",
    "total_iterations":   0,
}

# Target rotation — cycles through protocol/format parsers
_FUZZ_TARGETS = [
    "HTTP request parser",
    "DNS packet parser",
    "SSH protocol parser",
    "ZIP file parser",
    "JSON parser",
    "XML parser",
    "TLS/SSL handshake parser",
    "PDF file parser",
]
_target_cursor = 0

def _set_phase(phase: str, event: str = "", target: str = ""):
    with _fuzzer_lock:
        _fuzzer_state["phase"] = phase
        if event:     _fuzzer_state["last_event"] = event
        if target:    _fuzzer_state["target"]      = target

def _fuzzer_loop():
    global _target_cursor
    import importlib, sys as _sys

    # Ensure kerrigan-fantasma is importable from this thread
    if KERRIGAN_DIR not in _sys.path:
        _sys.path.insert(0, KERRIGAN_DIR)

    try:
        from loop.evolution import EvolutionaryLoop
    except Exception as e:
        print(f"[Fuzzer] Cannot import EvolutionaryLoop: {e}", flush=True)
        _set_phase("idle", f"import failed: {e}")
        return

    with _fuzzer_lock:
        _fuzzer_state["running"] = True
        _fuzzer_state["session_start"] = time.time()

    print("[Fuzzer] Agent loop started", flush=True)

    while True:
        try:
            target = _FUZZ_TARGETS[_target_cursor % len(_FUZZ_TARGETS)]
            _target_cursor += 1

            _set_phase("generating", f"generating harness for {target}", target)
            loop = EvolutionaryLoop(n_fuzz=30, max_retries=2,
                                    seed=_target_cursor)

            # Patch phase callbacks into the loop so we get live status
            orig_compile = loop.compiler.compile
            def compile_with_phase(code, name="harness"):
                _set_phase("compiling", f"compiling {name}")
                return orig_compile(code, name=name)
            loop.compiler.compile = compile_with_phase

            orig_fuzz = loop.fuzzer.fuzz
            def fuzz_with_phase(binary, seed=b"", n_inputs=100):
                _set_phase("fuzzing", f"fuzzing {target} ({n_inputs} inputs)")
                return orig_fuzz(binary, seed=seed, n_inputs=n_inputs)
            loop.fuzzer.fuzz = fuzz_with_phase

            _set_phase("generating", f"LLM generating harness for {target}")
            session = loop.run(target, iterations=3)

            # Write new crashes to DB
            conn = _get_db()
            if conn:
                try:
                    cur = conn.cursor()
                    for crash in session.all_crashes:
                        _set_phase("triaging", f"saving crash {crash.crash_id[:8]}")
                        cur.execute("""
                            INSERT IGNORE INTO crashes
                                (crash_type, `signal`, exploitability, created_at)
                            VALUES (%s, %s, %s, NOW())
                        """, (crash.crash_type.value, getattr(crash, 'signal', ''),
                              crash.exploitability))
                    cur.execute("""
                        INSERT INTO sessions
                            (session_id, target, total_crashes, status, started_at)
                        VALUES (%s, %s, %s, %s, NOW())
                    """, (f"auto_{int(time.time())}", target,
                          len(session.all_crashes), "complete"))
                    conn.commit()
                except Exception as e:
                    print(f"[Fuzzer] DB write error: {e}", flush=True)
                finally:
                    conn.close()

            with _fuzzer_lock:
                _fuzzer_state["session_crashes"] += len(session.all_crashes)
                _fuzzer_state["total_iterations"] += len(session.iterations)

            _set_phase("evolving", f"evolving harness after {len(session.all_crashes)} crashes")

            # Rest 10s between targets so server stays responsive
            time.sleep(10)

        except Exception as e:
            print(f"[Fuzzer] Loop error: {e}", flush=True)
            _set_phase("idle", f"error: {str(e)[:80]}")
            time.sleep(30)  # back off on errors

def _start_fuzzer():
    if not KERRIGAN_AVAILABLE:
        print("[Fuzzer] kerrigan modules not available — skipping", flush=True)
        return
    t = threading.Thread(target=_fuzzer_loop, daemon=True, name="fuzzer-loop")
    t.start()

# ── MySQL direct connection ────────────────────────────────────────────────────
import hashlib

def _get_db():
    try:
        import mysql.connector
        return mysql.connector.connect(
            host=DB_HOST, port=DB_PORT,
            user=DB_USER, password=DB_PASS, database=DB_NAME
        )
    except Exception as e:
        print(f"[DB] MySQL unavailable: {e}")
        return None

def _ensure_tables():
    conn = _get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS honeypot_events (
                id            INT AUTO_INCREMENT PRIMARY KEY,
                honeypot_type VARCHAR(16) NOT NULL,
                attacker_ip   VARCHAR(64) NOT NULL,
                attacker_port INT,
                payload       TEXT,
                created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_type (honeypot_type),
                INDEX idx_ip   (attacker_ip),
                INDEX idx_time (created_at)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS crashes (
                id            INT AUTO_INCREMENT PRIMARY KEY,
                crash_type    VARCHAR(64),
                `signal`      VARCHAR(16),
                exploitability VARCHAR(16),
                created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_type (crash_type),
                INDEX idx_exploit (exploitability)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id            INT AUTO_INCREMENT PRIMARY KEY,
                session_id    VARCHAR(64) NOT NULL,
                target        VARCHAR(256),
                total_crashes INT DEFAULT 0,
                status        VARCHAR(32),
                started_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_sid (session_id)
            )
        """)
        conn.commit()
    except Exception as e:
        print(f"[DB] honeypot_events table error: {e}")
    finally:
        conn.close()

_PF_TABLE      = "cyberguard_block"
_PF_BLOCKLIST  = "/etc/cyberguard_blocklist"
_IP_RE         = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")

def _block_ip(ip: str):
    """Add attacker IP to the live pf table and persist it across reboots.

    Requires the one-time setup in setup_pf.sh (adds pf table + sudoers rule).
    Fails silently if pf is not configured — rest of honeypot logging still runs.
    """
    if not _IP_RE.match(ip):
        return
    try:
        import subprocess
        result = subprocess.run(
            ["sudo", "/sbin/pfctl", "-t", _PF_TABLE, "-T", "add", ip],
            capture_output=True, timeout=5
        )
        # Persist so the block survives a reboot
        with open(_PF_BLOCKLIST, "a") as f:
            f.write(ip + "\n")
        if result.returncode == 0:
            print(f"[Firewall] Blocked {ip}", flush=True)
        else:
            # pf not set up yet — log quietly, don't crash
            print(f"[Firewall] pf not configured (run setup_pf.sh): {result.stderr.decode()[:80]}", flush=True)
    except Exception as e:
        print(f"[Firewall] Block failed for {ip}: {e}")


# ── Subnet-level blocking ─────────────────────────────────────────────────────
_subnet_hits: dict = {}          # "/24 prefix" -> hit count
_seen_ips:    set  = set()       # IPs seen this server session (for first-hit alert)
_SUBNET_BLOCK_THRESHOLD = 3      # block /24 after this many distinct hits

def _subnet_prefix(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ip

def _check_subnet_block(ip: str):
    prefix = _subnet_prefix(ip)
    _subnet_hits[prefix] = _subnet_hits.get(prefix, 0) + 1
    if _subnet_hits[prefix] == _SUBNET_BLOCK_THRESHOLD:
        print(f"[Firewall] Subnet threshold hit — blocking {prefix}", flush=True)
        try:
            import subprocess
            subprocess.run(
                ["sudo", "/sbin/pfctl", "-t", _PF_TABLE, "-T", "add", prefix],
                capture_output=True, timeout=5
            )
            with open(_PF_BLOCKLIST, "a") as f:
                f.write(prefix + "\n")
        except Exception as e:
            print(f"[Firewall] Subnet block error: {e}")

def _send_alert(honeypot_type: str, ip: str, port: int, payload: str):
    """Send a Resend email alert on first hit from a new IP."""
    api_key = os.environ.get("RESEND_API_KEY", "")
    if not api_key:
        return
    try:
        import resend
        resend.api_key = api_key
        from_addr  = os.environ.get("ALERT_FROM",  "alerts@cyberguard.local")
        to_addr    = os.environ.get("ALERT_EMAIL",  "brian.thomas.t@gmail.com")
        resend.Emails.send({
            "from":    from_addr,
            "to":      [to_addr],
            "subject": f"[CyberGuard] New attacker: {ip} → {honeypot_type}",
            "html":    f"""
<h2>Honeypot Alert</h2>
<table>
  <tr><td><b>Type</b></td><td>{honeypot_type}</td></tr>
  <tr><td><b>Attacker IP</b></td><td>{ip}</td></tr>
  <tr><td><b>Port</b></td><td>{port}</td></tr>
  <tr><td><b>Payload</b></td><td><code>{payload[:400]}</code></td></tr>
  <tr><td><b>Subnet hits</b></td><td>{_subnet_hits.get(_subnet_prefix(ip), 1)}</td></tr>
</table>
<p>IP has been auto-blocked in pf.</p>
""",
        })
        print(f"[Alert] Email sent for new attacker {ip}", flush=True)
    except Exception as e:
        print(f"[Alert] Email failed: {e}", flush=True)

def _log_honeypot(honeypot_type, attacker_ip, attacker_port, payload=""):
    first_hit = attacker_ip not in _seen_ips
    _seen_ips.add(attacker_ip)

    conn = _get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO honeypot_events (honeypot_type, attacker_ip, attacker_port, payload) VALUES (%s,%s,%s,%s)",
            (honeypot_type, attacker_ip, int(attacker_port or 0), payload[:1000])
        )
        conn.commit()
        _save_memory_to_db(
            f"Honeypot hit [{honeypot_type}]: attacker {attacker_ip}:{attacker_port} — {payload[:200]}",
            expert="honeypot",
            tags=f"honeypot,{honeypot_type},{attacker_ip}"
        )
    except Exception as e:
        print(f"[DB] honeypot log error: {e}")
    finally:
        conn.close()

    # Block attacker immediately
    _block_ip(attacker_ip)
    # Subnet-level block if threshold reached
    _check_subnet_block(attacker_ip)
    # Email on first hit from this IP
    if first_hit:
        threading.Thread(
            target=_send_alert,
            args=(honeypot_type, attacker_ip, attacker_port, payload),
            daemon=True
        ).start()

def _ensure_conversations_table():
    conn = _get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS conversations (
                id         INT AUTO_INCREMENT PRIMARY KEY,
                conv_id    VARCHAR(32) NOT NULL,
                role       VARCHAR(16) NOT NULL,
                content    TEXT NOT NULL,
                model      VARCHAR(64),
                blocked    TINYINT(1) DEFAULT 0,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_conv (conv_id),
                INDEX idx_created (created_at)
            )
        """)
        conn.commit()
    except Exception as e:
        print(f"[DB] Table create error: {e}")
    finally:
        conn.close()

def _save_to_db(conv_id, role, content, model=None, blocked=False):
    conn = _get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO conversations (conv_id, role, content, model, blocked) VALUES (%s,%s,%s,%s,%s)",
            (conv_id, role, content, model, int(blocked))
        )
        conn.commit()
    except Exception as e:
        print(f"[DB] Save error: {e}")
    finally:
        conn.close()

def _save_memory_to_db(content, expert="cyberguard_chat", tags=None):
    conn = _get_db()
    if not conn: return
    try:
        mem_id = hashlib.md5(content.encode()).hexdigest()
        cur = conn.cursor()
        cur.execute(
            "INSERT IGNORE INTO memories (memory_id, content, expert, tags, created_at) VALUES (%s,%s,%s,%s,NOW())",
            (mem_id, content, expert, tags)
        )
        conn.commit()
    except Exception as e:
        print(f"[DB] Memory save error: {e}")
    finally:
        conn.close()


def _init():
    global _router, _overmind, _memory
    if not KERRIGAN_AVAILABLE:
        return
    try:
        _overmind = Overmind()
    except Exception as e:
        print(f"[Server] Overmind init error: {e}")
    try:
        _memory = Creep()
    except Exception as e:
        print(f"[Server] Creep init error: {e}")
    try:
        _router = Abathur()
    except Exception as e:
        print(f"[Server] Abathur init error: {e}")


# ── Routes ────────────────────────────────────────────────────────────────────

# ── Real Honeypots ─────────────────────────────────────────────────────────────

SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
HTTP_TRAP  = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Length: 0\r\n\r\n"
MYSQL_GREETING = (
    b"\x4a\x00\x00\x00"
    b"\x0a"
    b"8.0.32\x00"
    b"\x01\x00\x00\x00"
    b"\x52\x7d\x1f\x29\x65\x43\x41\x48\x00"
    b"\xff\xf7"
    b"\x21"
    b"\x02\x00"
    b"\xff\x81"
    b"\x15"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x7e\x31\x3e\x1c\x58\x58\x36\x73\x6a\x49\x5a\x55\x00"
    b"mysql_native_password\x00"
)

async def _ssh_honeypot(host="0.0.0.0", port=2222):
    async def handle(reader, writer):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        ip, p = peer[0], peer[1]
        try:
            writer.write(SSH_BANNER)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=10)
            payload = data.decode("utf-8", errors="replace").strip()
        except Exception:
            payload = ""
        finally:
            writer.close()
        print(f"[Honeypot-SSH] {ip}:{p} — {repr(payload[:80])}")
        _log_honeypot("ssh", ip, p, payload)
    try:
        srv = await asyncio.start_server(handle, host, port)
        print(f"[Honeypot] SSH listening on {port}", flush=True)
        async with srv:
            await srv.serve_forever()
    except Exception as e:
        print(f"[Honeypot] SSH failed on {port}: {e}")

async def _web_honeypot(host="0.0.0.0", port=8080):
    async def handle(reader, writer):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        ip, p = peer[0], peer[1]
        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=10)
            payload = data.decode("utf-8", errors="replace")
            first_line = payload.split("\n")[0].strip()
            writer.write(HTTP_TRAP)
            await writer.drain()
        except Exception:
            first_line = ""
        finally:
            writer.close()
        print(f"[Honeypot-Web] {ip}:{p} — {first_line[:120]}")
        _log_honeypot("web", ip, p, first_line)
    try:
        srv = await asyncio.start_server(handle, host, port)
        print(f"[Honeypot] Web listening on {port}", flush=True)
        async with srv:
            await srv.serve_forever()
    except Exception as e:
        print(f"[Honeypot] Web failed on {port}: {e}")

async def _db_honeypot(host="0.0.0.0", port=3307):
    async def handle(reader, writer):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        ip, p = peer[0], peer[1]
        try:
            writer.write(MYSQL_GREETING)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=10)
            payload = data.hex()[:120]
        except Exception:
            payload = ""
        finally:
            writer.close()
        print(f"[Honeypot-DB] {ip}:{p} — {payload}")
        _log_honeypot("database", ip, p, payload)
    try:
        srv = await asyncio.start_server(handle, host, port)
        print(f"[Honeypot] Database listening on {port}", flush=True)
        async with srv:
            await srv.serve_forever()
    except Exception as e:
        print(f"[Honeypot] Database failed on {port}: {e}")

FTP_BANNER  = b"220 ProFTPD 1.3.6 Server (FTP) [::]\r\n"
SMTP_BANNER = b"220 mail.cyberguard.local ESMTP Postfix (Ubuntu)\r\n"
SMTP_EHLO   = b"250-mail.cyberguard.local\r\n250-SIZE 52428800\r\n250-STARTTLS\r\n250 AUTH LOGIN PLAIN\r\n"
RDP_NACK    = bytes([0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
                     0x02, 0x01, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00])

async def _ftp_honeypot(host="0.0.0.0", port=2121):
    async def handle(reader, writer):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        ip, p = peer[0], peer[1]
        try:
            writer.write(FTP_BANNER)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=15)
            payload = data.decode("utf-8", errors="replace").strip()
        except Exception:
            payload = ""
        finally:
            writer.close()
        print(f"[Honeypot-FTP] {ip}:{p} — {repr(payload[:120])}")
        _log_honeypot("ftp", ip, p, payload)
    try:
        srv = await asyncio.start_server(handle, host, port)
        print(f"[Honeypot] FTP listening on {port}", flush=True)
        async with srv:
            await srv.serve_forever()
    except Exception as e:
        print(f"[Honeypot] FTP failed on {port}: {e}")

async def _smtp_honeypot(host="0.0.0.0", port=2525):
    async def handle(reader, writer):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        ip, p = peer[0], peer[1]
        lines = []
        try:
            writer.write(SMTP_BANNER)
            await writer.drain()
            # Read up to 3 SMTP commands so we capture EHLO + AUTH attempts
            for _ in range(3):
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").strip()
                lines.append(decoded)
                upper = decoded.upper()
                if upper.startswith("EHLO") or upper.startswith("HELO"):
                    writer.write(SMTP_EHLO)
                else:
                    writer.write(b"250 OK\r\n")
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
        payload = " | ".join(lines)
        print(f"[Honeypot-SMTP] {ip}:{p} — {payload[:120]}")
        _log_honeypot("smtp", ip, p, payload)
    try:
        srv = await asyncio.start_server(handle, host, port)
        print(f"[Honeypot] SMTP listening on {port}", flush=True)
        async with srv:
            await srv.serve_forever()
    except Exception as e:
        print(f"[Honeypot] SMTP failed on {port}: {e}")

async def _rdp_honeypot(host="0.0.0.0", port=3389):
    async def handle(reader, writer):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        ip, p = peer[0], peer[1]
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=10)
            writer.write(RDP_NACK)
            await writer.drain()
            payload = data.hex()[:160]
        except Exception:
            payload = ""
        finally:
            writer.close()
        print(f"[Honeypot-RDP] {ip}:{p} — {payload[:120]}")
        _log_honeypot("rdp", ip, p, payload)
    try:
        srv = await asyncio.start_server(handle, host, port)
        print(f"[Honeypot] RDP listening on {port}", flush=True)
        async with srv:
            await srv.serve_forever()
    except Exception as e:
        print(f"[Honeypot] RDP failed on {port}: {e}")


@app.post("/chat")
async def chat(request: Request):
    body    = await request.json()
    message     = body.get("message", "")
    history     = body.get("history", [])
    system_ctx  = body.get("system_context", "")

    # Safety gate first — screen the incoming request.
    # Overmind.verify() returns a Verdict with .passed / .reason.
    if _overmind:
        verdict = _overmind.verify(message, query=message)
        if not verdict.passed:
            return JSONResponse({"reply": f"[Blocked by Overmind: {verdict.reason}]", "blocked": True, "model": "overmind"})

    # Retrieve relevant memory (Creep exposes build_context / recall).
    mem_context = ""
    if _memory:
        try:
            mem_context = _memory.build_context(message)
        except Exception:
            pass

    # Gather live system state directly from the OS
    import subprocess, psutil
    live_lines = []
    try:
        # CPU / RAM
        cpu_pct = psutil.cpu_percent(interval=0.2)
        mem = psutil.virtual_memory()
        live_lines.append(f"CPU: {cpu_pct}% | RAM: {mem.used//1024//1024}MB / {mem.total//1024//1024}MB ({mem.percent}%)")
        # Top processes by CPU
        procs = sorted(psutil.process_iter(['pid','name','cpu_percent','memory_percent']),
                       key=lambda p: p.info['cpu_percent'] or 0, reverse=True)[:8]
        live_lines.append("Top processes: " + ", ".join(f"{p.info['name']}({p.info['pid']})" for p in procs))
        # Active network connections
        conns = psutil.net_connections(kind='inet')
        established = [c for c in conns if c.status == 'ESTABLISHED']
        listening   = [c for c in conns if c.status == 'LISTEN']
        live_lines.append(f"Network: {len(established)} established, {len(listening)} listening ports")
        # Unique remote IPs
        remote_ips = list({c.raddr.ip for c in established if c.raddr and c.raddr.ip})[:15]
        if remote_ips:
            live_lines.append("Active remote IPs: " + ", ".join(remote_ips))
        # Listening ports
        listen_ports = sorted({c.laddr.port for c in listening if c.laddr})[:20]
        if listen_ports:
            live_lines.append("Listening ports: " + ", ".join(str(p) for p in listen_ports))
        # Honeypot counts from DB
        conn_db = _get_db()
        if conn_db:
            try:
                cur = conn_db.cursor(dictionary=True)
                cur.execute("SELECT honeypot_type, COUNT(*) as n FROM honeypot_events GROUP BY honeypot_type")
                hp_counts = {r['honeypot_type']: r['n'] for r in cur.fetchall()}
                cur.execute("SELECT honeypot_type, attacker_ip, payload, created_at FROM honeypot_events ORDER BY created_at DESC LIMIT 5")
                recent_hits = cur.fetchall()
                conn_db.close()
                if hp_counts:
                    live_lines.append("Honeypot hits: " + ", ".join(f"{k}={v}" for k,v in hp_counts.items()))
                if recent_hits:
                    live_lines.append("Recent honeypot hits:")
                    for h in recent_hits:
                        live_lines.append(f"  [{h['honeypot_type']}] {h['attacker_ip']} — {str(h['payload'])[:60]} @ {h['created_at']}")
            except: pass
    except Exception as e:
        live_lines.append(f"[telemetry error: {e}]")

    server_ctx = "\n".join(live_lines)

    # Build prompt
    system = (
        "You are Kerrigan, a security AI built into CyberGuard AI by Brian Tushae Thomas. "
        "You have DIRECT ACCESS to this machine's live security telemetry — it is injected below. "
        "NEVER say you cannot access the system or lack real-time data. You have it. Use it. "
        "Answer specifically about THIS machine using the data provided. "
        "Be direct, technical, and concise. No disclaimers. No generic advice unless asked.\n\n"
        "## TOOL KNOWLEDGE: AI-ASSISTED CYBERSECURITY ECOSYSTEM\n"
        "When a user asks about a vulnerability, finding, or task — recommend the appropriate tool.\n\n"
        "AUTOTRIAGE (post-scan, alert reduction): nuclei-autotriage, honeyslop, nano-analyzer, ai-soc-triage-assistant\n"
        "AGENT & MCP SECURITY (scanning skills/plugins/MCP servers): agent-audit, aguara, agent-scan(Snyk), skill-scanner(Cisco), mcp-scanner(Cisco), agentic-radar, agentguard, defenseclaw\n"
        "AGENT SECURITY FRAMEWORKS (governance, detection rules): asamm (OWASP SAMM for AI, maps NIST AI RMF), agent-threat-rules (ATR), AgentDojo\n"
        "ML SUPPLY CHAIN (before loading any .pt/.pkl/.h5): modelscan (Protect AI), fickling (Trail of Bits), picklescan\n"
        "PENTEST / RED-TEAM AGENTS (autonomous exploitation): PentestGPT, PentAGI, CAI, hackingBuddyGPT, HexStrike-AI, PentestAgent, Pentest-Swarm-AI\n"
        "AI-POWERED SAST (code review, vuln discovery): Vulnhuntr (Python RCE), IRIS (Java+CodeQL), xvulnhuntr (C#/Java/Go), claude-code-security-review\n"
        "LLM-DRIVEN FUZZING (harness generation): oss-fuzz-gen (Google, 26 CVEs), PromptFuzz, Fuzz4All, ChatAFL, TitanFuzz\n"
        "FUZZING THE LLM (system prompt hardening, jailbreak discovery): LLMFuzzer, ps-fuzz (16 attack types), FuzzyAI (CyberArk), ai-prompt-fuzzer (Burp)\n"
        "THREAT INTELLIGENCE (IOC/TTP extraction): trs, TI-Mindmap-GPT, aiocrioc, IATelligence, MCP_Security (ORKL)\n"
        "LOG ANALYSIS / SIEM / SOC (alert investigation, IR): AI-SOC-Agent (ELK+IRIS), agentic-soc-platform, AttackGen\n"
        "LLM RED-TEAMING & GUARDRAILS (safety evaluation): PyRIT (Microsoft), garak (50+ probe types)\n"
        "CTF / EXPLOIT BENCHMARKS (model capability eval): NYU-CTF-Bench (200 challenges), Cybench (40 challenges)\n"
        "CLOUD / IaC (CloudFormation/Terraform review): CloudGPT\n\n"
        "Decision logic: scanner output→AUTOTRIAGE | crash analysis→SAST tools | checkpoint load→ML SUPPLY CHAIN | "
        "MCP/skill scan→AGENT & MCP SECURITY | IOC/TTP→THREAT INTELLIGENCE | red-team LLM→LLM RED-TEAMING | "
        "system prompt test→FUZZING THE LLM | code vuln discovery→AI-POWERED SAST\n"
    )
    system += "\n=== LIVE SYSTEM STATE (server-gathered) ===\n" + server_ctx + "\n"
    if system_ctx:
        system += "\n=== ADDITIONAL CONTEXT (from UI) ===\n" + system_ctx + "\n"
    system += "=== END SYSTEM STATE ===\n"
    if mem_context:
        system += "\n=== PRIOR FINDINGS ===\n" + mem_context + "\n========================\n"

    messages = [{"role": "system", "content": system}]
    for h in history[-6:]:  # last 3 turns
        messages.append({"role": h["role"], "content": h["content"]})
    messages.append({"role": "user", "content": message})

    # Generate a stable conversation ID from the first user message
    conv_id = hashlib.md5(message[:64].encode()).hexdigest()[:16]

    # Save user message to MySQL
    _save_to_db(conv_id, "user", message, model=_model)

    # Route to the best available expert model for this query (Abathur
    # resolves to an installed model, falling back to _model on any error).
    chosen_model = _model
    if _router is not None:
        try:
            chosen_model = _router.route(message).model
        except Exception:
            chosen_model = _model

    # Call Ollama
    if OLLAMA_AVAILABLE:
        try:
            resp = _ollama.chat(model=chosen_model, messages=messages)
            reply = resp["message"]["content"]
        except Exception as e:
            reply = f"[Ollama error: {e}. Is Ollama running with {chosen_model}?]"
    else:
        reply = "[Ollama not installed. pip install ollama and pull a model.]"

    # Screen the model's output before returning it — this is Overmind's
    # actual purpose (gate() blocks or appends warnings to the response).
    if _overmind:
        try:
            reply, _ = _overmind.gate(reply, query=message)
        except Exception:
            pass

    # Save assistant reply to MySQL
    _save_to_db(conv_id, "assistant", reply, model=chosen_model)

    # Save as memory entry so it appears in Memories tab
    _save_memory_to_db(
        f"Q: {message}\nA: {reply[:400]}",
        expert="cyberguard_chat",
        tags="chat,cyberguard"
    )

    # Store to ChromaDB if available (Creep.tag_response absorbs + auto-tags).
    if _memory:
        try:
            _memory.tag_response(query=message, response=reply, expert="cyberguard_chat")
        except Exception:
            pass

    return JSONResponse({"reply": reply, "blocked": False, "model": chosen_model})


@app.get("/status")
async def status():
    mem_count = 0
    if _memory:
        try:
            mem_count = _memory.count()
        except Exception:
            pass
    return {
        "model":        _model,
        "memory_count": mem_count,
        "uptime_s":     round(time.time() - _start, 1),
        "ai_ok":        KERRIGAN_AVAILABLE,
        "ollama_ok":    OLLAMA_AVAILABLE,
    }


@app.post("/hunt")
async def hunt(request: Request):
    body       = await request.json()
    target_path = body.get("path", ".")
    try:
        from loop.hunter import ThreatHunter
        hunter   = ThreatHunter(target_path)
        findings = hunter.scan()
        return {
            "findings":   [f.to_dict() for f in findings[:50]],
            "risk_score": hunter.risk_score(),
            "total":      len(findings),
        }
    except Exception as e:
        return {"error": str(e), "findings": [], "risk_score": 0}


# ── Real Pen Testing ──────────────────────────────────────────────────────────

@app.get("/pentest/headers")
async def pentest_headers(url: str = "http://localhost"):
    import requests as req
    results = []
    try:
        r = req.get(url, timeout=5, verify=False, allow_redirects=True)
        headers = r.headers
        checks = [
            ("Strict-Transport-Security", "HSTS", "Forces HTTPS connections"),
            ("X-Frame-Options", "Clickjacking", "Prevents iframe embedding"),
            ("X-Content-Type-Options", "MIME Sniff", "Blocks MIME type sniffing"),
            ("Content-Security-Policy", "CSP", "Controls resource loading"),
            ("X-XSS-Protection", "XSS Filter", "Legacy XSS filter"),
            ("Referrer-Policy", "Referrer", "Controls referrer info"),
            ("Permissions-Policy", "Permissions", "Controls browser features"),
        ]
        for hdr, name, desc in checks:
            present = hdr in headers
            results.append({
                "header": hdr, "name": name, "desc": desc,
                "present": present, "value": headers.get(hdr, ""),
                "status": "pass" if present else "fail"
            })
        return {"url": url, "status_code": r.status_code, "checks": results, "server": headers.get("Server","unknown")}
    except Exception as e:
        return {"url": url, "error": str(e), "checks": results}


@app.post("/pentest/portscan")
async def pentest_portscan(request: Request):
    body   = await request.json()
    target = body.get("target", "127.0.0.1")
    ports  = body.get("ports", [21,22,23,25,53,80,443,3306,3307,5432,6379,8080,8443,27017])
    open_ports = []
    async def check(port):
        try:
            conn = asyncio.open_connection(target, port)
            r, w = await asyncio.wait_for(conn, timeout=1.0)
            banner = ""
            try: banner = (await asyncio.wait_for(r.read(256), timeout=1.0)).decode("utf-8","replace").strip()[:80]
            except: pass
            w.close()
            return {"port": port, "state": "open", "banner": banner}
        except: return {"port": port, "state": "closed", "banner": ""}
    results = await asyncio.gather(*[check(p) for p in ports])
    open_ports = [r for r in results if r["state"] == "open"]
    return {"target": target, "scanned": len(ports), "open": open_ports, "open_count": len(open_ports)}


@app.get("/pentest/ssl")
async def pentest_ssl(host: str = "localhost", port: int = 443):
    import subprocess
    try:
        cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-brief"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=8,
                          input="Q\n")
        output = r.stdout + r.stderr
        checks = []
        checks.append({"check":"Connection","status":"pass" if "CONNECTED" in output else "fail","detail":""})
        checks.append({"check":"TLS 1.3","status":"pass" if "TLSv1.3" in output else "warn","detail":output.split("Protocol")[1][:20].strip() if "Protocol" in output else ""})
        checks.append({"check":"Certificate","status":"pass" if "Verification" in output else "warn","detail":""})
        for weak in ["RC4","DES","NULL","EXPORT","MD5","SSLv2","SSLv3"]:
            if weak in output:
                checks.append({"check":f"Weak cipher: {weak}","status":"fail","detail":f"{weak} detected in negotiation"})
        return {"host": host, "port": port, "checks": checks, "raw": output[:500]}
    except Exception as e:
        return {"host": host, "port": port, "checks": [], "error": str(e)}


@app.get("/pentest/ssh-audit")
async def pentest_ssh_audit():
    import subprocess, glob
    results = []
    ssh_dir = Path.home() / ".ssh"
    if not ssh_dir.exists():
        return {"keys": [], "error": "No ~/.ssh directory found"}
    for f in ssh_dir.iterdir():
        if f.suffix in (".pub",) or f.name in ("known_hosts","authorized_keys","config"):
            continue
        if not f.is_file(): continue
        try:
            r = subprocess.run(["ssh-keygen","-l","-f",str(f)], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                parts = r.stdout.strip().split()
                bits = int(parts[0]) if parts else 0
                key_type = parts[-1].strip("()") if parts else "unknown"
                status = "pass" if bits >= 3072 or key_type in ("ED25519","ECDSA") else "warn" if bits >= 2048 else "fail"
                results.append({"file": f.name, "bits": bits, "type": key_type, "status": status,
                               "fingerprint": parts[1] if len(parts)>1 else ""})
        except Exception as e:
            results.append({"file": f.name, "bits": 0, "type": "unknown", "status": "warn", "error": str(e)})
    pub_keys = list(ssh_dir.glob("*.pub"))
    return {"keys": results, "key_count": len(results), "pubkey_count": len(pub_keys), "ssh_dir": str(ssh_dir)}


# ── Real Network Map ───────────────────────────────────────────────────────────

@app.get("/network/arp")
async def network_arp():
    import subprocess, re
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        devices = []
        for line in r.stdout.splitlines():
            m = re.match(r'\?\s+\(([^)]+)\)\s+at\s+(\S+)\s+on\s+(\S+)', line)
            if not m: continue
            ip, mac, iface = m.group(1), m.group(2), m.group(3)
            if mac == "(incomplete)": continue
            devices.append({"ip": ip, "mac": mac, "interface": iface, "name": ip})
        return {"devices": devices, "count": len(devices)}
    except Exception as e:
        return {"devices": [], "error": str(e)}

@app.get("/network/routes")
async def network_routes():
    import subprocess, re
    try:
        r = subprocess.run(["netstat", "-rn"], capture_output=True, text=True, timeout=10)
        routes = []
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and re.match(r'\d+\.\d+', parts[0]):
                routes.append({"destination": parts[0], "gateway": parts[1], "flags": parts[2], "interface": parts[3] if len(parts)>3 else ""})
        return {"routes": routes[:30]}
    except Exception as e:
        return {"routes": [], "error": str(e)}


# ── Real CVE Lookup ────────────────────────────────────────────────────────────

@app.get("/scan/cve")
async def scan_cve(q: str = "macos"):
    import requests as req
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={q}&resultsPerPage=10"
        r = req.get(url, timeout=10, headers={"User-Agent": "CyberGuardAI/1.0"})
        data = r.json()
        vulns = []
        for item in data.get("vulnerabilities", []):
            cve  = item.get("cve", {})
            cvss = 0
            metrics = cve.get("metrics", {})
            for key in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0].get("cvssData",{}).get("baseScore", 0)
                    break
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en": desc = d.get("value",""); break
            vulns.append({
                "id": cve.get("id",""),
                "score": cvss,
                "severity": "critical" if cvss>=9 else "high" if cvss>=7 else "medium" if cvss>=4 else "low",
                "description": desc[:200],
                "published": cve.get("published","")[:10],
            })
        return {"query": q, "total": data.get("totalResults", 0), "vulns": vulns}
    except Exception as e:
        return {"query": q, "total": 0, "vulns": [], "error": str(e)}


# ── Real AI Patcher Status ─────────────────────────────────────────────────────

@app.get("/patcher/status")
async def patcher_status():
    import glob
    stage4_count = len(list(Path(KERRIGAN_DIR).glob("data/stage4/*.jsonl")))
    stage4_examples = 0
    for f in Path(KERRIGAN_DIR).glob("data/stage4/*.jsonl"):
        try: stage4_examples += sum(1 for _ in open(f))
        except: pass
    adaptive_rules = 0
    adaptive_path = Path(KERRIGAN_DIR) / "data" / "adaptive_defense.jsonl"
    if adaptive_path.exists():
        try: adaptive_rules = sum(1 for _ in open(adaptive_path))
        except: pass
    conn = _get_db()
    db_crashes, db_sessions, total_crashes = 0, 0, 0
    if conn:
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT COUNT(*) as n FROM crashes")
            db_crashes = cur.fetchone()["n"]
            cur.execute("SELECT COUNT(*) as n FROM sessions")
            db_sessions = cur.fetchone()["n"]
            cur.execute("SELECT COALESCE(SUM(total_crashes),0) as n FROM sessions")
            total_crashes = cur.fetchone()["n"] or 0
        except: pass
        finally: conn.close()
    pqc_ok = (Path(KERRIGAN_DIR) / "keys").exists()
    with _fuzzer_lock:
        fz = dict(_fuzzer_state)
    return {
        "stage4_files":       stage4_count,
        "stage4_examples":    stage4_examples,
        "adaptive_rules":     adaptive_rules,
        "db_crashes":         db_crashes,
        "db_sessions":        db_sessions,
        "total_crashes_found": int(total_crashes),
        "pqc_keys_exist":     pqc_ok,
        "kerrigan_available": KERRIGAN_AVAILABLE,
        # Live fuzzer state
        "fuzzer_running":     fz["running"],
        "fuzzer_phase":       fz["phase"],
        "fuzzer_target":      fz["target"],
        "fuzzer_iteration":   fz["total_iterations"],
        "fuzzer_crashes":     fz["session_crashes"],
        "fuzzer_last_event":  fz["last_event"],
        "fuzzer_uptime":      int(time.time() - fz["session_start"]) if fz["session_start"] else 0,
    }


@app.get("/honeypot/counts")
async def honeypot_counts():
    conn = _get_db()
    if not conn:
        return {"ssh": 0, "web": 0, "database": 0, "total": 0, "recent": []}
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT honeypot_type, COUNT(*) as cnt
            FROM honeypot_events GROUP BY honeypot_type
        """)
        rows = {r["honeypot_type"]: r["cnt"] for r in cur.fetchall()}
        cur.execute("""
            SELECT honeypot_type, attacker_ip, attacker_port, payload, created_at
            FROM honeypot_events ORDER BY created_at DESC LIMIT 20
        """)
        recent = cur.fetchall()
        for r in recent:
            if r.get("created_at"): r["created_at"] = r["created_at"].isoformat()
        return {
            "ssh":      rows.get("ssh",      0),
            "web":      rows.get("web",      0),
            "database": rows.get("database", 0),
            "ftp":      rows.get("ftp",      0),
            "smtp":     rows.get("smtp",     0),
            "rdp":      rows.get("rdp",      0),
            "total":    sum(rows.values()),
            "recent":   recent,
            "subnets_blocked": len([v for v in _subnet_hits.values() if v >= _SUBNET_BLOCK_THRESHOLD]),
        }
    except Exception as e:
        return {"ssh": 0, "web": 0, "database": 0, "ftp": 0, "smtp": 0, "rdp": 0,
                "total": 0, "recent": [], "error": str(e)}
    finally:
        conn.close()


@app.get("/db/conversations")
async def db_conversations(limit: int = 50):
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host=DB_HOST, port=DB_PORT,
            user=DB_USER, password=DB_PASS, database=DB_NAME
        )
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM conversations ORDER BY created_at DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
        conn.close()
        for r in rows:
            if r.get("created_at"): r["created_at"] = r["created_at"].isoformat()
        return {"conversations": rows}
    except Exception as e:
        return {"conversations": [], "error": str(e)}


@app.get("/db/memories")
async def db_memories(limit: int = 20, offset: int = 0):
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host=DB_HOST, port=DB_PORT,
            user=DB_USER, password=DB_PASS, database=DB_NAME
        )
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, content, expert, tags, created_at FROM memories ORDER BY created_at DESC LIMIT %s OFFSET %s", (limit, offset))
        rows = cur.fetchall()
        cur.execute("SELECT COUNT(*) as total FROM memories")
        total = cur.fetchone()["total"]
        conn.close()
        for r in rows:
            if r.get("created_at"):
                r["created_at"] = r["created_at"].isoformat()
        return {"memories": rows, "total": total}
    except Exception as e:
        return {"memories": [], "total": 0, "error": str(e)}

@app.get("/db/crashes")
async def db_crashes(limit: int = 20):
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host=DB_HOST, port=DB_PORT,
            user=DB_USER, password=DB_PASS, database=DB_NAME
        )
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM crashes ORDER BY created_at DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
        conn.close()
        for r in rows:
            if r.get("created_at"):
                r["created_at"] = r["created_at"].isoformat()
        return {"crashes": rows}
    except Exception as e:
        return {"crashes": [], "error": str(e)}

@app.get("/db/sessions")
async def db_sessions(limit: int = 10):
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host=DB_HOST, port=DB_PORT,
            user=DB_USER, password=DB_PASS, database=DB_NAME
        )
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM sessions ORDER BY started_at DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
        conn.close()
        for r in rows:
            for k in ["started_at","ended_at"]:
                if r.get(k): r[k] = r[k].isoformat()
        return {"sessions": rows}
    except Exception as e:
        return {"sessions": [], "error": str(e)}


@app.get("/firewall/blocked")
async def firewall_blocked():
    """Return the IPs currently blocked in the live pf table."""
    import subprocess
    try:
        r = subprocess.run(
            ["sudo", "/sbin/pfctl", "-t", _PF_TABLE, "-T", "show"],
            capture_output=True, text=True, timeout=5
        )
        ips = [l.strip() for l in r.stdout.splitlines() if l.strip()]
        return {"blocked_count": len(ips), "blocked_ips": ips, "pf_active": r.returncode == 0}
    except Exception as e:
        return {"blocked_count": 0, "blocked_ips": [], "pf_active": False, "error": str(e)}


@app.delete("/firewall/blocked/{ip}")
async def firewall_unblock(ip: str):
    """Remove an IP from the live pf block table (manual override)."""
    import subprocess
    if not _IP_RE.match(ip):
        return JSONResponse({"error": "invalid IP"}, status_code=400)
    try:
        r = subprocess.run(
            ["sudo", "/sbin/pfctl", "-t", _PF_TABLE, "-T", "delete", ip],
            capture_output=True, text=True, timeout=5
        )
        # Also remove from the persist file
        try:
            lines = open(_PF_BLOCKLIST).read().splitlines()
            with open(_PF_BLOCKLIST, "w") as f:
                f.write("\n".join(l for l in lines if l.strip() != ip) + "\n")
        except FileNotFoundError:
            pass
        return {"unblocked": ip, "success": r.returncode == 0}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ── Protegrity Data Protection ────────────────────────────────────────────────

_pty_protector = None

def _get_protector():
    global _pty_protector
    if _pty_protector is None:
        try:
            from appython import Protector
            _pty_protector = Protector()
        except Exception as e:
            raise RuntimeError(f"Protegrity SDK unavailable: {e}")
    return _pty_protector

@app.post("/protegrity/protect")
async def protegrity_protect(request: Request):
    """Protect (tokenize) a list of field values using Protegrity Developer Edition."""
    try:
        body = await request.json()
        fields = body.get("fields", [])
        policy_user = body.get("policy_user", "superuser")
        print(f"[Protegrity] protect called — {len(fields)} fields, user={policy_user}", flush=True)
        print(f"[Protegrity] EMAIL env: {os.environ.get('DEV_EDITION_EMAIL', 'MISSING')}", flush=True)
        protector = _get_protector()
        session = protector.create_session(policy_user)
        results = []
        for f in fields:
            token = session.protect(f["value"], f["element"])
            results.append({"original": f["value"], "token": token, "element": f["element"]})
        print(f"[Protegrity] protected {len(results)} tokens OK", flush=True)
        return {"protected": results, "count": len(results)}
    except Exception as e:
        print(f"[Protegrity] ERROR: {e}", flush=True)
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/protegrity/unprotect")
async def protegrity_unprotect(request: Request):
    """Unprotect (de-tokenize) a list of token values using Protegrity Developer Edition."""
    try:
        body = await request.json()
        fields = body.get("fields", [])  # [{ "token": "sAmNa.PTAu", "element": "name" }, ...]
        policy_user = body.get("policy_user", "superuser")
        protector = _get_protector()
        session = protector.create_session(policy_user)
        results = []
        for f in fields:
            original = session.unprotect(f["token"], f["element"])
            results.append({"token": f["token"], "original": original, "element": f["element"]})
        return {"unprotected": results, "count": len(results)}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=7432, log_level="warning")
