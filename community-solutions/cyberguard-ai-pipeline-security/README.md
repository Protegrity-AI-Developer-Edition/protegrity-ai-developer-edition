# CyberGuard AI — Protegrity AI Pipeline Security Demo

![Static Badge](https://img.shields.io/badge/With_Protegrity-009245?style=flat&label=Built&labelColor=3a3a3e&link=%3Cobject%3Eprotegrity.com)
![Python](https://img.shields.io/badge/Python-3.11+-009245?style=flat&labelColor=3a3a3e&logo=python&logoColor=white)
![Electron](https://img.shields.io/badge/Electron-macOS-009245?style=flat&labelColor=3a3a3e)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat)](https://github.com/Protegrity-AI-Developer-Edition/protegrity-ai-developer-edition/blob/main/LICENSE)

> **Creator:** Brian Tushae Thomas · Anthos Intelligence  
> **GitHub:** [TushaeBXN](https://github.com/TushaeBXN) · **HuggingFace:** [machomenc](https://huggingface.co/machomenc)  
> **Demo Video:** [https://youtu.be/PeHmVaYvhjM](https://youtu.be/PeHmVaYvhjM)  
> **Full Repo:** [https://github.com/TushaeBXN/cyberguard](https://github.com/TushaeBXN/cyberguard)

---

## What This Builds

CyberGuard AI is a macOS security console (Electron) that demonstrates a **protect-before-ingest AI pipeline** — sensitive endpoint telemetry is tokenized by Protegrity Developer Edition before it ever reaches the LLM. The model operates entirely on cryptographic tokens. Real values are restored only at the authenticated analyst display layer.

The core problem: most AI security tools expose the very data they're supposed to protect. Every IP address, username, and device ID flows into the model's context window in plain text. CyberGuard AI closes that gap.

---

## Pipeline Architecture

```
Raw Telemetry → [Protegrity Tokenize] → [Kerrigan-Fantasma LLM] → [Output Guardrail] → [Protegrity De-tokenize] → Analyst
```

| Stage | What Happens | Protegrity Role |
|-------|-------------|-----------------|
| 1 — Ingest & Classify | Raw endpoint telemetry ingested, PII fields identified | — |
| 2 — Tokenize | Format-preserving encryption applied to IPs, usernames, device IDs | `session.protect()` |
| 3 — Model Inference | Kerrigan-Fantasma LLM generates NIST-mapped incident report on tokens only | — |
| 4 — Output Guardrail | Scans model output for raw PII patterns before analyst display | — |
| 5 — De-tokenize | Real values restored at display layer for authenticated analyst | `session.unprotect()` |

---

## NIST Compliance Mapping

| Control | Framework | How This Pipeline Satisfies It |
|---------|-----------|-------------------------------|
| SC-28 | NIST 800-53 | Protegrity FPE applied before model ingestion — context window never holds raw PII |
| SC-8 | NIST 800-53 | PII stripped before any inter-process data transfer |
| AC-3 | NIST 800-53 | De-tokenization enforced at display layer only |
| PR.DS-1 | NIST CSF 2.0 | Data-at-rest protection applied to AI context window |
| PR.DS-5 | NIST CSF 2.0 | Output guardrail prevents data leakage from model layer |
| MAP 1.6 | NIST AI RMF 1.0 | Risk-first architecture — protect-before-ingest by design |
| §6.1 | ISO/IEC 42001 | Architectural risk treatment eliminates re-identification class at design time |

---

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/TushaeBXN/cyberguard.git
cd cyberguard

# 2. Install dependencies
npm install

# 3. Set Protegrity Developer Edition credentials
export DEV_EDITION_EMAIL='your@email.com'
export DEV_EDITION_PASSWORD='your-password'
export DEV_EDITION_API_KEY='your-api-key'

# 4. Launch
npm start
```

Click **Protegrity Demo** in the left sidebar. Go to tab **③ Live Pipeline** and click **▶ Run Full Pipeline**.

---

## Prerequisites

- Node.js 18+ and npm
- Python 3.11+
- Protegrity Developer Edition credentials (`pip install protegrity-ai-developer-python`)
- Ollama (optional — for live LLM inference; falls back to stub if offline)

---

## Key Files

| File | Purpose |
|------|---------|
| `src/index.html` | Full UI — search `ProtegityDemoView` for the demo module |
| `src/kerrigan_server.py` | FastAPI server — `/protegrity/protect` and `/protegrity/unprotect` endpoints |
| `src/main.js` | Electron IPC — `protegrity-protect`, `protegrity-unprotect`, `demo-llm-infer` handlers |
| `src/data/demo-telemetry.json` | Synthetic endpoint telemetry (6 records, 6 attack types) |
| `DEMO.md` | Full recording script with segment-by-segment talk track |

---

## Protegrity Integration

Real tokenization is handled by the `appython` SDK in `kerrigan_server.py`:

```python
from appython import Protector

protector = Protector()
session = protector.create_session('superuser')

# Stage 2 — Tokenize before LLM ingestion
token = session.protect('sarah.chen', 'name')     # → sAmNa.PTAu
token = session.protect('10.0.1.47', 'string')    # → BI.o.f.TD

# Stage 5 — De-tokenize at display layer only
original = session.unprotect('sAmNa.PTAu', 'name')  # → sarah.chen
```

The Electron renderer never handles credentials — all Protegrity calls route through the main process IPC bridge.

---

## Demo Video

[https://youtu.be/PeHmVaYvhjM](https://youtu.be/PeHmVaYvhjM) — 13-minute walkthrough covering all 7 segments: Problem Framing, Architecture, Live Pipeline, NIST Mapping, Code Walkthrough, Use Cases, and Wrap-Up.

---

*Built for the Protegrity AI Pipeline Security Hackathon 2026 · Brian Tushae Thomas · Anthos Intelligence*
