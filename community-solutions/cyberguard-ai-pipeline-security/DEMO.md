# CyberGuard AI — Protegrity Hackathon Demo Script

**Hackathon:** Protegrity AI Pipeline Security Hackathon 2026  
**Deadline:** August 3, 2026  
**Creator:** Brian Tushae Thomas | Anthos Intelligence  
**GitHub:** github.com/TushaeBXN · github.com/TushaeThomas  
**HuggingFace:** hf.co/machomenc

---

## Before You Hit Record — Checklist

- [ ] `npm start` is running and terminal shows "model warm"
- [ ] App window is maximized
- [ ] Notifications silenced (System Settings → Focus → Do Not Disturb)
- [ ] Browser tabs closed
- [ ] This file open in a separate window as your talk track reference

---

## ① Problem Framing [0:00–1:30]

Click **Protegrity Demo** in the sidebar. You land on tab ① automatically. Talk through the three risk cards, scroll down to show the solution panel.

**Say:**

"Most AI security tools have a blind spot — they process the very data they're supposed to protect. Every IP address, every username, every device ID gets fed into the model's context window in plain text. That's a second attack surface hiding inside your security stack.

NIST 800-53 SC-28 requires protection of data at rest. A model's context window is data at rest — and most tools ignore that completely.

What we built is a pipeline that protects sensitive fields before they ever reach the AI — and only restores them at the analyst display layer. The model never sees real data. Ever."

---

## ② Architecture [1:30–3:30]

Click **② Architecture**. Walk through the 5 pipeline stages left to right, then scroll down and walk the "What Each Stage Sees" table.

**Say:**

"Here's how the pipeline works. Five stages.

Stage one — we ingest raw endpoint telemetry and classify which fields are sensitive.

Stage two — Protegrity Developer Edition applies format-preserving encryption. IP addresses still look like IP addresses. Usernames become tokens. Device IDs become tokens. But none of it is real anymore.

Stage three — Kerrigan-Fantasma, our custom security LLM, runs inference on the tokenized data. It never sees a real IP, a real name, or a real device ID.

Stage four — the output guardrail scans the model's response for any re-identification patterns before it leaves the AI layer.

Stage five — Protegrity de-tokenizes at the display layer only. The analyst sees real values. The model never did.

Scroll down — this table shows exactly what each stage sees. Red is raw PII. The yellow row is what the AI sees — tokens only. Green is the analyst view after de-tokenization."

---

## ③ Live Pipeline [3:30–7:00]

Click **③ Live Pipeline**. Point at the left table, then click ▶ Run Full Pipeline.

**Say:**

"Let's run it live. On the left — six real-looking endpoint telemetry records. C2 beacon, data exfiltration, lateral movement, DNS tunneling, persistence install, credential harvesting. Red means raw PII — IPs, usernames, device IDs. This is what a naive pipeline hands to the model.

I'm going to click Run Full Pipeline now."

*(click the button)*

"Stage one — ingested. Six records classified, four PII field types identified per record.

Stage two — look at the right panel. Protegrity just ran. `sarah.chen` is now `sAmNa.PTAu`. `10.0.1.47` is now `BI.o.f.TD`. `LAPTOP-SC7291` is now `Dr7q4x-DtGz4g`. That's real Protegrity Developer Edition format-preserving encryption — not mock data. The model's going to get coherent-looking data, just none of it is real.

Stage three — Kerrigan-Fantasma is running inference on the tokenized context right now. It's generating a NIST-mapped incident report referencing only those tokens.

Stage four — guardrail scan. Passed. Zero raw PII patterns in the model output. It stayed in its lane.

Stage five — de-tokenization. Protegrity restores the real values at the display layer."

*(scroll down to the green report)*

"This is what the analyst sees — real IPs, real names, real device IDs, mapped to NIST controls. The model generated this report without ever knowing who these people are or what these machines are called."

---

## ④ NIST Mapping [7:00–10:00]

Click **④ NIST Mapping**. Walk through each row — all show ✓ Met.

**Say:**

"Every stage maps to specific controls. SC-28 — protection of data at rest — satisfied by Protegrity tokenization before the model ever touches the data. SC-8 — transmission confidentiality — PII is stripped before any inter-process communication. AC-3 — access enforcement — de-tokenization is gated to the display layer only.

On the CSF 2.0 side, PR.DS-1 and PR.DS-5 are both met — data at rest is protected and the output guardrail prevents leakage.

NIST AI RMF MAP 1.6 — our architecture reflects organizational risk priorities. We didn't bolt on controls after the fact. We built the risk treatment into the design.

And ISO 42001 section 6.1 — actions to address AI risks. Tokenization eliminates an entire class of re-identification risk at the architectural level, not through policy."

---

## ⑤ Code Walkthrough [10:00–12:00]

Click **⑤ Code Walkthrough** in the app. Walk through the sub-tabs.

**Say:**

"Quick look at the implementation.

In `kerrigan_server.py`, the `/protegrity/protect` endpoint takes each field with its data element type and calls `session.protect()` from the Protegrity Developer Edition SDK. Every field gets a cryptographic token back. The vault maps token to original so Stage 5 can reverse it.

In `main.js`, the `protegrity-protect` IPC handler routes the call from the renderer to the Python server. The renderer never touches raw credentials — everything goes through the main process.

The output guardrail scans the model's response for raw RFC-1918 addresses, real usernames, real device IDs — anything that suggests re-identification happened.

The `demo-llm-infer` handler calls Kerrigan through the existing bridge. If Kerrigan is offline it falls back to a pre-written stub that demonstrates the same flow. No broken states."

---

## ⑥ Use Cases [12:00–13:30]

Switch back to the app, click **⑥ Use Cases & Roadmap**. Walk the four sector cards, then scroll to the roadmap.

**Say:**

"The protect-before-ingest pattern isn't specific to endpoint security. Anywhere AI processes regulated data, the same pipeline applies.

Healthcare — de-identified patient telemetry fed to diagnostic AI, PHI never enters the model context. HIPAA 164.312, HITRUST CSF.

Financial services — tokenized transaction records analyzed by fraud AI. Card numbers and account IDs never touch the LLM. PCI DSS v4.

Legal — attorney-client privileged documents analyzed with all PII tokenized. Output de-tokenized only for counsel. GDPR Article 25, privacy by design.

Government and DoD — CUI and ITAR-controlled telemetry analyzed without exposing controlled data to model weights. CMMC 2.0, FedRAMP SC-28.

Same pipeline, different field classification at stage one."

---

## ⑦ Wrap-Up [13:30–end]

Scroll down on tab ⑥ to the Anthos Intelligence branding card.

**Say:**

"CyberGuard AI is open-source security infrastructure built on Kerrigan-Fantasma — a custom recurrent-depth transformer fine-tuned on security corpora — with Protegrity Developer Edition as the data protection layer.

Phase two adds Protegrity Enterprise API with full DPM policy enforcement and role-based de-tokenization. Phase three adds multi-cloud support and a fine-tuned Kerrigan model trained on tokenized incident data.

I'm Brian Thomas, founder of Anthos Intelligence. GitHub is TushaeBXN, HuggingFace is machomenc. Thank you."

---

**Stop Recording** — Cmd+Ctrl+Esc, then File → Export As → 1080p
