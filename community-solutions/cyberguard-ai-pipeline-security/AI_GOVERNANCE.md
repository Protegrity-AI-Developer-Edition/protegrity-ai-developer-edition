# AI System Risk Assessment & Governance Card

**System:** CyberGuard (AI-Powered Endpoint Security & Compliance Monitor)  
**Mapped to:** NIST AI RMF 1.0 and ISO/IEC 42001:2023  
**Classification:** Internal

---

## 1. System Overview

| Field | Value |
|---|---|
| **System Name** | CyberGuard |
| **System Type** | AI-powered endpoint security monitor and compliance-scoring platform (macOS/Windows) |
| **Intended Use** | Real-time endpoint threat monitoring, simulated threat detection, and automated compliance scoring against ISO 27001, NIST CSF, CIS Controls, PCI-DSS, CMMC, GDPR, and HIPAA |
| **Primary Users** | Home users (individual/family endpoint protection) and small-to-mid enterprise security teams (Enterprise mode) |
| **Deployment Status** | Standalone desktop application (Electron); local installation, not currently distributed at scale |
| **Risk Tier** | Tier 3 (High) — processes local system/security data and produces compliance conclusions that may inform real security decisions |
| **System Owner** | Tushae Thomas |
| **Document Version** | 1.0 — initial governance card |

---

## 2. Purpose of This Document

CyberGuard produces two categories of AI-influenced output that carry real-world consequence if wrong:

1. **Threat detection and alerting** — a false negative leaves a user exposed
2. **Automated compliance scoring** against recognized frameworks — a misleading score could give an organization false confidence in its audit readiness

This card documents the risk assessment, disclosure controls, and data-handling boundaries that govern the tool, consistent with the organization's AI Governance Policy and the NIST AI RMF.

---

## 3. NIST AI RMF Function Mapping

| NIST AI RMF Function | Objective | Application to CyberGuard |
|---|---|---|
| **GOVERN** | Establish accountability for what the tool claims and how confidently. | System owner is accountable for compliance-scoring accuracy claims and for correcting the record if a framework mapping is later found incorrect or outdated (Section 6). |
| **MAP** | Identify the context of use and who relies on the output. | Two distinct user contexts (Home, Enterprise) carry different stakes: an Enterprise user may treat a compliance score as audit-relevant, which raises the bar on accuracy and disclosure, versus a Home user checking general security hygiene. |
| **MEASURE** | Assess the risk of incorrect output and of local data handling. | Risk assessed across false-negative threat detection, compliance-score misrepresentation, and local data exposure (Section 4). |
| **MANAGE** | Apply proportionate controls: disclosure, scope limits, data minimization. | Compliance scores carry an explicit non-certification disclaimer; local-only data processing by default; simulated threat detection is clearly labeled as simulation (Section 5). |

---

## 4. Risk Assessment

Risk is scored using Likelihood (1–5) × Impact (1–5).

| Risk Category | Description | Likelihood × Impact | Risk Level |
|---|---|---|---|
| **Compliance score misrepresentation** | A user or their organization treats an automated compliance score as equivalent to a formal audit or certification (e.g., ISO 27001, HIPAA) when it is not. | 4 × 4 = 16 | **High** |
| **False negative in threat detection** | The monitor fails to flag a real threat, giving the user false confidence in their security posture. | 3 × 5 = 15 | **High** |
| **Local data over-collection** | The endpoint agent collects more system/security telemetry than necessary for its stated function. | 2 × 4 = 8 | Medium |
| **Data exfiltration / local storage exposure** | Locally stored scan results or logs are not adequately protected on the endpoint itself. | 2 × 4 = 8 | Medium |
| **Simulated threat confused with real threat** | Threat-simulation features are mistaken by the user for an actual active compromise, causing unnecessary panic or a wrong response. | 2 × 3 = 6 | Low-Medium |
| **Framework mapping drift** | Underlying compliance frameworks (e.g., CMMC, NIST CSF) are updated by their governing bodies, but the tool's control mappings are not kept current. | 3 × 3 = 9 | Medium |

---

## 5. Controls & Disclosures

### 5.1 Compliance Scoring Integrity

- Every compliance score is displayed with a clear, persistent disclaimer that it is a **self-assessment aid** and is not a substitute for a formal third-party audit or certification.
- Control-to-framework mappings (ISO 27001, NIST CSF, CIS Controls, PCI-DSS, CMMC, GDPR, HIPAA) are **version-dated** so users can see when the mapping was last verified against the source framework.
- Enterprise-mode scoring includes a **confidence indicator** distinguishing controls verified by direct system scan from controls inferred or self-attested by the user.

### 5.2 Threat Detection & Simulation

- Simulated threat scenarios are **visually and textually distinguished** from live detection alerts at all times — no shared UI treatment between simulated and real findings.
- Detection logic and confidence thresholds are documented internally so that false-negative-prone categories are known and disclosed rather than silently assumed to be covered.

### 5.3 Data Handling

- Telemetry and scan data are **processed and stored locally** on the endpoint by default; no cloud transmission of raw system data without explicit user opt-in.
- Data collection is scoped to what is required for threat detection and compliance scoring — no collection of unrelated personal files or browsing data.
- Local scan results and logs are stored with file-system permissions restricting access to the authenticated user account.

---

## 6. Human Oversight & Correction Process

If a compliance framework mapping is found to be outdated or a detection rule produces a materially misleading result, the system owner documents the issue, corrects the mapping or rule, and version-dates the fix.

Enterprise users relying on CyberGuard output for audit preparation are advised to validate high-stakes findings against the current published framework text or a qualified assessor.

---

## 7. Review Cadence

- **Compliance framework mappings** — reviewed at a minimum annually, or immediately upon a known revision to a covered framework (e.g., a NIST CSF or CMMC version update).
- **Detection logic and risk classification** — reviewed quarterly, consistent with the Tier 3 cadence defined in the organization's AI Governance Policy.

---

## 8. Relationship to Broader Portfolio Governance

This document is a system-specific supplement to the organization-level **AI Governance Policy** and **AI System Inventory & Risk Register**. CyberGuard should be logged as a Tier 3 entry in that inventory, with this card attached as its supporting risk assessment and control documentation.

---

*Document Version 1.0 — initial governance card*  
*System Owner: Tushae Thomas*  
*Frameworks: NIST AI RMF 1.0 · ISO/IEC 42001:2023*
