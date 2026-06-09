<div align="center">
  <img src="icons/Revelio%20logo.png" alt="Revelio Logo" width="128" />
  <h1>Revelio</h1>
  <p><strong>Advanced Threat Intelligence & Phishing Analysis</strong></p>
</div>

---

**Revelio** is a next-generation Chrome Extension built for SOC teams. It catches zero-day social engineering and targeted BEC (Business Email Compromise) attacks that bypass traditional Secure Email Gateways. 

By combining lightning-fast deterministic heuristics with deep-context Large Language Models, Revelio provides enterprise-grade threat analysis directly within your browser.

## Core Capabilities

* **Dual-Engine Architecture:** Runs 12 strict deterministic checks (Header Auth, URL Lookalikes, Payload Scans) combined with a contextual AI engine (evaluating urgency, authority manipulation, and tone).
* **Zero-Trust Privacy:** Supports 100% offline analysis via **Ollama**. No sensitive email data ever leaves your machine. (Cloud fallback via OpenAI/Gemini is also supported).
* **SOC-Ready Reports:** Generates printable, MITRE-mapped threat intelligence reports with a multi-axis Threat Fingerprint Radar.
* **Instant Forensics:** Automatically unmasks URL shorteners, verifies DKIM/DMARC alignment, and flags display name impersonation.

## Quick Start

1. **Install:** Clone this repo, open `chrome://extensions/`, enable Developer Mode, and "Load unpacked" the `/phishguard-ai` folder.
2. **Setup AI (Optional but Recommended):** 
   * Install [Ollama](https://ollama.ai) and pull a model: `ollama pull deepseek-r1:8b`
   * Start the server: `OLLAMA_ORIGINS=chrome-extension://* ollama serve`
3. **Analyze:** Click the Revelio icon in your toolbar, paste any raw email (headers + body), and instantly receive your threat report.

---
*Built for security professionals who demand accuracy without sacrificing privacy. MIT Licensed.*
