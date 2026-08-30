<div align="center">
  <img src="icons/Revelio%20logo.png" alt="Revelio Logo" width="128" />
  <h1>Revelio</h1>
  <p><strong>Advanced Threat Intelligence & Phishing Analysis</strong></p>
  <p>
    <a href="https://github.com/DiptanshuDhawan/Revelio/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
    <img src="https://img.shields.io/badge/Version-1.0.0-green.svg" alt="Version">
  </p>
</div>

---

**Revelio** is a next-generation Chrome Extension built for SOC teams. It catches zero-day social engineering and targeted BEC (Business Email Compromise) attacks that bypass traditional Secure Email Gateways. 

By combining lightning-fast deterministic heuristics with deep-context Large Language Models, Revelio provides enterprise-grade threat analysis directly within your browser for Gmail and Outlook.

## Core Capabilities

* **Dual-Engine Architecture:** Runs 12 strict deterministic checks (Header Auth, URL Lookalikes, Payload Scans) combined with a contextual AI engine (evaluating urgency, authority manipulation, and tone).
* **Zero-Trust Privacy:** Supports 100% offline analysis via **Ollama**. No sensitive email data ever leaves your machine. (Cloud APIs like OpenAI, Gemini, and OpenRouter are also supported).
* **SOC-Ready Reports:** Generates printable, MITRE-mapped threat intelligence reports with a multi-axis Threat Fingerprint Radar.
* **Instant Forensics:** Automatically unmasks URL shorteners, verifies DKIM/DMARC alignment, and flags display name impersonation.
* **Passive Auto-Scan:** Scans emails in the background the moment you open them.

## Architecture

Revelio uses a Manifest V3 Service Worker (`background.js`) as a central hub to avoid CORS issues and orchestrate analysis safely.

* **`content.js`** extracts email DOM from Gmail/Outlook and signals the background worker.
* **`engine/analyzer.js`** coordinates the `ruleEngine.js` (12 deterministic checks) and `prompts.js` (LLM instructions), calculating the blended score.
* **`utils/urlScanner.js` & `urlSafety.js`** perform deep URL heuristics, Google Safe Browsing, and VirusTotal lookups.
* **`popup.js`** acts as the frontend controller, visualizing the results via Chart.js.

## Quick Start

1. **Install:** Clone this repo, open `chrome://extensions/`, enable **Developer mode** (top right), and click **Load unpacked**. Select the `Revelio` folder (not `phishguard-ai`).
2. **Setup AI (Optional but Recommended):** 
   * Install [Ollama](https://ollama.com) and pull a model: `ollama pull llama3.1` (or your preferred model).
   * Start the server with CORS enabled: `OLLAMA_ORIGINS="chrome-extension://*" ollama serve`
3. **Analyze:** Open an email in Gmail or Outlook and click the Revelio extension icon.

## Development & Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on setting up the dev environment, building Tailwind CSS (`npm run build:css`), and our coding standards.

---
*Built for security professionals who demand accuracy without sacrificing privacy. MIT Licensed.*
