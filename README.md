<div align="center">
  <img src="icons/icon128.png" alt="Revelio Logo" width="128" />
  <h1>🛡️ Revelio: Advanced Threat Intelligence</h1>
  <p><strong>Next-Generation, AI-Powered Email Security & Phishing Analysis for SOC Teams</strong></p>

  [![Version](https://img.shields.io/badge/Version-1.1.0-blue.svg)](https://github.com/DiptanshuDhawan/Revelio)
  [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
  [![AI Processing](https://img.shields.io/badge/AI%20Engine-Local%20%7C%20Cloud-purple.svg)](#)
  [![Platform](https://img.shields.io/badge/Platform-Chrome%20V3-orange.svg)](#)

</div>

---

## 🚀 The Problem We Solved
Modern phishing and Business Email Compromise (BEC) attacks have evolved beyond simple keyword triggers and malicious attachments. Threat actors now use AI-generated social engineering, zero-day lookalike domains, and hyper-targeted impersonation tactics that easily bypass traditional Secure Email Gateways (SEGs). 

**Revelio** was engineered from the ground up to solve this. It is a highly sophisticated, multi-layered threat analysis engine packaged seamlessly as a Chrome Extension. By combining blazing-fast deterministic rule sets with Deep Learning Large Language Models (LLMs), Revelio achieves SOC-level threat intelligence directly within your browser.

---

## 🧠 The Dual-Engine Architecture
Building an accurate threat analyzer is incredibly difficult due to the nuance in human communication. Revelio solves this using a **Hybrid Dual-Engine** approach:

### 1. Deterministic Heuristics Engine (The Shield)
Before AI even touches the payload, Revelio runs a barrage of 12 distinct deterministic security checks. These rules analyze the structural integrity of the email:
*   **Header Authentication Analysis:** Instant verification of SPF, DKIM, and DMARC alignment.
*   **Domain & URL Deobfuscation:** Extracts embedded links, resolves lookalikes (e.g., `paypal-secure-update.com`), detects suspicious TLDs, and spots HTML obfuscation tricks.
*   **Brand & Display Name Impersonation:** Detects when a display name (e.g., "CEO John Doe") contradicts the actual SMTP envelope sender.
*   **Payload Detection:** Scans for dangerous file extensions and credential-harvesting mechanisms.

### 2. Deep-Context AI Engine (The Brain)
To detect BEC, financial fraud, and AI-generated social engineering, Revelio injects the email into an advanced LLM framework. We designed custom prompt chains that force the AI to act as a senior threat analyst:
*   **Contextual Social Engineering:** Understands fabricated urgency, authority manipulation, and artificial deadlines.
*   **Financial Fraud Triggers:** Identifies subtle invoice fraud, payroll diversion, and wire transfer requests.
*   **Tone & Syntax Analysis:** Flags unnatural, AI-generated text or unusual deviations in corporate communication styles.

### ⚖️ The Weighted Scoring Algorithm
The magic is in how these engines combine. Revelio uses a proprietary algorithm `Final Score = (LLM Score × 0.6) + (Rule Score × 0.4)` to calculate a definitive threat score from `0` to `100`. This heavily reduces false positives while ensuring zero-day threats are caught by the LLM even if they bypass the hardcoded rules.

---

## 📊 Enterprise-Grade Threat Reports
Revelio generates comprehensive, beautifully designed threat reports in milliseconds.
*   **Threat Fingerprint Radar:** Visualizes the threat vector across 5 axes (Impersonation, Urgency, Social Engineering, Tech Deception, and AI-generation).
*   **MITRE ATT&CK Mapping:** Automatically maps detected threats to specific MITRE TTPs (e.g., `T1566.002 Spearphishing Link`).
*   **Persistent Scan History:** Saves all analysis locally for historical auditing and review.
*   **Exportable PDF Reports:** Generates professional, printable reports for compliance and incident response documentation.

---

## 🔒 Privacy-First AI (Zero-Trust Ready)
We understand that email data is highly sensitive. Revelio supports a **100% Local AI Deployment**.
By connecting Revelio to **Ollama**, you can run massive open-weights models (like `deepseek-r1:8b` or `Llama 3`) entirely on your local hardware. 
**Zero data leaves your machine. No telemetry. No API logging.**

*(Cloud API fallback options via OpenAI and Google Gemini are also supported for lower-spec machines).*

---

## 🛠️ Installation & Setup

### 1. Install the Extension
1. Clone or download this repository.
2. Open Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer Mode** (top right).
4. Click **Load unpacked** and select the `/phishguard-ai` directory.

### 2. Configure Local AI (Recommended)
1. Install [Ollama](https://ollama.ai).
2. Pull a high-performance reasoning model:
   ```bash
   ollama pull deepseek-r1:8b
   ```
3. Start the Ollama server with CORS enabled so the extension can communicate with it:
   *   **macOS / Linux:** `OLLAMA_ORIGINS=chrome-extension://* ollama serve`
   *   **Windows (PowerShell):** `$env:OLLAMA_ORIGINS = "chrome-extension://*"; ollama serve`

### 3. Usage
1. Click the Revelio shield icon in your Chrome toolbar.
2. Paste the raw email (Headers + Body) or upload an `.eml` file.
3. Click **Analyze** and receive your SOC-grade threat report in seconds.
4. Review your previous scans using the **History** button.

---

## 🤝 For Security Researchers & Contributors
Revelio was designed to be extensible. If you want to contribute to the engine:
*   Add new deterministic triggers in `engine/ruleEngine.js`.
*   Tweak the LLM System Prompts in `engine/prompts.js` to catch new BEC variants.
*   Add support for new LLM inference providers in `background.js`.

**License:** MIT License — Free for both personal and commercial SOC deployments.
