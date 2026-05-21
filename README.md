# 🛡️ Revelio — Email Threat Analyzer

> **AI-powered phishing email analysis for security professionals and enterprise SOC teams.**

Revelio is a Chrome Extension (Manifest V3) that lets you paste or upload any email, runs it through a multi-layer rule engine + LLM analysis, and delivers a professional threat intelligence report — all within your browser.

---

## 📋 Table of Contents
1. [Prerequisites](#prerequisites)
2. [Ollama Setup (Local Mode)](#ollama-setup)
3. [Extension Installation](#extension-installation)
4. [How to Use](#how-to-use)
5. [AI Provider Configuration](#ai-provider-configuration)
6. [Troubleshooting](#troubleshooting)
7. [Privacy & Security](#privacy--security)
8. [Architecture Overview](#architecture-overview)
9. [MITRE ATT&CK Reference](#mitre-attck-reference)

---

## Prerequisites

- **Chrome 120+** (or any Chromium-based browser supporting Manifest V3)
- **For local AI**: [Ollama](https://ollama.ai) installed (free, runs on your machine)
- **For cloud AI**: API key for OpenAI, Google Gemini, or xAI Grok

---

## Ollama Setup

Ollama enables 100% local AI analysis — no data ever leaves your machine.

### 1. Install Ollama

```bash
# macOS / Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Windows
# Download installer from: https://ollama.ai/download/windows
```

### 2. Pull a Model

Recommended models for phishing analysis:

```bash
# Best balance of accuracy and speed (recommended)
ollama pull deepseek-r1:8b

# Fast and efficient
ollama pull phi3

# Alternative with strong reasoning
ollama pull mistral

# Largest, most accurate (requires 8GB+ RAM)
ollama pull gemma2
```

### 3. Start Ollama Server

```bash
ollama serve
```

Ollama will run at `http://localhost:11434` by default.

### 4. Fix CORS for Chrome Extension

Chrome extensions require Ollama to accept cross-origin requests. Set the following environment variable before starting Ollama:

```bash
# macOS / Linux
OLLAMA_ORIGINS=chrome-extension://* ollama serve

# Windows (PowerShell)
$env:OLLAMA_ORIGINS = "chrome-extension://*"
ollama serve

# Windows (Command Prompt)
set OLLAMA_ORIGINS=chrome-extension://*
ollama serve
```

> **Tip**: Add this to a startup script or service configuration so it persists across reboots.

---

## Extension Installation

1. **Download/Clone** this repository to your local machine
2. Open **Chrome** and navigate to `chrome://extensions/`
3. Enable **Developer Mode** (toggle in the top-right corner)
4. Click **"Load unpacked"**
5. Select the `/phishguard-ai` folder (the one containing `manifest.json`)
6. The PhishGuard AI shield icon will appear in your Chrome toolbar

> If the icon isn't visible, click the puzzle-piece Extensions menu and pin PhishGuard AI.

---

## How to Use

### Analyzing an Email

1. **Click the PhishGuard AI icon** in your Chrome toolbar
2. **Paste the email content** into the text area (headers + body recommended)
   - Or click **Upload** to load a `.eml` or `.txt` file
   - Or click **Load Sample** to use one of 5 built-in demo emails
3. **Select your AI provider** (Ollama tab is active by default)
4. Click **"Analyze with AI"** (or press `Ctrl+Enter`)
5. Wait for the analysis (typically 3–10 seconds with Ollama)
6. Review the threat report across 5 tabs: Summary, Findings, URLs, Headers, Remediation

### Understanding Results

| Score Range | Verdict | Action |
|-------------|---------|--------|
| 0–39 | ✅ Safe | Normal precautions apply |
| 40–69 | ⚠️ Suspicious | Verify sender before acting |
| 70–85 | 🚨 Likely Phishing | Report to IT security |
| 86–100 | 🔴 Confirmed Phishing | Delete immediately, report |

### Using the Context Menu

1. **Select any email text** on a webpage (Gmail, Outlook, etc.)
2. **Right-click** and select **"🛡️ Analyze with PhishGuard AI"**
3. The extension opens with the selected text pre-loaded

### Exporting Reports

- **Copy Report**: Copies a formatted ASCII report to your clipboard
- **Export PDF**: Opens a print-optimized HTML report in a new tab (use `Ctrl+P` to print)

---

## AI Provider Configuration

Open Settings by clicking the ⚙️ gear icon in the extension header, or via the context menu.

### Ollama (Recommended — Free & Private)

| Field | Value |
|-------|-------|
| Endpoint | `http://localhost:11434` |
| Model | `deepseek-r1:8b` (recommended) |

Click **"Test Connection"** to verify Ollama is running. Detected models will appear as clickable chips.

### OpenAI

1. Get your API key from [platform.openai.com/api-keys](https://platform.openai.com/api-keys)
2. Enter the key in **Settings → AI Provider → OpenAI**
3. Select model: `gpt-4o-mini` (cost-efficient) or `gpt-4o` (most capable)

Estimated cost: ~$0.001–0.003 per email analysis with `gpt-4o-mini`.

### Google Gemini

1. Get your API key from [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
2. Enter the key in **Settings → AI Provider → Gemini**
3. Select model: `gemini-1.5-flash` (recommended)

### xAI Grok

1. Get your API key from [console.x.ai](https://console.x.ai)
2. Enter the key in **Settings → AI Provider → Grok**
3. Model is fixed to `grok-beta`

---

## Troubleshooting

### "Ollama: Offline ✗" Status

**Problem**: The extension cannot reach the Ollama server.

**Solutions**:
1. Ensure Ollama is running: `ollama serve`
2. Set the CORS environment variable (see [Ollama Setup](#ollama-setup))
3. Verify the endpoint in Settings matches your Ollama configuration
4. Check your firewall isn't blocking port 11434
5. Try visiting `http://localhost:11434/api/tags` in Chrome — it should return JSON

### "AI error: ..." in Analysis

**Problem**: The LLM returned an unexpected response.

**Solutions**:
1. Ensure your model is fully downloaded: `ollama pull deepseek-r1:8b`
2. For cloud providers, verify your API key is valid and has credits
3. Some models may not support JSON output reliably — try `deepseek-r1:8b` or `mistral`

### Gmail / Outlook Not Extracting Email

**Problem**: Context menu analysis doesn't capture the full email.

**Solutions**:
1. For Gmail: Use "Show Original" (three-dot menu → Show original) and copy the full text
2. For Outlook: Use "View Source" or copy the email manually
3. The extension works best with manually pasted content including headers

### Extension Not Loading

**Problem**: Extension doesn't appear after loading unpacked.

**Solutions**:
1. Ensure you selected the `phishguard-ai` folder (containing `manifest.json`), not the parent folder
2. Check `chrome://extensions/` for any error messages and click "Details"
3. Ensure Developer Mode is enabled
4. Try removing and re-adding the extension

### Analysis Returns Rule-Only Results

**Problem**: Results show `[AI provider offline — analysis based on rule engine only]`.

**This is expected behavior**: When no AI provider is available, PhishGuard falls back to rule-engine-only analysis. Connect Ollama or configure an API key for full AI analysis.

---

## Privacy & Security

| Mode | Data Privacy |
|------|-------------|
| **Ollama (Local)** | ✅ Zero data leaves your machine. All processing is 100% local. |
| **OpenAI** | Email content is sent to OpenAI's API. Subject to their [privacy policy](https://openai.com/policies/privacy-policy). |
| **Gemini** | Email content is sent to Google's API. Subject to their [privacy policy](https://policies.google.com/privacy). |
| **Grok** | Email content is sent to xAI's API. Subject to their [privacy policy](https://x.ai/privacy). |

**API keys** are stored locally in `chrome.storage.local` — never transmitted anywhere except to the respective AI provider's API.

**Email content** is never stored permanently unless you explicitly use the "Save Analysis" feature (auto-save in settings).

---

## Architecture Overview

```
User Input (paste/upload email)
           │
           ▼
    ┌─────────────────┐
    │  Header Parser  │  → Extracts From, To, Reply-To, SPF/DKIM/DMARC
    │  URL Scanner    │  → Finds all URLs, checks for lookalikes/shorteners
    │  Email Parser   │  → Subject, body, attachments
    └────────┬────────┘
             │
             ▼
    ┌─────────────────────┐
    │    Rule Engine      │  12 deterministic checks:
    │    (Local JS)       │  • Urgency Keywords
    │                     │  • Brand Spoofing
    │                     │  • Reply-To Mismatch
    │                     │  • Personal Data Request
    │                     │  • Generic Greeting
    │                     │  • Display Name Mismatch
    │                     │  • Suspicious TLD
    │                     │  • Dangerous Attachment
    │                     │  • Lookalike URLs
    │                     │  • Free Email Impersonation
    │                     │  • HTML Link Obfuscation
    │                     │  • Financial Fraud Triggers
    └────────┬────────────┘
    Rule Score (0-100)
             │
             ▼
    ┌─────────────────────┐
    │    LLM Analysis     │  Via background.js (no CORS):
    │   (background.js)   │  • Ollama (local)
    │                     │  • OpenAI GPT-4o
    │                     │  • Google Gemini
    │                     │  • xAI Grok
    └────────┬────────────┘
    LLM Score (0-100)
             │
             ▼
    Final Score = (LLM Score × 0.6) + (Rule Score × 0.4)
             │
             ▼
    ┌─────────────────────┐
    │   Threat Report     │  5-tab report with:
    │                     │  • Risk Gauge (animated SVG)
    │                     │  • Category Scores
    │                     │  • Rule Findings
    │                     │  • URL Analysis
    │                     │  • Header Authentication
    │                     │  • Remediation Checklist
    └─────────────────────┘
```

---

## MITRE ATT&CK Reference

PhishGuard AI maps detected threats to the MITRE ATT&CK framework, primarily under the **Initial Access** tactic.

| Technique ID | Name | Description |
|---|---|---|
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | General phishing categorization |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Targeted attack with malicious attachment |
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Spearphishing Link | Targeted attack with malicious link |
| [T1566.003](https://attack.mitre.org/techniques/T1566/003/) | Spearphishing via Service | Attack via third-party services |
| [T1534](https://attack.mitre.org/techniques/T1534/) | Internal Spearphishing | BEC-style internal impersonation |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Credential theft objective |
| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution | Malware delivery via email |
| [T1657](https://attack.mitre.org/techniques/T1657/) | Financial Theft | BEC financial fraud objective |

---

## Contributing

Found a bug or have a feature request? This is designed to be a starting point — feel free to extend:

- Add new rules in `engine/ruleEngine.js`
- Add new AI providers in `background.js`
- Improve the system prompt in `engine/prompts.js`
- Add more brand domains to the brand map

---

## License

MIT License — Use freely for personal and commercial purposes.

---

*Built for security professionals who need fast, accurate phishing detection without sending sensitive email data to unknown third parties.*
