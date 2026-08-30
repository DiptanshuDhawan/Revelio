<div align="center">
  <img src="docs/hero_banner.png" alt="Revelio Banner" width="100%">

  <p>
    <a href="https://developer.chrome.com/docs/extensions/"><img src="https://img.shields.io/badge/Chrome_Extension-4285F4?logo=googlechrome&logoColor=white" alt="Chrome Extension"></a>
    <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript"><img src="https://img.shields.io/badge/JavaScript-F7DF1E?logo=javascript&logoColor=black" alt="JavaScript"></a>
    <a href="https://tailwindcss.com/"><img src="https://img.shields.io/badge/Tailwind_CSS-38B2AC?logo=tailwind-css&logoColor=white" alt="Tailwind CSS"></a>
    <a href="https://github.com/DiptanshuDhawan/Revelio/commits/main"><img src="https://img.shields.io/github/last-commit/DiptanshuDhawan/Revelio.svg?style=flat&color=blue" alt="Last Commit"></a>
    <a href="https://github.com/DiptanshuDhawan/Revelio/commits/main"><img src="https://img.shields.io/github/commit-activity/m/DiptanshuDhawan/Revelio.svg?style=flat&color=brightgreen" alt="Commits per month"></a>
    <br>
    <a href="https://github.com/DiptanshuDhawan/Revelio"><img src="https://img.shields.io/github/languages/top/DiptanshuDhawan/Revelio.svg?style=flat&color=yellow" alt="Top Language"></a>
    <a href="https://github.com/DiptanshuDhawan/Revelio"><img src="https://img.shields.io/github/languages/code-size/DiptanshuDhawan/Revelio.svg?style=flat&color=orange" alt="Code Size"></a>
    <a href="https://github.com/DiptanshuDhawan/Revelio"><img src="https://img.shields.io/badge/Maintained%3F-yes-green.svg" alt="Maintained"></a>
    <a href="#license"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
    <a href="https://github.com/DiptanshuDhawan/Revelio/pulls"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome"></a>
    <a href="#project-status"><img src="https://img.shields.io/badge/Status-Beta-orange.svg" alt="Status"></a>
  </p>
</div>

---

## Features & Interface

### Threat Intelligence Dashboard
The extension popup provides a complete breakdown of the analyzed email, including a Threat Radar, MITRE ATT&CK mapping, and specific AI-driven findings.

<div align="center">
  <img src="docs/popup.png" alt="Threat Radar" width="260">&nbsp;
  <img src="docs/popup_analysis.png" alt="AI Analysis" width="260">&nbsp;
  <img src="docs/popup_rules.png" alt="Rule Checks" width="260">
  <br><br>
  <img src="docs/popup_urls.png" alt="URL Scanning" width="260">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <img src="docs/popup_remediation.png" alt="Remediation" width="260">
</div>

### Extensive Configuration
Revelio offers a comprehensive settings panel where you can seamlessly switch between local (Ollama) and cloud AI providers, configure URL safety checks (Google Safe Browsing & VirusTotal), and adjust sensitivity thresholds.

<div align="center">
  <img src="docs/settings_ai.png" alt="AI Provider Configuration" width="800">
</div>

### PDF Report Generation
Generate SOC-ready PDF reports with a single click to document and escalate confirmed threats.

<div align="center">
  <img src="docs/report_pdf.png" alt="Revelio PDF Report" width="600">
</div>

---

Traditional Secure Email Gateways often miss zero-day social engineering and targeted Business Email Compromise (BEC) attacks. Revelio solves this by bringing enterprise-grade, AI-driven threat analysis directly into your browser. 

- **Dual-Engine Architecture**: Combines lightning-fast deterministic heuristics (URL lookalikes, header spoofing) with deep-context Large Language Models (evaluating urgency, manipulation, and tone).
- **Zero-Trust Privacy**: Supports 100% offline analysis via Ollama. No sensitive email data ever leaves your machine unless you explicitly configure a cloud provider.
- **Dynamic AI Integrations**: Plugs seamlessly into local models (Ollama) or leading cloud providers (OpenAI, Google Gemini, OpenRouter) with automatic, dynamic model discovery.
- **Passive Auto-Scan**: Scans emails seamlessly in the background the moment you open them, generating MITRE-mapped threat intelligence reports.

## Architecture

Revelio operates entirely within the browser using Manifest V3 architecture.

```mermaid
graph TD
    User([User Email Client]) -->|Opens Email| Content[Content Script]
    
    Content -->|Extracts DOM| Worker[Background Service Worker]
    
    Worker -->|Heuristic Checks| Rules[Rule Engine]
    Worker -->|Prompt Injection| AI[AI Provider Router]
    
    AI -.->|Local Inference| Ollama[(Local Ollama)]
    AI -.->|Cloud Inference| Cloud[(OpenAI / Gemini / OpenRouter)]
    
    Rules --> Evaluator[Threat Evaluator]
    AI --> Evaluator
    
    Evaluator -->|Displays Report| Popup[Chrome Popup UI]
    Evaluator -.->|Persists History| Storage[(Local Storage)]
```

## Quick Start

### Prerequisites

- Google Chrome, Microsoft Edge, or any Chromium-based browser
- Node.js & npm (for building CSS)
- **(Optional)** [Ollama](https://ollama.com/) for fully offline, zero-trust local analysis

### 1. Clone the repository

```bash
git clone https://github.com/DiptanshuDhawan/Revelio.git
cd Revelio
```

### 2. Build the styles

Revelio uses Tailwind CSS. Install dependencies and compile the stylesheet:

```bash
npm install
npm run build:css
```

### 3. Load the extension

1. Open your browser and navigate to `chrome://extensions/`.
2. Enable **Developer mode** using the toggle in the top right corner.
3. Click **Load unpacked** and select the `Revelio` directory.

### 4. Configure AI Providers (Settings)

Click the Revelio extension icon, open the **Settings**, and navigate to the **AI Provider** tab:
- **Local (Ollama)**: Ensure Ollama is running with CORS enabled:
  ```bash
  OLLAMA_ORIGINS="chrome-extension://*" ollama serve
  ```
- **Cloud**: Input your API key for OpenAI, Gemini, or OpenRouter. Available models are fetched dynamically.

## Development & Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on setting up the dev environment and our coding standards. 

## Project Status

Revelio is currently in active beta. The core heuristic engine, popup UI, dynamic AI provider system, and background orchestration are fully functional. Current work focuses on expanding deterministic rules and refining LLM prompts for newer models.

## License

Distributed under the MIT License. See `LICENSE` for details.
