# Contributing to Revelio

Thank you for your interest in contributing! This guide covers how to set up the
development environment, understand the codebase, and submit changes.

---

## Development Setup

### Prerequisites
- Google Chrome (or Chromium-based browser)
- Node.js ≥ 18 (for CSS build only — the extension itself is vanilla JS)

### Install Dependencies

`ash
npm install
`

### Load the Extension

1. Open chrome://extensions in Chrome
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** and select the d:\Revelio folder
4. The Revelio icon will appear in your toolbar

### Build CSS (Tailwind)

The popup and settings pages use Tailwind CSS compiled via:

`ash
npm run build:css
`

Run this whenever you change a .html file or any Tailwind class. The output
goes to popup/popup-built.css.

---

## Project Architecture

`
Revelio/
├── background.js            # Service worker — routes all API calls (LLM, Safe Browsing, VT)
├── content.js               # Content script — extracts email DOM from Gmail / Outlook
├── engine/
│   ├── constants.js         # All detection data (brand map, keyword lists, score weights)
│   ├── ruleEngine.js        # 12 deterministic phishing detection rules
│   ├── analyzer.js          # Orchestrator — parse → rules → score → verdict
│   └── prompts.js           # LLM prompt builder + offline fallback result generator
├── utils/
│   ├── cache.js             # Email hashing + chrome.storage.local cache helpers
│   ├── storage.js           # Settings, history, stats, feedback storage wrappers
│   ├── urlScanner.js        # URL extraction + per-URL heuristic risk scoring
│   ├── urlSafety.js         # Google Safe Browsing + VirusTotal API clients
│   ├── headerParser.js      # Raw email header parser (SPF/DKIM/DMARC)
│   ├── homoglyphMap.js      # Unicode homoglyph detection table
│   └── reportExporter.js   # Clipboard text export + PDF generation
├── popup/
│   ├── popup.html           # Main extension popup UI
│   ├── popup.js             # Popup controller (1,600+ lines — see section headers)
│   └── popup.css / popup-built.css
├── settings/
│   ├── settings.html
│   └── settings.js          # Settings page controller
├── report/
│   ├── report.html          # PDF report template (opened in new tab)
│   └── report.js
└── samples/
    └── sampleEmails.js      # Demo emails for the manual-paste flow
`

**Data flow:**
`
Gmail/Outlook (DOM)
  → content.js (PASSIVE_SCAN / EXTRACT_EMAIL message)
    → background.js (runs full pipeline)
      ├── engine/analyzer.js  (parse + rules)
      ├── engine/prompts.js   (build LLM prompt)
      ├── callOllama / callOpenAI / callGemini / callOpenRouter
      └── utils/cache.js      (save result to chrome.storage)
        → popup.js            (renders threat report)
`

---

## Code Style

- **File headers**: Every file starts with // Revelio — <Module Name>
- **Section separators**: // ─── Section Name ───...────
- **JSDoc**: All exported functions must have @param and @returns documentation
- **Constants**: Never use magic numbers. Add them to engine/constants.js
- **Logging prefix**: Always use [Revelio] — e.g. console.warn('[Revelio] ...')
- **Indentation**: 2 spaces (enforced by .editorconfig)
- **Imports**: Use relative paths with .js extension (required for browser ES modules)

---

## Submitting Changes

1. Fork the repo and create a branch: git checkout -b feat/your-feature-name
2. Make your changes following the code style guide above
3. Test end-to-end: load unpacked, open Gmail, open a suspicious email, verify results
4. Open a Pull Request against main
5. Fill in the PR template checklist

---

## Reporting Bugs

Use the GitHub issue tracker and select the **Bug Report** template.
Please include:
- Chrome version
- Extension version (visible in chrome://extensions)
- AI provider being used
- Console errors (F12 → Console in the extension popup)
