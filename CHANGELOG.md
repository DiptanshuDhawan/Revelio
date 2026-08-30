# Changelog

All notable changes to Revelio are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2025-08-30

### Added
- Chrome Extension (Manifest V3) supporting Gmail and Outlook
- Auto passive scanning: emails are analyzed the moment you open them
- Four AI provider integrations: Ollama (local), OpenAI, Google Gemini, OpenRouter
- 12 deterministic phishing detection rules (urgency keywords, display-name spoof, lookalike domains, SPF/DKIM/DMARC checks, homoglyph detection, and more)
- LLM + rule-engine blended scoring with user-configurable sensitivity
- Deep URL scan: 12+ heuristic checks per URL (shorteners, suspicious TLDs, lookalike domains)
- Google Safe Browsing and VirusTotal integration for on-demand URL verification
- MITRE ATT&CK T1566 mapping in every report
- Email history with per-record analysis details
- PDF and clipboard export of threat reports
- SOC dashboard integration (heartbeat + alert forwarding)
- Dark mode and light mode support
- Offline/fallback mode when no AI provider is reachable
