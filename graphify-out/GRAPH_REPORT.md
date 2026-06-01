# Graph Report - .  (2026-06-01)

## Corpus Check
- Corpus is ~30,594 words - fits in a single context window. You may not need a graph.

## Summary
- 235 nodes · 375 edges · 25 communities (15 shown, 10 thin omitted)
- Extraction: 96% EXTRACTED · 4% INFERRED · 0% AMBIGUOUS · INFERRED: 15 edges (avg confidence: 0.88)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Popup UI Flow|Popup UI Flow]]
- [[_COMMUNITY_Rule Engine Domain Checks|Rule Engine Domain Checks]]
- [[_COMMUNITY_Extension Manifest|Extension Manifest]]
- [[_COMMUNITY_Settings and Storage|Settings and Storage]]
- [[_COMMUNITY_Analysis Pipeline|Analysis Pipeline]]
- [[_COMMUNITY_Header and URL Parsing|Header and URL Parsing]]
- [[_COMMUNITY_Package Config|Package Config]]
- [[_COMMUNITY_Background LLM Calls|Background LLM Calls]]
- [[_COMMUNITY_Report Export|Report Export]]
- [[_COMMUNITY_Documentation & Prompts|Documentation & Prompts]]
- [[_COMMUNITY_Content Script Extractor|Content Script Extractor]]
- [[_COMMUNITY_Security Shield Concept|Security Shield Concept]]
- [[_COMMUNITY_Claude Settings|Claude Settings]]
- [[_COMMUNITY_AI Shield Gradient Concept|AI Shield Gradient Concept]]
- [[_COMMUNITY_Padlock Image Concept|Padlock Image Concept]]
- [[_COMMUNITY_Icon Fallbacks|Icon Fallbacks]]
- [[_COMMUNITY_Settings Storage|Settings Storage]]
- [[_COMMUNITY_Claude Graphify|Claude Graphify]]
- [[_COMMUNITY_Copy to Clipboard|Copy to Clipboard]]
- [[_COMMUNITY_Export PDF|Export PDF]]
- [[_COMMUNITY_Sample Emails|Sample Emails]]
- [[_COMMUNITY_Manifest Revelio|Manifest Revelio]]
- [[_COMMUNITY_Tailwind Theme Config|Tailwind Theme Config]]

## God Nodes (most connected - your core abstractions)
1. `runRuleEngine()` - 16 edges
2. `handleAnalyze()` - 16 edges
3. `renderResults()` - 10 edges
4. `parseHeaders()` - 10 edges
5. `autoExtractAndAnalyze()` - 9 edges
6. `saveSettings()` - 8 edges
7. `showToast()` - 7 edges
8. `getSettings()` - 7 edges
9. `handleAnalyze()` - 6 edges
10. `parseAIResponse()` - 6 edges

## Surprising Connections (you probably didn't know these)
- `saveAnalysis` --semantically_similar_to--> `cacheResult`  [INFERRED] [semantically similar]
  utils/storage.js → popup/popup.js
- `handleAnalyze()` --calls--> `analyzeEmail()`  [EXTRACTED]
  popup/popup.js → engine/analyzer.js
- `handleAnalyze()` --calls--> `generateOfflineFallback()`  [EXTRACTED]
  popup/popup.js → engine/prompts.js
- `switchProviderTab()` --calls--> `saveSettings()`  [EXTRACTED]
  popup/popup.js → utils/storage.js
- `handleAnalyze()` --calls--> `saveAnalysis()`  [EXTRACTED]
  popup/popup.js → utils/storage.js

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Email Extraction Flow** — content_extractCurrentEmail, content_extractGmail, content_extractOutlook, rationale_heuristic_extraction [INFERRED 0.95]
- **Core Analysis Pipeline** — popup_handleAnalyze, analyzer_analyzeEmail, analyzer_parseEmailData, headerParser_parseHeaders, urlScanner_extractAndAnalyzeURLs [INFERRED 0.85]
- **Local State Management** — storage_saveAnalysis, storage_getSettings, popup_cacheResult, storage_saveSettings [INFERRED 0.85]
- **App Icon Visual Composition** — icon128_png, icon128_shield, icon128_lock [EXTRACTED 1.00]

## Communities (25 total, 10 thin omitted)

### Community 0 - "Popup UI Flow"
Cohesion: 0.08
Nodes (39): computeFinalScore(), scoreToVerdict(), applyIconFallback(), autoExtractAndAnalyze(), cacheResult(), capitalize(), categoryColor(), checkForPendingText() (+31 more)

### Community 1 - "Rule Engine Domain Checks"
Cohesion: 0.12
Nodes (32): BRAND_DOMAIN_MAP, calculateRuleScore(), checkDangerousAttachment(), checkDisplayNameMismatch(), checkFreeEmailImpersonation(), checkGenericGreeting(), checkHTMLObfuscation(), checkInvoiceFinancial() (+24 more)

### Community 2 - "Extension Manifest"
Cohesion: 0.07
Nodes (26): action, default_icon, default_popup, default_title, author, background, service_worker, type (+18 more)

### Community 3 - "Settings and Storage"
Cohesion: 0.18
Nodes (14): handleClearHistory(), openHistory(), renderHistory(), attachEventListeners(), loadSettingsIntoUI(), switchProvider(), clearHistory(), DEFAULT_SETTINGS (+6 more)

### Community 4 - "Analysis Pipeline"
Cohesion: 0.12
Nodes (18): analyzeEmail, computeFinalScore, parseEmailData, extractCurrentEmail, extractGmail, extractOutlook, parseHeaders, autoExtractAndAnalyze (+10 more)

### Community 5 - "Header and URL Parsing"
Cohesion: 0.27
Nodes (12): analyzeEmail(), extractSubjectFromBody(), parseEmailData(), createEmptyHeaders(), extractDomain(), extractFirstHopIP(), extractHeader(), extractRootDomain() (+4 more)

### Community 6 - "Package Config"
Cohesion: 0.14
Nodes (13): author, description, devDependencies, tailwindcss, @tailwindcss/cli, keywords, license, main (+5 more)

### Community 7 - "Background LLM Calls"
Cohesion: 0.32
Nodes (8): buildAnalysisPrompt(), callGemini(), callGrok(), callOllama(), callOpenAI(), clamp(), handleAnalyze(), parseAIResponse()

### Community 8 - "Report Export"
Cohesion: 0.23
Nodes (11): handleCopyReport(), handleExportPDF(), handleFalsePositive(), handleFileUpload(), showToast(), asciiBar(), copyToClipboard(), exportPDF() (+3 more)

### Community 9 - "Documentation & Prompts"
Cohesion: 0.22
Nodes (6): generateOfflineFallback(), LLM Analysis, MITRE ATT&CK Reference, Ollama Setup, Revelio — Email Threat Analyzer, Rule Engine

### Community 10 - "Content Script Extractor"
Cohesion: 0.70
Nodes (4): extractCurrentEmail(), extractFallback(), extractGmail(), extractOutlook()

### Community 11 - "Security Shield Concept"
Cohesion: 0.50
Nodes (4): Cybersecurity Protection Concept, Padlock Motif, PhishGuard AI App Icon 128x128, Shield Motif

### Community 13 - "AI Shield Gradient Concept"
Cohesion: 0.67
Nodes (3): AI/Modern Tech Gradient (Blue/Purple), Shield Icon (Protection), PhishGuard AI 16x16 Icon

## Knowledge Gaps
- **66 isolated node(s):** `PreToolUse`, `BRAND_DOMAIN_MAP`, `URGENCY_KEYWORDS`, `PERSONAL_DATA_KEYWORDS`, `GENERIC_GREETINGS` (+61 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **10 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `runRuleEngine()` connect `Rule Engine Domain Checks` to `Header and URL Parsing`?**
  _High betweenness centrality (0.036) - this node is a cross-community bridge._
- **Why does `saveSettings()` connect `Settings and Storage` to `Popup UI Flow`, `Background LLM Calls`?**
  _High betweenness centrality (0.023) - this node is a cross-community bridge._
- **Why does `analyzeEmail()` connect `Header and URL Parsing` to `Popup UI Flow`, `Rule Engine Domain Checks`?**
  _High betweenness centrality (0.021) - this node is a cross-community bridge._
- **What connects `PreToolUse`, `BRAND_DOMAIN_MAP`, `URGENCY_KEYWORDS` to the rest of the system?**
  _70 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Popup UI Flow` be split into smaller, more focused modules?**
  _Cohesion score 0.08405797101449275 - nodes in this community are weakly interconnected._
- **Should `Rule Engine Domain Checks` be split into smaller, more focused modules?**
  _Cohesion score 0.11586452762923351 - nodes in this community are weakly interconnected._
- **Should `Extension Manifest` be split into smaller, more focused modules?**
  _Cohesion score 0.07407407407407407 - nodes in this community are weakly interconnected._