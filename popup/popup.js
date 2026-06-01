// PhishGuard AI — Popup Controller
// Auto-detects the current Gmail/Outlook email on open and instantly analyzes it.

import { analyzeEmail, computeFinalScore, scoreToVerdict } from '../engine/analyzer.js';
import { generateOfflineFallback } from '../engine/prompts.js';
import { getSettings, saveSettings, saveAnalysis, getHistory, clearHistory, saveFeedback } from '../utils/storage.js';
import { copyToClipboard, exportPDF } from '../utils/reportExporter.js';
import { SAMPLE_EMAILS } from '../samples/sampleEmails.js';

// ─── State ────────────────────────────────────────────────────────────────────
let currentResult = null;
let currentSettings = {};
let currentAnalysisId = null;

// ─── Email Hash (simple fingerprint for cache keying) ────────────────────────
function hashEmail(text) {
  // Fast non-cryptographic hash (djb2-style)
  let hash = 5381;
  for (let i = 0; i < Math.min(text.length, 2000); i++) {
    hash = ((hash << 5) + hash) ^ text.charCodeAt(i);
    hash = hash & 0xffffffff; // keep 32-bit
  }
  return 'phishcache_v2_' + Math.abs(hash).toString(36);
}

// Save analysis result to cache keyed by email hash
async function cacheResult(emailText, result) {
  try {
    const key = hashEmail(emailText);
    await chrome.storage.local.set({
      [key]: { result, cachedAt: Date.now(), emailPreview: emailText.slice(0, 80) },
      phishguard_last_cache_key: key,
    });
  } catch (e) { /* silent */ }
}

// Restore cached result if available for this email text
async function getCachedResult(emailText) {
  try {
    const key = hashEmail(emailText);
    const data = await chrome.storage.local.get(key);
    if (data[key]) {
      // Only use cache if it's less than 30 minutes old
      const ageMs = Date.now() - (data[key].cachedAt || 0);
      if (ageMs < 30 * 60 * 1000) return data[key].result;
    }
  } catch (e) { /* silent */ }
  return null;
}

// Clear the last cached result (call when user wants a fresh analysis)
async function clearLastCache(emailText = '') {
  try {
    const keys = ['phishguard_last_cache_key'];
    if (emailText) keys.push(hashEmail(emailText));

    const data = await chrome.storage.local.get('phishguard_last_cache_key');
    const key = data.phishguard_last_cache_key;
    if (key) keys.push(key);

    await chrome.storage.local.remove([...new Set(keys)]);
  } catch (e) { /* silent */ }
}

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  hydrateIconFallbacks();
  currentSettings = await getSettings();
  applyTheme(currentSettings.theme);
  populateSettingsFromStorage(currentSettings);
  startOllamaCheck();
  attachEventListeners();

  // ── Auto-detect flow ─────────────────────────────────────────────────────
  // 1. Check if there is pending text from the right-click context menu
  const consumed = await checkForPendingText();
  // 2. If nothing pending, try to auto-extract from the current active tab
  if (!consumed) {
    await autoExtractAndAnalyze();
  }
});

function hydrateIconFallbacks(root = document) {
  const iconMap = {
    shield: '🛡',
    dark_mode: '◐',
    settings: '⚙',
    close: '×',
    history: '↺',
    upload: '↑',
    psychology: '◎',
    memory: '▣',
    autorenew: '↻',
    check_circle: '✓',
    warning: '!',
    error: '!',
    info: 'i',
    check: '✓',
    manage_search: '⌕',
    link_off: '⊘',
    security: '◆',
    content_copy: '□',
    print: '▤',
    refresh: '↻',
  };

  root.querySelectorAll?.('.material-symbols-outlined').forEach((el) => {
    applyIconFallback(el, iconMap);
  });
}

function applyIconFallback(el, iconMap = null) {
  const map = iconMap || {
    shield: '🛡',
    dark_mode: '◐',
    settings: '⚙',
    close: '×',
    history: '↺',
    upload: '↑',
    psychology: '◎',
    memory: '▣',
    autorenew: '↻',
    check_circle: '✓',
    warning: '!',
    error: '!',
    info: 'i',
    check: '✓',
    manage_search: '⌕',
    link_off: '⊘',
    security: '◆',
    content_copy: '□',
    print: '▤',
    refresh: '↻',
  };
  const key = el.textContent.trim();
  if (map[key]) {
    el.textContent = map[key];
    el.classList.add('icon-fallback');
  }
}

const iconObserver = new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    mutation.addedNodes.forEach((node) => {
      if (node.nodeType === Node.ELEMENT_NODE) hydrateIconFallbacks(node);
    });
    if (mutation.type === 'characterData') {
      const parent = mutation.target.parentElement;
      if (parent?.classList?.contains('material-symbols-outlined')) {
        applyIconFallback(parent);
      }
    }
  }
});

iconObserver.observe(document.documentElement, { childList: true, characterData: true, subtree: true });

// ─── Theme ────────────────────────────────────────────────────────────────────
function applyTheme(theme) {
  const body = document.body;
  const darkIcon = document.getElementById('theme-icon-dark');
  const lightIcon = document.getElementById('theme-icon-light');

  if (theme === 'light') {
    body.classList.remove('dark-mode');
    body.classList.add('light-mode');
    if (darkIcon) darkIcon.style.display = 'block';
    if (lightIcon) lightIcon.style.display = 'none';
  } else {
    body.classList.add('dark-mode');
    body.classList.remove('light-mode');
    if (darkIcon) darkIcon.style.display = 'none';
    if (lightIcon) lightIcon.style.display = 'block';
  }
}

document.getElementById('theme-toggle').addEventListener('click', async () => {
  const newTheme = currentSettings.theme === 'dark' ? 'light' : 'dark';
  currentSettings.theme = newTheme;
  applyTheme(newTheme);
  await saveSettings({ theme: newTheme });
});

// ─── Ollama Health Check ──────────────────────────────────────────────────────
function startOllamaCheck() {
  checkOllamaStatus();
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'OLLAMA_STATUS') updateOllamaStatus(msg.online);
  });
}

async function checkOllamaStatus() {
  const endpoint = currentSettings.ollamaEndpoint || 'http://localhost:11434';
  const pill = document.getElementById('ollama-status');
  if (pill) {
    setStatusPill(pill, 'checking', 'Checking...');
  }

  try {
    const response = await chrome.runtime.sendMessage({ type: 'CHECK_OLLAMA', endpoint });
    updateOllamaStatus(response?.online);
  } catch {
    updateOllamaStatus(false);
  }
}

function updateOllamaStatus(online) {
  const pill = document.getElementById('ollama-status');
  if (!pill) return;
  const provider = currentSettings.provider || 'ollama';

  if (provider !== 'ollama') {
    setStatusPill(pill, 'online', `${capitalize(provider)}: Ready`);
    return;
  }

  setStatusPill(pill, online ? 'online' : 'offline', online ? 'Ollama: Connected' : 'Ollama: Offline');
}

function setStatusPill(pill, state, text) {
  const label = pill.querySelector('.status-label');
  const dot = pill.firstElementChild;
  const tone = {
    online: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
    offline: 'bg-error/10 border-error/20 text-error',
    checking: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
  }[state] || 'bg-surface-variant/20 border-outline-variant/30 text-on-surface-variant';

  pill.className = `flex items-center gap-1.5 border rounded-full px-2 py-1 text-[10px] font-label-caps ${tone}`;
  if (dot) {
    const dotColor = state === 'offline' ? 'bg-error' : state === 'checking' ? 'bg-amber-400' : 'bg-emerald-400';
    dot.className = `w-1.5 h-1.5 rounded-full ${dotColor} ${state === 'offline' ? '' : 'animate-pulse'}`;
  }
  if (label) label.textContent = text;
}

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

// ─── Auto-Detect Banner ───────────────────────────────────────────────────────
function showBanner(state, text) {
  const banner = document.getElementById('auto-detect-banner');
  const bannerText = document.getElementById('auto-detect-text');
  const icon = document.getElementById('auto-detect-icon');
  if (!banner) return;

  banner.style.display = 'flex';
  
  const baseClasses = 'items-center justify-between px-container-padding py-2 text-[12px] z-30 shadow-sm shrink-0';
  if (state === 'detecting') {
    banner.className = `${baseClasses} bg-primary/10 border-b border-primary/20 text-primary`;
  } else if (state === 'success') {
    banner.className = `${baseClasses} bg-emerald-500/10 border-b border-emerald-500/20 text-emerald-400`;
  } else {
    banner.className = `${baseClasses} bg-error/10 border-b border-error/20 text-error`;
  }

  if (bannerText) bannerText.textContent = text;

  if (icon) {
    if (state === 'detecting') {
      icon.textContent = 'autorenew';
      icon.classList.add('animate-spin');
    } else if (state === 'success') {
      icon.textContent = 'check_circle';
      icon.classList.remove('animate-spin');
    } else {
      icon.textContent = 'warning';
      icon.classList.remove('animate-spin');
    }
    applyIconFallback(icon);
  }
}

function hideBanner() {
  const banner = document.getElementById('auto-detect-banner');
  if (banner) banner.style.display = 'none';
}

// ─── Check for Context Menu Pre-Filled Text ───────────────────────────────────
// Returns true if it consumed pending text and triggered analysis.
async function checkForPendingText() {
  try {
    const data = await chrome.storage.local.get('pendingEmailText');
    if (data.pendingEmailText) {
      const text = data.pendingEmailText;
      await chrome.storage.local.remove('pendingEmailText');
      document.getElementById('email-input').value = text;
      showBanner('success', 'Email loaded from page selection — analyzing...');
      setTimeout(() => handleAnalyze(), 300);
      return true;
    }
  } catch (e) { /* silent */ }
  return false;
}

// ─── Auto-Extract from Active Tab ────────────────────────────────────────────
// This is the core of the zero-friction flow:
// 1. Get the active tab
// 2. If it's Gmail/Outlook, ping the content script
// 3. If content script is alive, request email extraction
// 4. If we get email text, immediately start analysis
async function autoExtractAndAnalyze() {
  let tabs;
  try {
    tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch {
    return; // Not allowed (e.g., chrome:// page)
  }

  const tab = tabs?.[0];
  if (!tab?.id || !tab?.url) return;

  const url = tab.url;
  const isMailPage =
    url.includes('mail.google.com') ||
    url.includes('outlook.live.com') ||
    url.includes('outlook.office.com') ||
    url.includes('outlook.office365.com');

  // Show banner only if we're on a mail page
  if (isMailPage) {
    showBanner('detecting', 'Detecting open email...');
  } else {
    showBanner('error', 'Not a supported mail page (Gmail/Outlook). Please upload or paste manually.');
    return;
  }

  // Ping content script to confirm it's injected
  let ping;
  try {
    ping = await chrome.tabs.sendMessage(tab.id, { type: 'PING' });
  } catch {
    // Content script might not be injected yet — try scripting API to inject it
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['content.js'],
      });
      // Small delay for script to initialize
      await sleep(200);
      ping = await chrome.tabs.sendMessage(tab.id, { type: 'PING' });
    } catch {
      showBanner('error', 'Could not connect to page. Try reloading the tab.');
      return;
    }
  }

  if (!ping?.pong) {
    showBanner('error', 'Content script not responding. Reload Gmail/Outlook and try again.');
    return;
  }

  // Request email extraction
  let extracted;
  try {
    extracted = await chrome.tabs.sendMessage(tab.id, { type: 'EXTRACT_EMAIL' });
  } catch (e) {
    showBanner('error', 'Could not read email. Open an email first, then click the icon.');
    return;
  }

  if (!extracted?.emailText) {
    const msg = extracted?.error || 'No email found. Please open an email in Gmail or Outlook first.';
    showBanner('error', msg);
    return;
  }

  // Populate the textarea (so the user can see what was captured)
  const textarea = document.getElementById('email-input');
  if (textarea) textarea.value = extracted.emailText;

  // ── Cache check: if this exact email was already analyzed, show cached result ──
  const cached = await getCachedResult(extracted.emailText);
  if (cached) {
    currentResult = cached;
    // Route cached offline results to offline view
    if (cached.llmResult?._offlineMode) {
      renderOfflineView(cached.ruleResult, cached.finalScore);
      showView('offline');
      hideBanner();
    } else {
      renderResults(cached);
      showView('results');
    }
    showBanner('success', '✓ Showing cached result — click "Analyze Another" to re-scan');
    return;
  }

  const sourceLabel = extracted.source === 'gmail'
    ? 'Gmail email detected'
    : extracted.source === 'outlook'
    ? 'Outlook email detected'
    : 'Email detected';

  showBanner('success', `${sourceLabel}. Analyzing...`);

  // Small visual pause so the user sees the banner before loading screen
  await sleep(400);

  // Fire analysis automatically
  await handleAnalyze();
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ─── Populate Settings from Storage ──────────────────────────────────────────
function populateSettingsFromStorage(settings) {
  const ollamaEndpoint = document.getElementById('ollama-endpoint');
  const ollamaModel = document.getElementById('ollama-model');
  const openaiKey = document.getElementById('openai-key');
  const openaiModel = document.getElementById('openai-model');
  const geminiKey = document.getElementById('gemini-key');
  const geminiModel = document.getElementById('gemini-model');
  const grokKey = document.getElementById('grok-key');

  if (ollamaEndpoint) ollamaEndpoint.value = settings.ollamaEndpoint || 'http://localhost:11434';
  if (ollamaModel) {
    const knownModels = ['deepseek-r1:8b', 'llama3.1', 'mistral', 'phi3', 'llama3.2', 'gemma2'];
    if (knownModels.includes(settings.ollamaModel)) {
      ollamaModel.value = settings.ollamaModel;
    } else if (settings.ollamaModel) {
      ollamaModel.value = 'custom';
      const custom = document.getElementById('ollama-model-custom');
      if (custom) { custom.style.display = 'block'; custom.value = settings.ollamaModel; }
    }
  }
  if (openaiKey) openaiKey.value = settings.openaiApiKey || '';
  if (openaiModel) openaiModel.value = settings.openaiModel || 'gpt-4o-mini';
  if (geminiKey) geminiKey.value = settings.geminiApiKey || '';
  if (geminiModel) geminiModel.value = settings.geminiModel || 'gemini-1.5-flash';
  if (grokKey) grokKey.value = settings.grokApiKey || '';

  switchProviderTab(settings.provider || 'ollama');
}

// ─── Collect Settings from UI ─────────────────────────────────────────────────
function collectSettings() {
  const ollamaModelEl = document.getElementById('ollama-model');
  let ollamaModel = ollamaModelEl?.value || 'deepseek-r1:8b';
  if (ollamaModel === 'custom') {
    ollamaModel = document.getElementById('ollama-model-custom')?.value || 'deepseek-r1:8b';
  }

  return {
    ...currentSettings,
    ollamaEndpoint: document.getElementById('ollama-endpoint')?.value || 'http://localhost:11434',
    ollamaModel,
    openaiApiKey: document.getElementById('openai-key')?.value || '',
    openaiModel: document.getElementById('openai-model')?.value || 'gpt-4o-mini',
    geminiApiKey: document.getElementById('gemini-key')?.value || '',
    geminiModel: document.getElementById('gemini-model')?.value || 'gemini-1.5-flash',
    grokApiKey: document.getElementById('grok-key')?.value || '',
  };
}

// ─── Provider Tab Switching ───────────────────────────────────────────────────
function switchProviderTab(provider) {
  document.querySelectorAll('.provider-tab').forEach((tab) => {
    tab.classList.toggle('active', tab.dataset.provider === provider);
    tab.setAttribute('aria-selected', tab.dataset.provider === provider);
  });
  document.querySelectorAll('.provider-config').forEach((panel) => {
    const show = panel.id === `provider-panel-${provider}`;
    panel.classList.toggle('active', show);
    panel.hidden = !show;
  });
  currentSettings.provider = provider;
  saveSettings({ provider });
  updateOllamaStatus(undefined);
  checkOllamaStatus();
}

// ─── Main Event Listeners ─────────────────────────────────────────────────────
function attachEventListeners() {
  // Provider tabs
  document.querySelectorAll('.provider-tab').forEach((tab) => {
    tab.addEventListener('click', () => switchProviderTab(tab.dataset.provider));
  });

  // Ollama model custom toggle
  document.getElementById('ollama-model')?.addEventListener('change', (e) => {
    const custom = document.getElementById('ollama-model-custom');
    if (custom) custom.style.display = e.target.value === 'custom' ? 'block' : 'none';
  });

  // Analyze button
  document.getElementById('analyze-btn')?.addEventListener('click', handleAnalyze);

  // Clear button
  document.getElementById('clear-btn')?.addEventListener('click', () => {
    document.getElementById('email-input').value = '';
    hideBanner();
    document.getElementById('email-input').focus();
  });

  // File upload
  document.getElementById('file-upload')?.addEventListener('change', handleFileUpload);

  // Banner dismiss
  document.getElementById('auto-detect-dismiss')?.addEventListener('click', hideBanner);

  // Sample dropdown
  const sampleBtn = document.getElementById('sample-btn');
  const sampleMenu = document.getElementById('sample-menu');
  sampleBtn?.addEventListener('click', (e) => {
    e.stopPropagation();
    sampleMenu?.classList.toggle('hidden');
  });
  document.querySelectorAll('.dropdown-item').forEach((item) => {
    item.addEventListener('click', () => {
      const sample = SAMPLE_EMAILS.find((s) => s.id === item.dataset.sample);
      if (sample) {
        document.getElementById('email-input').value = sample.content;
        sampleMenu?.classList.add('hidden');
        hideBanner();
        showToast(`Loaded: ${sample.label}`, 'success');
      }
    });
  });
  document.addEventListener('click', () => sampleMenu?.classList.add('hidden'));

  // Result tabs
  document.querySelectorAll('.result-tab').forEach((tab) => {
    tab.addEventListener('click', () => switchResultTab(tab.dataset.tab));
  });

  // Action bar
  document.getElementById('analyze-another-btn')?.addEventListener('click', async () => {
    // Clear the cache so the next open will run a fresh analysis
    await clearLastCache(document.getElementById('email-input')?.value || '');
    showView('input');
    // Re-attempt auto-detect when user clicks "New Analysis"
    setTimeout(() => autoExtractAndAnalyze(), 100);
  });
  document.getElementById('copy-report-btn')?.addEventListener('click', handleCopyReport);
  document.getElementById('export-pdf-btn')?.addEventListener('click', handleExportPDF);
  document.getElementById('history-btn')?.addEventListener('click', openHistory);
  document.getElementById('history-close-btn')?.addEventListener('click', closeHistory);
  document.getElementById('clear-history-btn')?.addEventListener('click', handleClearHistory);
  document.getElementById('false-positive-btn')?.addEventListener('click', handleFalsePositive);

  // Offline view buttons
  document.getElementById('offline-retry-btn')?.addEventListener('click', async () => {
    showView('input');
    await clearLastCache(document.getElementById('email-input')?.value || '');
    await handleAnalyze();
  });
  document.getElementById('offline-new-btn')?.addEventListener('click', async () => {
    await clearLastCache(document.getElementById('email-input')?.value || '');
    showView('input');
    setTimeout(() => autoExtractAndAnalyze(), 100);
  });
  document.getElementById('offline-copy-btn')?.addEventListener('click', handleCopyReport);
  document.getElementById('offline-log-btn')?.addEventListener('click', openHistory);

  // Keyboard shortcut: Ctrl/Cmd+Enter to analyze
  document.getElementById('email-input')?.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') handleAnalyze();
  });
}

// ─── File Upload Handler ──────────────────────────────────────────────────────
async function handleFileUpload(e) {
  const file = e.target.files?.[0];
  if (!file) return;

  try {
    const text = await file.text();
    document.getElementById('email-input').value = text;
    showToast(`Loaded: ${file.name}`, 'success');
  } catch {
    showToast('Failed to read file', 'error');
  }
  e.target.value = '';
}

// ─── Analyze Handler ─────────────────────────────────────────────────────────
async function handleAnalyze() {
  const emailText = document.getElementById('email-input')?.value?.trim();
  if (!emailText || emailText.length < 10) {
    showToast('No email content found. Open an email in Gmail/Outlook first.', 'error');
    showBanner('error', 'Open an email in Gmail or Outlook, then click the PhishGuard icon.');
    return;
  }

  const settings = collectSettings();
  currentSettings = { ...currentSettings, ...settings };
  await saveSettings(settings);

  showView('loading');
  startLoadingAnimation();

  try {
    // Run rule engine locally
    const { emailData, ruleResult } = await analyzeEmail(emailText);

    // Call LLM via background service worker
    let llmResult;
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'ANALYZE',
        emailText,
        settings,
      });

      if (response.success) {
        llmResult = response.data;
      } else {
        throw new Error(response.error || 'Analysis failed');
      }
    } catch (llmError) {
      if (llmError.message === 'OLLAMA_OFFLINE' || llmError.message?.includes('OLLAMA')) {
        showToast('Ollama offline — using rule engine only', 'error');
      } else {
        showToast(`AI error: ${llmError.message?.slice(0, 50)}`, 'error');
      }
      llmResult = generateOfflineFallback(ruleResult);
    }

    const finalScore = computeFinalScore(llmResult.llmScore, ruleResult.ruleScore);

    currentResult = { emailData, ruleResult, llmResult, finalScore, settings };
    currentAnalysisId = null;

    if (settings.autoSave !== false) {
      const entry = await saveAnalysis(currentResult);
      if (entry) currentAnalysisId = entry.id;
    }

    chrome.runtime.sendMessage({ type: 'UPDATE_BADGE', score: finalScore }).catch(() => {});

    // Route to offline view if AI was unavailable
    if (llmResult._offlineMode) {
      // Don't cache offline results — we want a fresh try when Ollama comes back
      renderOfflineView(ruleResult, finalScore);
      showView('offline');
      hideBanner();
    } else {
      // Cache this result so reopening popup for same email skips re-analysis
      await cacheResult(emailText, currentResult);
      renderResults(currentResult);
      showView('results');
    }

  } catch (err) {
    showToast(`Error: ${err.message?.slice(0, 60)}`, 'error');
    showView('input');
  }
}

// ─── Loading Animation ────────────────────────────────────────────────────────
const LOADING_MESSAGES = [
  'Reading email content...',
  'Extracting email metadata...',
  'Running rule-based checks...',
  'Scanning for lookalike domains...',
  'Analyzing with AI...',
  'Mapping to MITRE ATT&CK...',
  'Generating remediation steps...',
  'Compiling threat report...',
];

function startLoadingAnimation() {
  const bar = document.getElementById('progress-bar');
  const msgEl = document.getElementById('loading-message');
  if (!bar || !msgEl) return;

  bar.style.width = '0%';
  let msgIdx = 0;
  let progress = 0;

  const msgInterval = setInterval(() => {
    msgIdx = (msgIdx + 1) % LOADING_MESSAGES.length;
    msgEl.textContent = LOADING_MESSAGES[msgIdx];
  }, 1200);

  const progressInterval = setInterval(() => {
    progress = Math.min(progress + Math.random() * 8, 92);
    bar.style.width = `${progress}%`;
  }, 500);

  window._phishLoadIntervals = [msgInterval, progressInterval];
  msgEl.textContent = LOADING_MESSAGES[0];
}

function stopLoadingAnimation() {
  if (window._phishLoadIntervals) {
    window._phishLoadIntervals.forEach(clearInterval);
    window._phishLoadIntervals = null;
  }
  const bar = document.getElementById('progress-bar');
  if (bar) bar.style.width = '100%';
}

// ─── View Switching ───────────────────────────────────────────────────────────
function showView(view) {
  document.querySelectorAll('.view').forEach((v) => {
    v.classList.remove('active');
    v.classList.add('hidden');
    v.hidden = true;
  });

  const target = document.getElementById(`${view}-view`);
  if (target) {
    target.classList.add('active');
    target.classList.remove('hidden');
    target.hidden = false;
    // Deferred scroll reset — wait for browser to layout the newly-visible element
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        target.scrollTop = 0;
      });
    });
  }

  if (view !== 'loading') stopLoadingAnimation();
}

// ─── Offline View Renderer ────────────────────────────────────────────────────
function renderOfflineView(ruleResult, finalScore) {
  const scoreEl = document.getElementById('offline-rule-score');
  const verdictEl = document.getElementById('offline-verdict-badge');
  const findingsEl = document.getElementById('offline-findings-list');

  const score = ruleResult?.ruleScore ?? finalScore ?? 0;
  const findings = ruleResult?.findings || [];

  if (scoreEl) scoreEl.textContent = score;

  // Derive verdict + colour from score
  let verdict = 'Safe';
  let verdictClass = 'text-emerald-400 border-emerald-400/50 bg-emerald-400/10';
  if (score >= 86) { verdict = 'Confirmed Phishing'; verdictClass = 'text-error border-error/50 bg-error/10'; }
  else if (score >= 70) { verdict = 'Likely Phishing'; verdictClass = 'text-error border-error/40 bg-error/10'; }
  else if (score >= 40) { verdict = 'Suspicious'; verdictClass = 'text-amber-400 border-amber-400/50 bg-amber-400/10'; }

  if (verdictEl) {
    verdictEl.textContent = verdict.toUpperCase();
    verdictEl.className = `inline-block border px-2 py-0.5 rounded text-[10px] font-bold tracking-widest uppercase mb-2 ${verdictClass}`;
  }

  if (!findingsEl) return;
  findingsEl.innerHTML = '';

  const triggered = findings.filter((f) => !f.passed);
  const safe = findings.filter((f) => f.passed);
  const allToShow = [...triggered, ...safe.slice(0, 2)];

  if (allToShow.length === 0) {
    findingsEl.innerHTML = `<p class="text-[13px] text-on-surface-variant italic text-center py-4">No rule findings available.</p>`;
    return;
  }

  const sanitize = (s) => (s || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  for (const finding of allToShow) {
    const isHigh = finding.severity === 'critical' || finding.severity === 'high';
    const passed = finding.passed;
    const stripColor = passed ? 'bg-emerald-500' : isHigh ? 'bg-error' : 'bg-amber-500';
    const iconColor = passed ? 'text-emerald-400' : isHigh ? 'text-error' : 'text-amber-400';
    const icon = passed ? 'check' : isHigh ? 'warning' : 'info';

    const card = document.createElement('div');
    card.className = 'bg-surface-container border border-outline-variant/15 rounded-lg p-3 relative overflow-hidden';
    card.innerHTML = `
      <div class="absolute left-0 top-0 bottom-0 w-[3px] ${stripColor}"></div>
      <div class="flex items-start gap-2.5">
        <span class="material-symbols-outlined ${iconColor} text-[18px] mt-0.5">${icon}</span>
        <div class="flex-1 min-w-0">
          <p class="text-on-surface text-[13px] font-semibold">${sanitize(finding.name)}</p>
          <p class="text-on-surface-variant text-[12px] leading-relaxed mt-0.5">${sanitize(finding.finding)}</p>
          ${finding.quote && !passed ? `<div class="mt-2 bg-error/5 border border-error/10 rounded p-1.5 font-code-xs text-[11px] ${iconColor} break-words">${sanitize(finding.quote.slice(0, 100))}</div>` : ''}
        </div>
      </div>
    `;
    findingsEl.appendChild(card);
  }
}

// ─── Result Tab Switching ─────────────────────────────────────────────────────
function switchResultTab(tab) {
  document.querySelectorAll('.result-tab').forEach((t) => {
    const active = t.dataset.tab === tab;
    t.classList.toggle('active', active);
    t.classList.toggle('text-primary', active);
    t.classList.toggle('border-b-2', active);
    t.classList.toggle('border-primary', active);
    t.classList.toggle('font-bold', active);
    t.classList.toggle('text-on-secondary-container', !active);
    t.classList.toggle('opacity-60', !active);
    t.setAttribute('aria-selected', active);
  });
  document.querySelectorAll('.result-panel').forEach((p) => {
    const show = p.id === `tab-${tab}`;
    p.classList.toggle('active', show);
    p.classList.toggle('hidden', !show);
    p.hidden = !show;
  });
}

// ─── Score Helpers ────────────────────────────────────────────────────────────
function scoreToClass(score) {
  if (score >= 86) return 'verdict-confirmed';
  if (score >= 70) return 'verdict-likely';
  if (score >= 40) return 'verdict-suspicious';
  return 'verdict-safe';
}

function categoryColor(score) {
  if (score >= 70) return '#ef4444';
  if (score >= 40) return '#f59e0b';
  return '#22c55e';
}

// ─── Render Results ───────────────────────────────────────────────────────────
function renderResults(result) {
  const { finalScore, llmResult, ruleResult, emailData } = result;

  renderGauge(finalScore, llmResult, ruleResult);
  renderSummaryTab(finalScore, llmResult);
  renderFindingsTab(ruleResult, llmResult);
  renderURLsTab(emailData?.urls || []);
  renderHeadersTab(emailData?.headers);
  renderRemediationTab(finalScore, llmResult);

  // Reset to first tab
  switchResultTab('summary');
}

// ─── Gauge ────────────────────────────────────────────────────────────────────
function renderGauge(score, llm, ruleResult) {
  const arc = document.getElementById('gauge-arc');
  const scoreText = document.getElementById('gauge-score-text');
  const verdictBadge = document.getElementById('verdict-badge');
  const aiScoreVal = document.getElementById('ai-score-val');
  const ruleScoreVal = document.getElementById('rule-score-val');
  const riskBadgesEl = document.getElementById('risk-badges');
  const mitreWrap = document.getElementById('mitre-tag-wrap');
  const mitreLink = document.getElementById('mitre-link');
  const mitreText = document.getElementById('mitre-tag-text');
  const summaryVerdict = document.getElementById('summary-verdict-text');
  const summaryConfidence = document.getElementById('summary-confidence');

  const circumference = 141.37;
  const offset = circumference - (score / 100) * circumference;
  if (arc) {
    arc.style.strokeDashoffset = circumference;
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        arc.style.strokeDashoffset = offset;
      });
    });
  }

  if (scoreText) scoreText.textContent = score;

  const verdict = llm?.verdict || scoreToVerdict(score);
  if (verdictBadge) {
    verdictBadge.textContent = verdict.toUpperCase();
    verdictBadge.className = `border px-3 py-1 rounded text-[11px] font-bold tracking-widest uppercase ${scoreToClass(score)}`;
  }

  if (aiScoreVal) aiScoreVal.textContent = llm?.llmScore ?? '—';
  if (ruleScoreVal) ruleScoreVal.textContent = ruleResult?.ruleScore ?? '—';

  if (summaryVerdict) summaryVerdict.textContent = verdict;
  if (summaryConfidence) summaryConfidence.textContent = `${llm?.confidence || 'Medium'} Confidence`;

  if (riskBadgesEl) {
    riskBadgesEl.innerHTML = '';
    if (llm?.becRisk) riskBadgesEl.insertAdjacentHTML('beforeend', '<span class="bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[9px] px-2 py-0.5 rounded uppercase font-bold tracking-wider">BEC RISK</span>');
    if (llm?.spearPhishingRisk) riskBadgesEl.insertAdjacentHTML('beforeend', '<span class="bg-red-500/10 border border-red-500/30 text-red-400 text-[9px] px-2 py-0.5 rounded uppercase font-bold tracking-wider">SPEAR-PHISHING</span>');
    if (llm?.aiGeneratedRisk) riskBadgesEl.insertAdjacentHTML('beforeend', '<span class="bg-primary/10 border border-primary/30 text-primary text-[9px] px-2 py-0.5 rounded uppercase font-bold tracking-wider">AI-GENERATED</span>');
  }

  if (llm?.mitreAttack?.id) {
    if (mitreWrap) mitreWrap.style.display = 'flex';
    if (mitreText) mitreText.textContent = `${llm.mitreAttack.id} — ${llm.mitreAttack.name || 'Phishing'}`;
    if (mitreLink && llm.mitreAttack.url) mitreLink.href = llm.mitreAttack.url;
  } else {
    if (mitreWrap) mitreWrap.style.display = 'none';
  }
}

// ─── Summary Tab ─────────────────────────────────────────────────────────────
function renderSummaryTab(score, llm) {
  const actionEl = document.getElementById('summary-recommended-action');
  if (actionEl) actionEl.textContent = llm?.recommendedAction || '';

  const barsEl = document.getElementById('category-bars');
  if (!barsEl) return;
  barsEl.innerHTML = '';

  const categories = [
    { icon: '🎭', label: 'Impersonation', key: 'impersonation' },
    { icon: '⏰', label: 'Urgency Manipulation', key: 'urgencyManipulation' },
    { icon: '🧠', label: 'Social Engineering', key: 'socialEngineering' },
    { icon: '🔗', label: 'Technical Indicators', key: 'technicalIndicators' },
    { icon: '🤖', label: 'AI-Generated Signs', key: 'aiGeneratedSigns' },
  ];

  for (const cat of categories) {
    const val = llm?.categories?.[cat.key] ?? 0;
    const color = categoryColor(val);
    const row = document.createElement('div');
    row.className = 'flex items-center gap-2 min-w-0';
    row.innerHTML = `
      <span class="text-[14px] text-on-surface-variant w-4 text-center">${cat.icon}</span>
      <span class="text-[12px] font-body-md text-on-surface-variant w-32 truncate min-w-0">${cat.label}</span>
      <div class="flex-1 h-1.5 bg-surface-variant rounded-full overflow-hidden">
        <div class="h-full category-bar-fill transition-all duration-1000 ease-out" style="width: 0%; background:${color};" data-target="${val}"></div>
      </div>
      <span class="text-label-caps font-label-caps w-5 text-right" style="color:${color}">${val}</span>
    `;
    barsEl.appendChild(row);
  }

  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      document.querySelectorAll('.category-bar-fill').forEach((el) => {
        el.style.width = el.dataset.target + '%';
      });
    });
  });

  const noteWrap = document.getElementById('analyst-note-wrap');
  const noteText = document.getElementById('analyst-note-text');
  if (llm?.analystNote) {
    if (noteWrap) noteWrap.style.display = 'flex';
    if (noteText) noteText.textContent = llm.analystNote;
  } else {
    if (noteWrap) noteWrap.style.display = 'none';
  }
}

// ─── Findings Tab ────────────────────────────────────────────────────────────
function renderFindingsTab(ruleResult, llm) {
  const listEl = document.getElementById('rule-findings-list');
  if (!listEl) return;
  listEl.innerHTML = '';

  const findings = ruleResult?.findings || [];
  const sanitize = (str) => str ? str.replace(/</g, '&lt;').replace(/>/g, '&gt;') : '';

  for (const finding of findings) {
    const card = document.createElement('div');
    const isError = finding.severity === 'critical' || finding.severity === 'high';
    const colorClass = finding.passed ? 'text-emerald-400' : isError ? 'text-error' : 'text-amber-400';
    const bgClass = finding.passed ? 'bg-emerald-400' : isError ? 'bg-error' : 'bg-amber-400';
    const icon = finding.passed ? 'check' : isError ? 'warning' : 'info';

    card.className = 'bg-surface-container border border-white/5 rounded-lg p-3 relative overflow-hidden backdrop-blur-md';
    card.innerHTML = `
      <div class="absolute left-0 top-0 bottom-0 w-[3px] ${bgClass}"></div>
      <div class="flex items-start gap-3">
        <span class="material-symbols-outlined ${colorClass} text-[20px] mt-0.5">${icon}</span>
        <div class="flex-1 min-w-0">
          <h3 class="text-on-surface font-semibold text-[14px] mb-1">${sanitize(finding.name)}</h3>
          <p class="text-on-secondary-container text-[13px] leading-relaxed">${sanitize(finding.finding)}</p>
          ${finding.quote && !finding.passed ? `<div class="mt-3 bg-error/5 border border-error/10 rounded p-2 font-code-xs text-[11px] ${colorClass}/80 break-words">${sanitize(finding.quote.slice(0, 120))}</div>` : ''}
        </div>
      </div>
    `;
    listEl.appendChild(card);
  }

  const llmSection = document.getElementById('llm-findings-section');
  const llmList = document.getElementById('llm-findings-list');
  if (llm?.topFindings?.length > 0) {
    if (llmSection) llmSection.style.display = 'block';
    if (llmList) {
      llmList.innerHTML = llm.topFindings.map((f) =>
        `<li>${f.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</li>`
      ).join('');
    }
  } else {
    if (llmSection) llmSection.style.display = 'none';
  }

  const quotesSection = document.getElementById('suspicious-quotes-section');
  const quotesList = document.getElementById('suspicious-quotes-list');
  if (llm?.suspiciousQuotes?.length > 0) {
    if (quotesSection) quotesSection.style.display = 'block';
    if (quotesList) {
      quotesList.innerHTML = llm.suspiciousQuotes.map((q) =>
        `<div class="quote-item">"${q.replace(/</g, '&lt;').replace(/>/g, '&gt;')}"</div>`
      ).join('');
    }
  } else {
    if (quotesSection) quotesSection.style.display = 'none';
  }
}

// ─── URLs Tab ─────────────────────────────────────────────────────────────────
function renderURLsTab(urls) {
  const empty = document.getElementById('urls-empty');
  const tableWrap = document.getElementById('urls-table-wrap');
  const tbody = document.getElementById('urls-tbody');

  if (!urls || urls.length === 0) {
    if (empty) empty.style.display = 'flex';
    if (tableWrap) tableWrap.style.display = 'none';
    return;
  }

  if (empty) empty.style.display = 'none';
  if (tableWrap) tableWrap.style.display = 'flex';
  if (!tbody) return;

  tbody.innerHTML = '';
  const esc = (s) => (s || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  for (const url of urls.slice(0, 30)) {
    const tr = document.createElement('div');
    const displayText = (url.displayText || url.href).slice(0, 40);
    const href = (url.href || '').slice(0, 60);

    const scoreColor = url.riskScore >= 70 ? 'text-error' : url.riskScore >= 40 ? 'text-amber-400' : 'text-emerald-400';
    const bgClass = url.riskScore >= 70 ? 'bg-error' : url.riskScore >= 40 ? 'bg-amber-400' : 'bg-emerald-400';

    tr.className = 'flex px-4 py-3 relative group hover:bg-surface-variant/20 transition-colors border-b border-outline-variant/10 min-w-0';
    tr.innerHTML = `
      <div class="absolute left-0 top-0 bottom-0 w-[3px] ${bgClass} rounded-r opacity-80"></div>
      <div class="w-1/3 text-[12px] text-on-surface-variant opacity-80 truncate pr-2 pt-1" title="${esc(displayText)}">${esc(displayText)}</div>
      <div class="w-1/2 text-code-xs text-primary pt-1 break-all pr-2 relative" title="${esc(href)}">${esc(href)}</div>
      <div class="w-1/6 text-right font-headline-sm font-bold ${scoreColor} pt-1">${url.riskScore}</div>
    `;
    tbody.appendChild(tr);
  }
}

// ─── Headers Tab ─────────────────────────────────────────────────────────────
function renderHeadersTab(headers) {
  const noHeadersMsg = document.getElementById('no-headers-msg');
  const headersContent = document.getElementById('headers-content');

  if (!headers || !headers.hasHeaders) {
    if (noHeadersMsg) noHeadersMsg.style.display = 'flex';
    if (headersContent) headersContent.innerHTML = '';
    return;
  }

  if (noHeadersMsg) noHeadersMsg.style.display = 'none';
  if (!headersContent) return;
  headersContent.innerHTML = '';

  const esc = (s) => (s || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  function authClass(result) {
    if (result === 'pass') return 'auth-pass';
    if (result === 'fail') return 'auth-fail';
    if (result === 'softfail') return 'auth-softfail';
    return 'auth-none';
  }

  function authLabel(result) {
    if (result === 'not-present') return 'Not Present';
    if (result === 'present-unverified') return 'Present';
    return result.toUpperCase();
  }

  const headerRows = [
    { key: 'From', val: headers.fromRaw, flagClass: '' },
    { key: 'To', val: headers.toRaw, flagClass: '' },
    { key: 'Reply-To', val: headers.replyToRaw, flagClass: headers.replyToDiffersFromFrom ? 'text-error font-bold' : '' },
    { key: 'Return-Path', val: headers.returnPathRaw, flagClass: headers.returnPathDiffersFromFrom ? 'text-error font-bold' : '' },
    { key: 'Subject', val: headers.subject, flagClass: '' },
    { key: 'Date', val: headers.date, flagClass: '' },
    { key: 'Message-ID', val: headers.messageId, flagClass: '' },
    { key: 'X-Mailer', val: headers.xMailer, flagClass: '' },
    { key: 'Origin IP', val: headers.firstHopIP || headers.xOriginatingIP, flagClass: '' },
  ].filter((r) => r.val);

  for (const row of headerRows) {
    const div = document.createElement('div');
    div.className = 'flex flex-col gap-1 border-b border-white/5 pb-2 min-w-0';
    div.innerHTML = `
      <span class="text-[10px] font-code-xs text-on-surface-variant/60 uppercase">${row.key}</span>
      <span class="text-[12px] font-code-xs text-on-surface opacity-90 break-all ${row.flagClass}">${esc(row.val)}</span>
    `;
    headersContent.appendChild(div);
  }

  const authDiv = document.createElement('div');
  authDiv.className = 'bg-surface-container/40 backdrop-blur-md border border-white/5 rounded-xl p-3 flex flex-col gap-3 relative mt-3 min-w-0';
  authDiv.innerHTML = `
    <div class="absolute left-0 top-0 bottom-0 w-[3px] bg-primary rounded-l-xl"></div>
    <div class="flex items-center gap-2 mb-1">
      <span class="material-symbols-outlined text-primary text-sm">security</span>
      <h3 class="text-[11px] font-label-caps text-on-surface-variant uppercase">Authentication Status</h3>
    </div>
    <div class="flex flex-wrap gap-2 pt-1">
      <div class="bg-surface-variant/30 border border-outline-variant/30 rounded px-2 py-1 flex items-center gap-1.5">
        <span class="text-[10px] font-code-xs opacity-80">SPF:</span>
        <span class="text-[10px] font-code-xs font-bold text-primary">${authLabel(headers.spfResult)}</span>
      </div>
      <div class="bg-surface-variant/30 border border-outline-variant/30 rounded px-2 py-1 flex items-center gap-1.5">
        <span class="text-[10px] font-code-xs opacity-80">DKIM:</span>
        <span class="text-[10px] font-code-xs font-bold text-primary">${authLabel(headers.dkimResult)}</span>
      </div>
      <div class="bg-surface-variant/30 border border-outline-variant/30 rounded px-2 py-1 flex items-center gap-1.5">
        <span class="text-[10px] font-code-xs opacity-80">DMARC:</span>
        <span class="text-[10px] font-code-xs font-bold text-primary">${authLabel(headers.dmarcResult)}</span>
      </div>
    </div>
  `;
  headersContent.appendChild(authDiv);

  if (headers.replyToDiffersFromFrom) {
    const warn = document.createElement('div');
    warn.className = 'mt-3 bg-error/10 border border-error/30 rounded-lg p-3 text-[12px] text-error flex gap-2';
    warn.innerHTML = '<span class="material-symbols-outlined text-[16px]">warning</span> Reply-To domain differs from From domain — replies would go to a different server!';
    headersContent.appendChild(warn);
  }
}

// ─── Remediation Tab ──────────────────────────────────────────────────────────
function renderRemediationTab(score, llm) {
  const tierBox = document.getElementById('tier-guidance');
  const checklistEl = document.getElementById('remediation-checklist');

  if (tierBox) {
    let cls, icon, text;
    if (score <= 39) {
      cls = 'bg-emerald-500/20 border-emerald-500/40 text-emerald-400';
      icon = 'check_circle';
      text = 'This email appears safe. Normal precautions apply.';
    } else if (score <= 69) {
      cls = 'bg-amber-500/20 border-amber-500/40 text-amber-400';
      icon = 'warning';
      text = 'Exercise caution. Verify the sender via official channels.';
    } else {
      cls = 'bg-error/20 border-error/40 text-error';
      icon = 'error';
      text = 'Confirmed threat. Do not click links or download attachments.';
    }
    tierBox.className = `bg-surface-container border rounded-lg p-3 mb-2 relative overflow-hidden shadow-sm ${cls}`;
    tierBox.innerHTML = `
      <div class="flex gap-3 items-start">
        <span class="material-symbols-outlined mt-0.5" style="font-variation-settings: 'FILL' 1;">${icon}</span>
        <p class="text-[13px] leading-relaxed">${text}</p>
      </div>
    `;
  }

  if (checklistEl) {
    checklistEl.innerHTML = '';
    const steps = llm?.remediationSteps?.length > 0 ? llm.remediationSteps : [
      'Do not click any links or open attachments in this email.',
      'Verify the sender by contacting them through official channels.',
      'Report this email to your IT security or help desk team.',
      'Delete the email from your inbox and trash.'
    ];

    steps.forEach((step, i) => {
      const item = document.createElement('label');
      item.className = 'flex items-start gap-3 p-3 rounded-lg bg-surface-container-low border border-outline-variant/20 hover:bg-surface-variant/20 transition-colors cursor-pointer group min-w-0';
      const esc = (s) => s.replace(/</g, '&lt;').replace(/>/g, '&gt;');
      item.innerHTML = `
        <div class="relative flex items-center justify-center mt-0.5">
          <input type="checkbox" id="check-step-${i}" class="peer appearance-none w-5 h-5 border border-outline rounded bg-surface-container checked:bg-primary checked:border-primary transition-all cursor-pointer">
          <span class="material-symbols-outlined text-on-primary absolute text-[16px] opacity-0 peer-checked:opacity-100 pointer-events-none transition-opacity" style="font-variation-settings: 'FILL' 1;">check</span>
        </div>
        <div class="flex-1">
          <p class="text-[13px] text-on-surface opacity-90 group-hover:opacity-100 transition-opacity">${esc(step)}</p>
        </div>
      `;
      checklistEl.appendChild(item);
    });
  }
}

// ─── Action Bar Handlers ──────────────────────────────────────────────────────
async function handleCopyReport() {
  if (!currentResult) { showToast('No analysis to copy', 'error'); return; }
  const btn = document.getElementById('copy-report-btn');
  try {
    await copyToClipboard(currentResult);
    showToast('Report copied to clipboard!', 'success');
    if (btn) {
      btn.textContent = '✓ Copied!';
      setTimeout(() => {
        btn.innerHTML = '<svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg> Copy Report';
      }, 2000);
    }
  } catch {
    showToast('Copy failed', 'error');
  }
}

function handleExportPDF() {
  if (!currentResult) { showToast('No analysis to export', 'error'); return; }
  try {
    exportPDF(currentResult);
    showToast('PDF opened in new tab — use Ctrl+P to print', 'success');
  } catch {
    showToast('PDF export failed', 'error');
  }
}

async function handleFalsePositive() {
  if (!currentAnalysisId) { showToast('Save analysis first', 'error'); return; }
  await saveFeedback(currentAnalysisId, true);
  showToast('Marked as false positive. Thank you!', 'success');
  const btn = document.getElementById('false-positive-btn');
  if (btn) { btn.textContent = '✓ Marked as False Positive'; btn.disabled = true; }
}

// ─── History Panel ────────────────────────────────────────────────────────────
async function openHistory() {
  const overlay = document.getElementById('history-overlay');
  if (!overlay) return;
  overlay.hidden = false;
  await renderHistory();
}

function closeHistory() {
  const overlay = document.getElementById('history-overlay');
  if (overlay) overlay.hidden = true;
}

async function renderHistory() {
  const listEl = document.getElementById('history-list');
  if (!listEl) return;

  const history = await getHistory();
  listEl.innerHTML = '';

  if (history.length === 0) {
    listEl.innerHTML = `<div class="empty-state"><svg viewBox="0 0 24 24" width="32" height="32" fill="currentColor" class="empty-icon"><path d="M13 3c-4.97 0-9 4.03-9 9H1l3.89 3.89.07.14L9 12H6c0-3.87 3.13-7 7-7s7 3.13 7 7-3.13 7-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42C8.27 19.99 10.51 21 13 21c4.97 0 9-4.03 9-9s-4.03-9-9-9zm-1 5v5l4.28 2.54.72-1.21-3.5-2.08V8H12z"/></svg><p>No analyses yet</p></div>`;
    return;
  }

  for (const entry of history) {
    const item = document.createElement('div');
    item.className = 'history-item';

    const score = entry.finalScore ?? 0;
    const bgColor = score >= 70 ? 'rgba(239,68,68,0.15)' : score >= 40 ? 'rgba(245,158,11,0.15)' : 'rgba(34,197,94,0.15)';
    const textColor = score >= 70 ? '#ef4444' : score >= 40 ? '#f59e0b' : '#22c55e';
    const timestamp = entry.timestamp ? new Date(entry.timestamp).toLocaleDateString('en-US', {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    }) : '—';
    const subject = (entry.subject || 'No Subject').slice(0, 55);

    item.innerHTML = `
      <div class="history-score-badge" style="background:${bgColor};color:${textColor};">${score}</div>
      <div class="history-info">
        <div class="history-subject" title="${subject}">${subject}</div>
        <div class="history-meta">${timestamp} &nbsp;·&nbsp; <span class="history-verdict" style="color:${textColor}">${entry.verdict || 'Unknown'}</span></div>
      </div>
    `;

    item.addEventListener('click', () => {
      if (entry.fullResult) {
        currentResult = entry.fullResult;
        currentAnalysisId = entry.id;
        renderResults(entry.fullResult);
        showView('results');
        closeHistory();
      }
    });

    listEl.appendChild(item);
  }
}

async function handleClearHistory() {
  if (!confirm('Clear all analysis history? This cannot be undone.')) return;
  await clearHistory();
  await renderHistory();
  showToast('History cleared', 'success');
}

// ─── Toast ────────────────────────────────────────────────────────────────────
let toastTimeout;

function showToast(message, type = '') {
  const toast = document.getElementById('toast');
  if (!toast) return;

  clearTimeout(toastTimeout);
  toast.textContent = message;
  
  if (type === 'error') {
    toast.className = 'fixed top-4 left-1/2 -translate-x-1/2 bg-error text-on-error px-4 py-2 rounded-lg shadow-xl border border-error/50 text-[13px] transition-all duration-300 transform z-50';
  } else if (type === 'success') {
    toast.className = 'fixed top-4 left-1/2 -translate-x-1/2 bg-emerald-500 text-white px-4 py-2 rounded-lg shadow-xl border border-emerald-400 text-[13px] transition-all duration-300 transform z-50';
  } else {
    toast.className = 'fixed top-4 left-1/2 -translate-x-1/2 bg-surface-variant text-on-surface px-4 py-2 rounded-lg shadow-xl border border-outline-variant/50 text-[13px] transition-all duration-300 transform z-50';
  }

  toast.classList.add('-translate-y-16', 'opacity-0');

  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      toast.classList.remove('-translate-y-16', 'opacity-0');
      toast.classList.add('translate-y-0', 'opacity-100');
    });
  });

  toastTimeout = setTimeout(() => {
    toast.classList.remove('translate-y-0', 'opacity-100');
    toast.classList.add('-translate-y-16', 'opacity-0');
  }, 3500);
}
