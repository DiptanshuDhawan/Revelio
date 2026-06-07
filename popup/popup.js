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
let currentEmailText = '';
let threatChartInstance = null;

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

  // Update provider badge in idle view
  const badgeText = document.getElementById('provider-badge-text');
  if (badgeText) {
    const prov = currentSettings.provider || 'ollama';
    const provLabel = prov === 'ollama' ? 'Ollama · Local' : prov === 'openai' ? 'OpenAI · Cloud' : 'Gemini · Cloud';
    badgeText.textContent = provLabel;
  }

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
document.getElementById('settings-link').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});


// ─── Ollama Health Check ──────────────────────────────────────────────────────
function startOllamaCheck() {
  checkOllamaStatus();
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'OLLAMA_STATUS') updateOllamaStatus(msg.online);
  });
}

async function checkOllamaStatus() {
  const provider = currentSettings.provider || 'ollama';
  const endpoint = currentSettings.ollamaEndpoint || 'http://localhost:11434';
  const pill = document.getElementById('ollama-status');

  if (provider !== 'ollama') {
    if (pill) setStatusPill(pill, 'online', `${capitalize(provider)}: Ready`);
    return;
  }

  if (pill) {
    setStatusPill(pill, 'checking', 'Checking...');
  }

  try {
    const response = await chrome.runtime.sendMessage({ type: 'CHECK_OLLAMA', endpoint });
    updateOllamaStatus(response?.online);
    
    if (response?.online) {
      const modelsResp = await chrome.runtime.sendMessage({ type: 'GET_OLLAMA_MODELS', endpoint }).catch(() => {});
      if (modelsResp && modelsResp.success && modelsResp.models && modelsResp.models.length > 0) {
        const select = document.getElementById('ollama-model');
        if (select) {
          const currentVal = select.value || currentSettings.ollamaModel;
          select.innerHTML = '';
          modelsResp.models.forEach(m => {
            const opt = document.createElement('option');
            opt.value = m;
            opt.textContent = m;
            select.appendChild(opt);
          });
          if (modelsResp.models.includes(currentVal)) {
            select.value = currentVal;
          } else if (currentSettings.ollamaModel && modelsResp.models.includes(currentSettings.ollamaModel)) {
            select.value = currentSettings.ollamaModel;
          } else {
             select.value = modelsResp.models[0];
          }
        }
      }
    }
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
      currentEmailText = text;
      showBanner('success', 'Email loaded from page selection — analyzing...');
      setTimeout(() => handleAnalyze(text), 300);
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

  // Show scanning state in idle view
  const setIdleState = (title, msg, variant = 'scanning') => {
    const titleEl = document.getElementById('idle-status-title');
    const msgEl = document.getElementById('idle-status-msg');
    const svgEl = document.getElementById('scan-icon-svg');
    const containerEl = document.getElementById('scan-icon-container');
    if (titleEl) titleEl.textContent = title;
    if (msgEl) msgEl.textContent = msg;
    // Update icon color per variant
    if (svgEl) {
      svgEl.style.color = variant === 'error' ? '#ef4444'
        : variant === 'scanning' ? '#f59e0b'
        : '#38bdf8';
    }
  };

  setIdleState('Scanning...', 'Detecting email in current tab...', 'scanning');

  const url = tab.url;
  const isMailPage =
    url.includes('mail.google.com') ||
    url.includes('outlook.live.com') ||
    url.includes('outlook.office.com') ||
    url.includes('outlook.office365.com');

  if (!isMailPage) {
    setIdleState('Not a Mail Page', 'Open Gmail or Outlook in a tab and click Force Rescan.', 'error');
    return;
  }

  // Ping content script to confirm it’s injected
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
      setIdleState('Could Not Connect', 'Try reloading the Gmail/Outlook tab, then click Force Rescan.', 'error');
      return;
    }
  }

  if (!ping?.pong) {
    setIdleState('Content Script Not Responding', 'Reload Gmail/Outlook and try again.', 'error');
    return;
  }

  // Request email extraction
  const extracted = await chrome.tabs.sendMessage(tab.id, { type: 'EXTRACT_EMAIL' });
  if (!extracted || !extracted.emailText) {
    setIdleState('No Email Detected', 'Open a specific email (not just the inbox) and click Force Rescan.', 'error');
    return;
  }

  currentEmailText = extracted.emailText;

  // ── Cache check: if this exact email was already analyzed, show cached result ──
  const cached = await getCachedResult(currentEmailText);
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
    const msgEl = document.getElementById('idle-status-msg');
    if (msgEl) msgEl.textContent = '✓ Showing cached result — click "Analyze Another" to re-scan';
    return;
  }

  // ── Active Background Scan check: if passive scan is running, hook into it ──
  showView('loading');
  startLoadingAnimation();
  const activeCheck = await chrome.runtime.sendMessage({ type: 'CHECK_ACTIVE_SCAN', emailText: currentEmailText }).catch(() => ({}));
  if (activeCheck && activeCheck.active) {
    if (activeCheck.result) {
      currentResult = activeCheck.result;
      if (currentResult.llmResult?._offlineMode) {
        renderOfflineView(currentResult.ruleResult, currentResult.finalScore);
        showView('offline');
        hideBanner();
      } else {
        renderResults(currentResult);
        showView('results');
      }
    } else {
      setIdleState('Analysis Failed', 'Background scan failed.', 'error');
    }
    return;
  }

  const sourceLabel = extracted.source === 'gmail'
    ? 'Gmail email detected'
    : extracted.source === 'outlook'
    ? 'Outlook email detected'
    : 'Email detected';

  const msgEl = document.getElementById('idle-status-msg');
  if (msgEl) msgEl.textContent = `${sourceLabel}. Analyzing...`;

  // Small visual pause so the user sees the banner before loading screen
  await sleep(400);

  // Fire analysis automatically
  await handleAnalyze(currentEmailText);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ─── Populate Settings from Storage ──────────────────────────────────────────
function populateSettingsFromStorage(settings) {
  const ollamaModel = document.getElementById('ollama-model');

  if (ollamaModel) {
    const saved = settings.ollamaModel || '';
    if (saved) {
      // Add it as a temporary option if not present, will be replaced when models are fetched
      if (!Array.from(ollamaModel.options).some(opt => opt.value === saved)) {
        const opt = document.createElement('option');
        opt.value = saved;
        opt.textContent = saved;
        ollamaModel.appendChild(opt);
      }
      ollamaModel.value = saved;
    }
  }
}

// ─── Collect Settings from UI ─────────────────────────────────────────────────
function collectSettings() {
  return currentSettings;
}

// ─── Main Event Listeners ─────────────────────────────────────────────────────
function attachEventListeners() {
  // Provider tabs (for future use)
  document.querySelectorAll('.provider-tab').forEach((tab) => {
    tab.addEventListener('click', () => switchProviderTab(tab.dataset.provider));
  });

  // Rescan button
  document.getElementById('rescan-btn')?.addEventListener('click', () => {
    // Reset status UI
    document.getElementById('idle-status-title').textContent = 'Auto-Scan Active';
    document.getElementById('idle-status-msg').textContent = 'Open an email in Gmail or Outlook. Revelio will automatically scan it for threats.';
    autoExtractAndAnalyze();
  });

  // Banner dismiss
  document.getElementById('auto-detect-dismiss')?.addEventListener('click', hideBanner);

  // Result tabs
  document.querySelectorAll('.result-tab').forEach((tab) => {
    tab.addEventListener('click', () => switchResultTab(tab.dataset.tab));
  });

  // Action bar
  document.getElementById('analyze-another-btn')?.addEventListener('click', async () => {
    await clearLastCache(currentEmailText);
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
    await clearLastCache(currentEmailText);
    await handleAnalyze(currentEmailText);
  });
  document.getElementById('offline-new-btn')?.addEventListener('click', async () => {
    await clearLastCache(currentEmailText);
    showView('input');
    setTimeout(() => autoExtractAndAnalyze(), 100);
  });
  document.getElementById('offline-copy-btn')?.addEventListener('click', handleCopyReport);
  document.getElementById('offline-log-btn')?.addEventListener('click', openHistory);
}

// ─── Analyze Handler ─────────────────────────────────────────────────────────
async function handleAnalyze(textToAnalyze) {
  const emailText = textToAnalyze || currentEmailText;
  if (!emailText || emailText.length < 10) {
    showToast('No email content found. Open an email in Gmail/Outlook first.', 'error');
    showBanner('error', 'Open an email in Gmail or Outlook, then click the PhishGuard icon.');
    return;
  }

  const freshSettings = await getSettings();
  currentSettings = freshSettings;

  showView('loading');
  startLoadingAnimation();

  try {
    // Trigger background scan and wait for the result
    const response = await chrome.runtime.sendMessage({
      type: 'MANUAL_SCAN',
      emailText: emailText,
      source: 'manual'
    });

    if (!response || !response.success) {
      throw new Error(response ? response.error : 'Background scan failed');
    }

    currentResult = response.data;
    // Inject the settings the popup needs
    currentResult.settings = freshSettings;
    currentAnalysisId = null; // Will fetch from history if needed

    // Route to offline view if AI was unavailable
    if (currentResult.llmResult && currentResult.llmResult._offlineMode) {
      renderOfflineView(currentResult.ruleResult, currentResult.finalScore);
      showView('offline');
      hideBanner();
    } else {
      renderResults(currentResult);
      showView('results');
    }

  } catch (err) {
    showToast(`Error: ${err.message?.slice(0, 60)}`, 'error');
    // Show idle screen so user can Force Rescan
    const title = document.getElementById('idle-status-title');
    const msg = document.getElementById('idle-status-msg');
    if (title) title.textContent = 'Analysis Failed';
    if (msg) msg.textContent = err.message?.slice(0, 120) || 'An error occurred.';
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
  // Switch to the skeleton loading view
  showView('loading');

  // Show loading section, hide idle bottom
  const loadingSection = document.getElementById('loading-section');
  const idleBottom = document.getElementById('idle-bottom');
  if (loadingSection) loadingSection.style.display = 'flex';
  if (idleBottom) idleBottom.style.display = 'none';

  // Start rotating the disc (bob animation on icon-disc)
  const iconDisc = document.getElementById('icon-disc');
  if (iconDisc) iconDisc.style.animation = 'scanBob 1.8s ease-in-out infinite';

  // Speed up radar rings to look more active
  const ring1 = document.getElementById('radar-ring-1');
  const ring2 = document.getElementById('radar-ring-2');
  if (ring1) ring1.style.animation = 'radarPing 1.2s ease-out infinite';
  if (ring2) ring2.style.animation = 'radarPing 1.2s ease-out 0.4s infinite';

  // Cycle title through loading messages
  const bar = document.getElementById('progress-bar');
  const msgEl = document.getElementById('idle-status-title');
  const subMsgEl = document.getElementById('idle-status-msg');

  if (bar) bar.style.width = '0%';
  if (subMsgEl) subMsgEl.textContent = '';

  let msgIdx = 0;
  let progress = 0;

  const msgInterval = setInterval(() => {
    msgIdx = (msgIdx + 1) % LOADING_MESSAGES.length;
    if (msgEl) msgEl.textContent = LOADING_MESSAGES[msgIdx];
  }, 1200);

  const progressInterval = setInterval(() => {
    progress = Math.min(progress + Math.random() * 8, 92);
    if (bar) bar.style.width = `${progress}%`;
  }, 500);

  window._phishLoadIntervals = [msgInterval, progressInterval];
  if (msgEl) msgEl.textContent = LOADING_MESSAGES[0];
}

function stopLoadingAnimation() {
  if (window._phishLoadIntervals) {
    window._phishLoadIntervals.forEach(clearInterval);
    window._phishLoadIntervals = null;
  }
  const bar = document.getElementById('progress-bar');
  if (bar) bar.style.width = '100%';

  // Restore idle mode UI
  const loadingSection = document.getElementById('loading-section');
  const idleBottom = document.getElementById('idle-bottom');
  const iconDisc = document.getElementById('icon-disc');
  const ring1 = document.getElementById('radar-ring-1');
  const ring2 = document.getElementById('radar-ring-2');
  const subMsgEl = document.getElementById('idle-status-msg');

  if (loadingSection) loadingSection.style.display = 'none';
  if (idleBottom) idleBottom.style.display = 'flex';
  if (iconDisc) iconDisc.style.animation = '';
  if (ring1) ring1.style.animation = 'radarPing 2s ease-out infinite';
  if (ring2) ring2.style.animation = 'radarPing 2s ease-out 0.7s infinite';
  // Restore idle description
  if (subMsgEl && !subMsgEl.textContent.trim()) {
    subMsgEl.textContent = 'Open an email in Gmail or Outlook — Revelio will automatically detect and analyze it for threats.';
  }
}

// ─── View Switching ───────────────────────────────────────────────────────────
function showView(view) {
  const resolvedView = view;

  document.querySelectorAll('.view').forEach((v) => {
    v.classList.remove('active');
    v.classList.add('hidden');
    v.hidden = true;
  });

  const target = document.getElementById(`${resolvedView}-view`);
  if (target) {
    target.classList.add('active');
    target.classList.remove('hidden');
    target.hidden = false;
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        target.scrollTop = 0;
      });
    });
  }

  // Stop animation when leaving the loading state
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

  const sanitize = (s) => {
    if (typeof s === 'object') s = JSON.stringify(s);
    return String(s || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  };

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
function getThresholds(sensitivity = 50) {
  const offset = (sensitivity - 50) * 0.4;
  return {
    confirmed: Math.max(0, Math.min(100, 86 + offset)),
    likely: Math.max(0, Math.min(100, 70 + offset)),
    suspicious: Math.max(0, Math.min(100, 40 + offset))
  };
}

function scoreToClass(score) {
  const t = getThresholds(currentSettings?.sensitivityThreshold);
  if (score >= t.confirmed) return 'verdict-confirmed';
  if (score >= t.likely) return 'verdict-likely';
  if (score >= t.suspicious) return 'verdict-suspicious';
  return 'verdict-safe';
}

function categoryColor(score) {
  const t = getThresholds(currentSettings?.sensitivityThreshold);
  if (score >= t.likely) return '#ef4444';
  if (score >= t.suspicious) return '#f59e0b';
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

  const verdict = scoreToVerdict(score, currentSettings?.sensitivityThreshold);
  if (verdictBadge) {
    verdictBadge.textContent = verdict.toUpperCase();
    verdictBadge.className = `border px-3 py-1 rounded text-[11px] font-bold tracking-widest uppercase ${scoreToClass(score)}`;
  }

  const attackVectorBadge = document.getElementById('attack-vector-badge');
  if (attackVectorBadge) {
    if (llm?.attackVector && llm.attackVector.toLowerCase() !== 'unknown' && llm.attackVector.toLowerCase() !== 'n/a') {
      attackVectorBadge.textContent = llm.attackVector.toUpperCase();
      attackVectorBadge.style.display = 'inline-block';
      const t = getThresholds(currentSettings?.sensitivityThreshold);
      attackVectorBadge.style.color = score >= t.likely ? '#EF4444' : score >= t.suspicious ? '#F59E0B' : '#10B981';
      attackVectorBadge.style.borderColor = score >= t.likely ? 'rgba(239, 68, 68, 0.3)' : score >= t.suspicious ? 'rgba(245, 158, 11, 0.3)' : 'rgba(16, 185, 129, 0.3)';
      attackVectorBadge.style.backgroundColor = score >= t.likely ? 'rgba(239, 68, 68, 0.1)' : score >= t.suspicious ? 'rgba(245, 158, 11, 0.1)' : 'rgba(16, 185, 129, 0.1)';
    } else {
      attackVectorBadge.style.display = 'none';
    }
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
  const stripEl = document.getElementById('summary-threat-strip');
  if (stripEl) {
    const t = getThresholds(currentSettings?.sensitivityThreshold);
    const sev = score >= t.likely ? 'danger' : score >= t.suspicious ? 'warn' : 'safe';
    stripEl.className = `threat-strip ${sev}`;
  }

  const verdictEl = document.getElementById('summary-verdict-text');
  if (verdictEl) {
    const verdict = scoreToVerdict(score, currentSettings?.sensitivityThreshold);
    verdictEl.textContent = verdict;
    const t = getThresholds(currentSettings?.sensitivityThreshold);
    const color = score >= t.likely ? '#EF4444' : score >= t.suspicious ? '#F59E0B' : '#10B981';
    verdictEl.style.color = color;
  }

  const actionEl = document.getElementById('summary-recommended-action');
  if (actionEl) actionEl.textContent = llm?.recommendedAction || '';

  const aiCardEl = document.getElementById('ai-analysis-card');
  const aiNarrativeEl = document.getElementById('ai-threat-narrative');
  const aiBecWrapEl = document.getElementById('ai-bec-details-wrap');
  const aiBecTextEl = document.getElementById('ai-bec-details-text');
  const analystNoteWrap = document.getElementById('analyst-note-wrap');
  const analystNoteText = document.getElementById('analyst-note-text');
  
  if (aiCardEl) {
    if (llm?.threatNarrative || llm?.analystNote) {
      aiCardEl.style.display = 'block';
      if (aiNarrativeEl) aiNarrativeEl.textContent = llm.threatNarrative || 'No narrative provided.';
      
      if (llm?.becRisk && llm?.becDetails) {
        if (aiBecWrapEl) aiBecWrapEl.style.display = 'block';
        if (aiBecTextEl) aiBecTextEl.textContent = llm.becDetails;
      } else {
        if (aiBecWrapEl) aiBecWrapEl.style.display = 'none';
      }
      
      if (llm?.analystNote) {
        if (analystNoteWrap) analystNoteWrap.style.display = 'flex';
        if (analystNoteText) analystNoteText.textContent = llm.analystNote;
      } else {
        if (analystNoteWrap) analystNoteWrap.style.display = 'none';
      }
    } else {
      aiCardEl.style.display = 'none';
    }
  }

  const chartCanvas = document.getElementById('threat-radar-chart');
  if (!chartCanvas) return;

  const isDarkMode = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const ctx = chartCanvas.getContext('2d');

  const categories = [
    { id: 'IMP', full: 'Impersonation', key: 'impersonation' },
    { id: 'URG', full: 'Urgency', key: 'urgencyManipulation' },
    { id: 'SOC', full: 'Social engineering', key: 'socialEngineering' },
    { id: 'TECH', full: 'Tech. deception', key: 'technicalIndicators' },
    { id: 'AI', full: 'AI-generated', key: 'aiGeneratedSigns' },
  ];

  const dataValues = categories.map(cat => llm?.categories?.[cat.key] ?? 0);

  // Dynamic Theme Colors (Cyan/Primary theme matching project)
  const fillColor = isDarkMode ? 'rgba(56, 189, 248, 0.20)' : 'rgba(14, 165, 233, 0.15)';
  const borderColor = isDarkMode ? '#38bdf8' : '#0ea5e9';
  const pointBg = borderColor;
  const pointBorder = isDarkMode ? '#1a1a1a' : '#ffffff';
  const gridColor = isDarkMode ? 'rgba(255,255,255,0.12)' : 'rgba(0,0,0,0.08)';
  const tickColor = isDarkMode ? 'rgba(255,255,255,0.5)' : 'rgba(0,0,0,0.5)';

  if (threatChartInstance) {
    threatChartInstance.destroy();
  }

  // Fallback to window.Chart (loaded via script tag in HTML)
  if (window.Chart) {
    threatChartInstance = new window.Chart(ctx, {
      type: 'radar',
      data: {
        labels: categories.map(c => c.full),
        datasets: [{
          data: dataValues,
          backgroundColor: fillColor,
          borderColor: borderColor,
          borderWidth: 2,
          pointBackgroundColor: pointBg,
          pointBorderColor: pointBorder,
          pointRadius: 4,
          pointHoverRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          r: {
            min: 0,
            max: 100,
            ticks: {
              stepSize: 25,
              color: tickColor,
              backdropColor: 'transparent',
              font: { size: 9, family: 'Inter, sans-serif', weight: '600' }
            },
            grid: { color: gridColor },
            angleLines: { color: gridColor },
            pointLabels: {
              color: tickColor,
              font: { size: 10, family: 'Inter, sans-serif', weight: '600' }
            }
          }
        }
      }
    });
  }
}

// ─── Findings Tab ────────────────────────────────────────────────────────────
function renderFindingsTab(ruleResult, llm) {
  const listEl = document.getElementById('rule-findings-list');
  if (!listEl) return;
  listEl.innerHTML = '';

  const findings = ruleResult?.findings || [];
  const sanitize = (str) => {
    if (typeof str === 'object') str = JSON.stringify(str);
    return String(str || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  };

  for (const finding of findings) {
    const card = document.createElement('div');
    const isError = finding.severity === 'critical' || finding.severity === 'high';
    const severity = finding.passed ? 'safe' : isError ? (finding.severity === 'critical' ? 'critical' : 'high') : 'medium';

    const iconColor = finding.passed ? 'text-emerald-400' : isError ? 'text-error' : 'text-amber-400';
    const titleColor = finding.passed ? 'text-emerald-400' : isError ? 'text-error' : 'text-on-surface';
    const icon = finding.passed ? 'check_circle' : isError ? 'warning' : 'info';
    const pillText = finding.passed ? 'SAFE' : finding.severity.toUpperCase();

    card.className = 'glass-panel relative overflow-hidden p-3 flex flex-col gap-1.5';
    card.innerHTML = `
      <div class="finding-strip ${severity}"></div>
      <div class="flex items-start gap-2.5 ml-2">
        <span class="material-symbols-outlined ${iconColor} text-[18px] mt-0.5" style="font-variation-settings: 'FILL' 1;">${icon}</span>
        <div class="flex-1 min-w-0">
          <div class="flex justify-between items-start gap-2 mb-0.5">
            <div class="flex items-center gap-1.5 min-w-0">
              <h3 class="${titleColor} font-semibold text-[13px] leading-tight truncate">${sanitize(finding.name)}</h3>
              <span class="source-badge rule shrink-0">⚙️ Rules</span>
            </div>
            <span class="finding-severity-pill ${severity} shrink-0">${pillText}</span>
          </div>
          <p class="text-on-surface-variant text-[12px] leading-relaxed opacity-90">${sanitize(finding.finding)}</p>
          ${finding.quote && !finding.passed ? `<div class="mt-1.5 finding-quote-block">${sanitize(finding.quote.slice(0, 120))}</div>` : ''}
        </div>
      </div>
    `;
    listEl.appendChild(card);
  }

  const llmSection = document.getElementById('llm-findings-section');
  const llmList = document.getElementById('llm-findings-list');
  if (llm?.topFindings?.length > 0) {
    if (llmSection) llmSection.style.display = 'flex';
    if (llmList) {
      llmList.innerHTML = '';
      llm.topFindings.forEach((f) => {
        let title = 'AI Finding';
        let detail = '';
        let severity = 'medium';
        
        if (typeof f === 'string') {
          detail = f;
        } else {
          title = f.title || title;
          detail = f.detail || detail;
          severity = f.severity?.toLowerCase() || severity;
        }

        const isError = severity === 'critical' || severity === 'high';
        const sevClass = isError ? (severity === 'critical' ? 'critical' : 'high') : severity;
        const iconColor = isError ? 'text-error' : severity === 'medium' ? 'text-amber-400' : 'text-emerald-400';
        const titleColor = isError ? 'text-error' : severity === 'medium' ? 'text-amber-400' : 'text-on-surface';
        const icon = isError ? 'warning' : severity === 'medium' ? 'info' : 'check_circle';
        const pillText = severity.toUpperCase();

        const card = document.createElement('div');
        card.className = 'ai-finding-card glass-panel relative overflow-hidden p-3 flex flex-col gap-1.5';
        card.innerHTML = `
          <div class="finding-strip ${sevClass}"></div>
          <div class="flex items-start gap-2.5 ml-2">
            <span class="material-symbols-outlined ${iconColor} text-[18px] mt-0.5" style="font-variation-settings: 'FILL' 1;">${icon}</span>
            <div class="flex-1 min-w-0">
              <div class="flex justify-between items-start gap-2 mb-0.5">
                <div class="flex items-center gap-1.5 min-w-0">
                  <h3 class="${titleColor} font-semibold text-[13px] leading-tight truncate">${sanitize(title)}</h3>
                  <span class="source-badge ai shrink-0">🤖 AI</span>
                </div>
                <span class="finding-severity-pill ${sevClass} shrink-0">${pillText}</span>
              </div>
              <p class="text-on-surface-variant text-[12px] leading-relaxed opacity-90">${sanitize(detail)}</p>
            </div>
          </div>
        `;
        llmList.appendChild(card);
      });
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
  const wrap = document.getElementById('urls-content-wrap');
  const container = document.getElementById('urls-cards-container');

  if (!urls || urls.length === 0) {
    if (empty) empty.style.display = 'flex';
    if (wrap) wrap.style.display = 'none';
    return;
  }

  if (empty) empty.style.display = 'none';
  if (wrap) wrap.style.display = 'flex';
  if (!container) return;

  const total = urls.length;
  let mal = 0, susp = 0, safe = 0;
  urls.forEach(u => {
    if (u.safetyVerdict === 'malicious') mal++;
    else if (u.safetyVerdict === 'suspicious') susp++;
    else safe++;
  });

  const $ = id => document.getElementById(id);
  if ($('urls-total-count')) $('urls-total-count').textContent = `${total} URLs Found`;
  if ($('urls-malicious-count')) $('urls-malicious-count').textContent = mal;
  if ($('urls-suspicious-count')) $('urls-suspicious-count').textContent = susp;
  if ($('urls-safe-count')) $('urls-safe-count').textContent = safe;

  container.innerHTML = '';
  const esc = (s) => (s || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  urls.slice(0, 30).forEach((url, i) => {
    const card = document.createElement('div');
    const isMal = url.safetyVerdict === 'malicious';
    const isSusp = url.safetyVerdict === 'suspicious';
    const severity = isMal ? 'malicious' : isSusp ? 'suspicious' : 'safe';
    
    const textColor = isMal ? 'text-error' : isSusp ? 'text-amber-500' : 'text-emerald-500';
    
    let tagsHtml = '';
    if (url.riskTags && url.riskTags.length) {
      tagsHtml = url.riskTags.map(tag => 
        `<span class="url-risk-tag ${textColor}">${esc(tag)}</span>`
      ).join('');
    }

    let apiResultsHtml = '';
    if (url.safeBrowsingResult || url.virusTotalResult) {
      apiResultsHtml += '<div class="mt-2 pt-2 border-t border-outline-variant/20 flex flex-col gap-1 text-[11px]">';
      if (url.safeBrowsingResult) {
        if (!url.safeBrowsingResult.isSafe) {
          apiResultsHtml += `<div class="text-error font-bold flex items-center gap-1"><span class="material-symbols-outlined text-[14px]">shield</span> Safe Browsing: ${url.safeBrowsingResult.threatType}</div>`;
        } else if (url.safeBrowsingResult.error) {
          apiResultsHtml += `<div class="text-on-surface-variant flex items-center gap-1"><span class="material-symbols-outlined text-[14px]">shield</span> Safe Browsing: ${url.safeBrowsingResult.error}</div>`;
        } else {
          apiResultsHtml += `<div class="text-emerald-500 flex items-center gap-1"><span class="material-symbols-outlined text-[14px]">shield</span> Safe Browsing: Clean</div>`;
        }
      }
      if (url.virusTotalResult) {
        if (url.virusTotalResult.error || url.virusTotalResult.status === 'not_found' || url.virusTotalResult.status === 'submitted') {
          apiResultsHtml += `<div class="text-on-surface-variant flex items-center gap-1"><span class="material-symbols-outlined text-[14px]">security</span> VirusTotal: ${url.virusTotalResult.message || url.virusTotalResult.error || 'Error'}</div>`;
        } else {
          const det = url.virusTotalResult.totalDetected || 0;
          const tot = url.virusTotalResult.totalEngines || 0;
          const vtColor = det > 0 ? 'text-error font-bold' : 'text-emerald-500';
          apiResultsHtml += `<div class="${vtColor} flex items-center gap-1"><span class="material-symbols-outlined text-[14px]">security</span> VirusTotal: ${det}/${tot} security vendors flagged this</div>`;
          if (det > 0 && url.virusTotalResult.detectingEngines) {
            const engineBadges = url.virusTotalResult.detectingEngines.map(engineStr => {
              const [name, result] = engineStr.split(': ');
              const isMal = result === 'malicious';
              const badgeClass = isMal ? 'bg-error/10 border-error/30 text-error' : 'bg-amber-500/10 border-amber-500/30 text-amber-500';
              return `<span class="px-1.5 py-0.5 border rounded text-[9px] font-bold ${badgeClass}">${esc(name)}</span>`;
            }).join('');
            apiResultsHtml += `<div class="flex flex-wrap gap-1 mt-1 ml-5">${engineBadges}</div>`;
          }
        }
      }
      apiResultsHtml += '</div>';
    }

    card.className = 'glass-panel relative overflow-hidden p-3 flex flex-col gap-1.5';
    card.innerHTML = `
      <div class="flex items-start gap-3">
        <div class="url-status-dot ${severity} mt-1.5"></div>
        <div class="flex-1 min-w-0">
          <div class="flex justify-between items-start gap-2 mb-1.5">
            <div class="font-bold ${textColor} text-[11px] uppercase tracking-wider font-code-xs">${url.safetyVerdict}</div>
            <div class="text-[9px] font-code-xs text-on-surface-variant border border-white/10 rounded px-1.5 py-0.5 bg-white/5 flex-shrink-0">Score: ${url.riskScore}</div>
          </div>
          <div class="text-[12px] text-on-surface-variant mb-1 truncate">
            <span class="text-outline opacity-80">Display: </span>${esc(url.displayText)}
          </div>
          <div class="text-code-xs text-primary break-all mb-2 opacity-90 leading-relaxed">${esc(url.href)}</div>
          ${tagsHtml ? `<div class="flex flex-wrap gap-1 mb-2">${tagsHtml}</div>` : ''}
          ${apiResultsHtml}
          <div class="mt-2 pt-2 border-t border-white/5">
            <button class="check-safety-btn deep-scan-btn" data-idx="${i}">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:middle;margin-right:5px;opacity:0.8;">
                <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                <line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/>
              </svg>
              Deep Scan (Safe Browsing + VirusTotal)
            </button>
          </div>
        </div>
      </div>
    `;

    container.appendChild(card);
  });

  // Attach button listeners
  container.querySelectorAll('.check-safety-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const idx = parseInt(e.currentTarget.dataset.idx, 10);
      const url = urls[idx];
      
      // Proceed immediately to scan
      
      e.currentTarget.disabled = true;
      e.currentTarget.innerHTML = `
        <span style="display:inline-flex;align-items:center;gap:7px;">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="deep-scan-spinning">
            <circle cx="12" cy="12" r="3"/>
            <path d="M12 2v3M12 19v3M4.22 4.22l2.12 2.12M17.66 17.66l2.12 2.12M2 12h3M19 12h3M4.22 19.78l2.12-2.12M17.66 6.34l2.12-2.12"/>
          </svg>
          <span style="letter-spacing:0.06em;">Scanning URLs<span class="scan-dots"></span></span>
        </span>
      `;

      
      try {
        // Run Safe Browsing
        const sbRes = await new Promise(resolve => {
          chrome.runtime.sendMessage({ type: 'CHECK_URL_SAFETY', url: url.href }, res => resolve(res));
        });
        if (sbRes && sbRes.success && sbRes.data) {
          url.safeBrowsingResult = sbRes.data;
          if (sbRes.data.isSafe === false) url.safetyVerdict = 'malicious';
        }

        // Run VirusTotal
        const vtRes = await new Promise(resolve => {
          chrome.runtime.sendMessage({ type: 'DEEP_SCAN_URL', url: url.href }, res => resolve(res));
        });
        if (vtRes && vtRes.success && vtRes.data) {
          url.virusTotalResult = vtRes.data;
          if (vtRes.data.totalDetected > 0) url.safetyVerdict = 'malicious';
        }
      } catch (err) {
        console.error('URL Scan failed', err);
      }
      
      // Save the updated analysis to cache so it persists when re-opening popup
      if (window.currentResult) {
        window.currentResult.emailData.urls = urls;
        if (window.currentAnalysisId) {
          // This would require importing saveAnalysisToCache, but since we modify urls in-place,
          // it might persist if we just re-render. Let's just re-render for now.
        }
      }
      
      renderURLsTab(urls);
    });
  });
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
    const isDanger = score > 69;
    const isWarn = score > 39 && score <= 69;
    const cls = isDanger ? 'danger' : isWarn ? 'warn' : 'safe';
    const icon = isDanger ? 'warning' : isWarn ? 'warning' : 'check_circle';
    const title = isDanger ? 'Confirmed threat.' : isWarn ? 'Exercise caution.' : 'Email appears safe.';
    const subtitle = isDanger
      ? 'Delete immediately. Do not interact with links or attachments.'
      : isWarn
        ? 'Verify the sender via official channels before taking any action.'
        : 'Normal precautions apply. No immediate action required.';
    const iconColor = isDanger ? 'text-error' : isWarn ? 'text-amber-400' : 'text-emerald-400';
    const titleColor = isDanger ? 'text-error' : isWarn ? 'text-amber-400' : 'text-emerald-400';

    tierBox.className = `glass-panel${isDanger ? ' threat-pulse' : ''} relative overflow-hidden p-3 flex flex-col gap-1.5 mb-0`;
    tierBox.innerHTML = `
      ${isDanger ? '<div class="threat-strip danger"></div>' : isWarn ? '<div class="threat-strip warn"></div>' : '<div class="threat-strip safe"></div>'}
      <div class="flex items-center gap-2 ml-2">
        <span class="material-symbols-outlined ${iconColor} text-xl" style="font-variation-settings: 'FILL' 1;">${icon}</span>
        <h2 class="text-headline-sm font-headline-sm ${titleColor} font-bold">${title}</h2>
      </div>
      <p class="text-body-md font-body-md text-on-surface-variant ml-2 opacity-90">${subtitle}</p>
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

    // Fallback subtitles per step
    const fallbackSubs = [
      'Remove from inbox to prevent accidental clicks.',
      'Verify account status via official channels, not links provided.',
      'Contact your help desk or CISO immediately.',
      'Remove from trash as well to fully purge.'
    ];

    const wrapper = document.createElement('div');
    wrapper.className = 'glass-panel p-0 overflow-hidden flex flex-col';
    wrapper.innerHTML = `
      <div class="px-3 py-2 border-b border-white/5 flex items-center justify-between" style="background: rgba(37, 43, 46, 0.5);">
        <h3 class="text-[13px] font-headline-sm text-on-surface font-semibold">Remediation Plan</h3>
        <span class="text-code-xs font-code-xs text-outline">Action Required</span>
      </div>
      <div id="remediation-steps-inner" class="p-2 flex flex-col gap-1"></div>
    `;
    checklistEl.appendChild(wrapper);

    const stepsInner = wrapper.querySelector('#remediation-steps-inner');
    const esc = (s) => s.replace(/</g, '&lt;').replace(/>/g, '&gt;');

    steps.forEach((step, i) => {
      // First step gets error color (most urgent)
      const isUrgent = i === 0 && (llm?.remediationSteps?.length > 0 ? false : true);
      const stepTextColor = isUrgent ? 'text-error' : 'text-on-surface';

      const item = document.createElement('label');
      item.className = 'flex items-start gap-2.5 p-2.5 rounded-lg hover:bg-white/5 transition-colors cursor-pointer group';
      item.innerHTML = `
        <input type="checkbox" class="cyber-checkbox mt-0.5" id="check-step-${i}">
        <div class="flex flex-col checkbox-label">
          <span class="text-body-md font-body-md ${stepTextColor} font-medium">${esc(step)}</span>
          ${fallbackSubs[i] ? `<span class="text-code-xs font-code-xs text-outline mt-1">${esc(fallbackSubs[i])}</span>` : ''}
        </div>
      `;
      stepsInner.appendChild(item);
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
