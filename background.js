// Revelio — Background Service Worker (Manifest V3)
// All external API calls (LLM providers, Safe Browsing, VirusTotal, Dashboard)
// are routed through here to avoid CORS issues in the popup.

import { getSettings, saveSettings, saveAnalysis } from './utils/storage.js';
import { checkSafeBrowsing, checkVirusTotal } from './utils/urlSafety.js';
import { buildAnalysisPrompt, generateOfflineFallback } from './engine/prompts.js';
import { analyzeEmail, computeFinalScore, scoreToVerdict } from './engine/analyzer.js';
import { hashEmail, cacheAnalysisResult } from './utils/cache.js';

// ─── Dashboard Integrations ───────────────────────────────────────────────────

async function sendHeartbeatToDashboard() {
  try {
    const settings = await getSettings();
    const dashboardUrl = (settings.dashboardUrl || 'http://localhost:3000').replace(/\/+$/, '');
    const apiKey = settings.dashboardApiKey || '';
    if (!dashboardUrl) return;

    let aiOnline = false;
    try {
      const endpoint = settings.ollamaEndpoint || 'http://localhost:11434';
      const resp = await fetch(`${endpoint}/api/tags`, { method: 'GET' });
      aiOnline = resp.ok;
    } catch { aiOnline = false; }

    let activeModel = settings.ollamaModel || '';
    if (settings.provider === 'openai') activeModel = settings.openaiModel || '';
    else if (settings.provider === 'gemini') activeModel = settings.geminiModel || '';
    else if (settings.provider === 'openrouter') activeModel = settings.openrouterModel || '';

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    
    await fetch(`${dashboardUrl}/api/heartbeat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': apiKey,
      },
      body: JSON.stringify({
        userEmail: settings.userEmail || 'unknown@localhost',
        userName: settings.userName || '',
        department: settings.department || '',
        hostname: settings.hostname || '',
        extensionVersion: chrome.runtime.getManifest().version,
        aiProvider: settings.provider || 'ollama',
        aiModelName: activeModel,
        aiOnline,
      }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
  } catch (e) {
    console.warn('[Revelio] Dashboard heartbeat failed:', e.message);
  }
}

async function sendAlertToDashboard(analysisResult, endpointInfo) {
  try {
    const settings = await getSettings();
    const dashboardUrl = (settings.dashboardUrl || 'http://localhost:3000').replace(/\/+$/, '');
    const apiKey = settings.dashboardApiKey || '';
    if (!dashboardUrl) return;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    
    await fetch(`${dashboardUrl}/api/alerts`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': apiKey,
      },
      body: JSON.stringify({
        endpointInfo,
        analysisResult,
      }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
  } catch (e) {
    console.warn('[Revelio] Dashboard alert send failed:', e.message);
  }
}

// ─── Context Menu Setup ───────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'revelio-analyze',
    title: '🛡️ Analyze with Revelio',
    contexts: ['selection'],
  });

  // Default settings initialization
  getSettings().then((settings) => {
    if (!settings.initialized) {
      saveSettings({
        initialized: true,
        provider: 'ollama',
        ollamaEndpoint: 'http://localhost:11434',
        ollamaModel: '',
        openaiApiKey: '',
        openaiModel: 'gpt-4o-mini',
        geminiApiKey: '',
        geminiModel: 'gemini-1.5-flash',

        sensitivityThreshold: 50,
        autoSave: true,
        showRuleBreakdown: true,
        maxHistoryEntries: 20,
        contextMenuEnabled: true,
        theme: 'dark',
      });
    }
  });

  // Setup Ollama health check alarm
  chrome.alarms.create('ollamaHealthCheck', { periodInMinutes: 0.5 });
  chrome.alarms.create('dashboardHeartbeat', { periodInMinutes: 1 });

  sendHeartbeatToDashboard().catch(console.error);
});

// ─── Context Menu Click Handler ───────────────────────────────────────────────

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'revelio-analyze') return;

  const selectedText = info.selectionText || '';
  if (!selectedText.trim()) return;

  // Store the selected text so the popup can read it
  await chrome.storage.local.set({ pendingEmailText: selectedText });

  // Open the popup programmatically
  try {
    await chrome.action.openPopup();
  } catch (e) {
    // Fallback: open popup.html in a new tab if openPopup() fails
    chrome.tabs.create({ url: chrome.runtime.getURL('popup/popup.html') + '?fromContext=1' });
  }
});

// ─── Badge Management ─────────────────────────────────────────────────────────

function updateBadge(score) {
  if (score === null || score === undefined) {
    chrome.action.setBadgeText({ text: '' });
    return;
  }

  if (score < 40) {
    chrome.action.setBadgeText({ text: '' });
  } else if (score < 70) {
    chrome.action.setBadgeText({ text: '!' });
    chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' });
  } else if (score <= 85) {
    chrome.action.setBadgeText({ text: '!!' });
    chrome.action.setBadgeBackgroundColor({ color: '#f97316' });
  } else {
    chrome.action.setBadgeText({ text: '⚠' });
    chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
  }
}

// ─── Alarm Handler (Ollama Health Check) ─────────────────────────────────────

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'ollamaHealthCheck') {
    const settings = await getSettings();
    const endpoint = settings.ollamaEndpoint || 'http://localhost:11434';
    let online = false;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      const response = await fetch(`${endpoint}/api/tags`, {
        method: 'GET',
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      online = response.ok;
    } catch {
      online = false;
    }

    // Broadcast to any open popups
    chrome.runtime.sendMessage({ type: 'OLLAMA_STATUS', online }).catch(() => {});
  }
  
  if (alarm.name === 'dashboardHeartbeat') {
    sendHeartbeatToDashboard().catch(console.error);
  }
});

// ─── Message Handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'FORCE_HEARTBEAT') {
    sendHeartbeatToDashboard().catch(() => {});
    sendResponse({ success: true });
    return true;
  }

  if (message.type === 'ANALYZE') {
    handleAnalyze(message)
      .then((result) => sendResponse({ success: true, data: result }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // Keep message channel open for async response
  }

  if (message.type === 'MANUAL_SCAN') {
    getSettings().then(settings => {
      runAnalysisPipeline(message.emailText, message.source, settings, false)
        .then((result) => sendResponse({ success: true, data: result }))
        .catch((err) => sendResponse({ success: false, error: err.message }));
    });
    return true;
  }

  if (message.type === 'CHECK_OLLAMA') {
    checkOllama(message.endpoint)
      .then((online) => sendResponse({ online }))
      .catch(() => sendResponse({ online: false }));
    return true;
  }

  if (message.type === 'UPDATE_BADGE') {
    updateBadge(message.score);
    sendResponse({ ok: true });
    return false;
  }

  if (message.type === 'PASSIVE_SCAN') {
    handlePassiveScan(message.emailText, message.source, sender.tab?.id).catch(console.error);
    sendResponse({ ok: true });
    return false;
  }

  if (message.type === 'CHECK_ACTIVE_SCAN') {
    const hash = hashEmail(message.emailText);
    if (activePassiveScans.has(hash)) {
      activePassiveScans.get(hash).then(result => sendResponse({ active: true, result })).catch(() => sendResponse({ active: false }));
      return true;
    }
    sendResponse({ active: false });
    return false;
  }

  if (message.type === 'CHECK_URL_SAFETY') {
    getSettings().then(settings => {
      checkSafeBrowsing(message.url, settings.safeBrowsingApiKey)
        .then(result => sendResponse({ success: true, data: result }))
        .catch(err => sendResponse({ success: false, error: err.message }));
    });
    return true;
  }

  if (message.type === 'DEEP_SCAN_URL') {
    getSettings().then(settings => {
      checkVirusTotal(message.url, settings.virusTotalApiKey)
        .then(result => sendResponse({ success: true, data: result }))
        .catch(err => sendResponse({ success: false, error: err.message }));
    });
    return true;
  }

  if (message.type === 'GET_OLLAMA_MODELS') {
    getOllamaModels(message.endpoint)
      .then((models) => sendResponse({ success: true, models }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.type === 'GET_PROVIDER_MODELS') {
    const { provider, apiKey, endpoint } = message;
    let promise;
    switch (provider) {
      case 'ollama':
        promise = getOllamaModels(endpoint);
        break;
      case 'openai':
        promise = getOpenAIModels(apiKey);
        break;
      case 'gemini':
        promise = getGeminiModels(apiKey);
        break;
      case 'openrouter':
        promise = getOpenRouterModels(apiKey);
        break;
      default:
        promise = Promise.reject(new Error(`Unknown provider: ${provider}`));
    }
    promise
      .then((models) => sendResponse({ success: true, models }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }
});

// ─── Provider Model Discovery ─────────────────────────────────────────────────

async function getOpenAIModels(apiKey) {
  if (!apiKey) throw new Error('OpenAI API key is required');
  const response = await fetch('https://api.openai.com/v1/models', {
    headers: { Authorization: `Bearer ${apiKey.trim()}` },
  });
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData?.error?.message || `HTTP ${response.status}: Failed to fetch OpenAI models`);
  }
  const data = await response.json();
  const models = (data.data || [])
    .map((m) => m.id)
    .filter((id) => {
      const isExcluded = /^(text-embedding|tts|whisper|dall-e|babbage|davinci|canary|text-moderation|omni-moderation|audio-|realtime)/i.test(id);
      const isKnownGood = /^(gpt-|o1|o3|chatgpt-)/i.test(id);
      return !isExcluded && isKnownGood;
    });

  const priority = ['gpt-4o', 'gpt-4o-mini', 'o1-mini', 'o1-preview', 'o1', 'o3-mini', 'gpt-4-turbo', 'gpt-3.5-turbo'];
  models.sort((a, b) => {
    const aIdx = priority.indexOf(a);
    const bIdx = priority.indexOf(b);
    if (aIdx !== -1 && bIdx !== -1) return aIdx - bIdx;
    if (aIdx !== -1) return -1;
    if (bIdx !== -1) return 1;
    return a.localeCompare(b);
  });

  return models;
}

async function getGeminiModels(apiKey) {
  if (!apiKey) throw new Error('Gemini API key is required');
  const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(apiKey.trim())}`);
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData?.error?.message || `HTTP ${response.status}: Failed to fetch Gemini models`);
  }
  const data = await response.json();
  const models = (data.models || [])
    .filter((m) => (m.supportedGenerationMethods || []).includes('generateContent'))
    .map((m) => ({
      id: m.name.replace(/^models\//, ''),
      name: m.displayName ? `${m.displayName} (${m.name.replace(/^models\//, '')})` : m.name.replace(/^models\//, ''),
    }));

  const priority = ['gemini-2.0-flash', 'gemini-1.5-flash', 'gemini-1.5-pro', 'gemini-2.0-flash-lite-preview-02-05', 'gemini-2.5-pro', 'gemini-2.5-flash'];
  models.sort((a, b) => {
    const aIdx = priority.indexOf(a.id);
    const bIdx = priority.indexOf(b.id);
    if (aIdx !== -1 && bIdx !== -1) return aIdx - bIdx;
    if (aIdx !== -1) return -1;
    if (bIdx !== -1) return 1;
    return a.id.localeCompare(b.id);
  });

  return models;
}

async function getOpenRouterModels(apiKey = '') {
  const headers = {};
  if (apiKey && apiKey.trim()) headers['Authorization'] = `Bearer ${apiKey.trim()}`;
  const response = await fetch('https://openrouter.ai/api/v1/models', { headers });
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData?.error?.message || `HTTP ${response.status}: Failed to fetch OpenRouter models`);
  }
  const data = await response.json();
  const models = (data.data || []).map((m) => ({
    id: m.id,
    name: m.name ? `${m.name} (${m.id})` : m.id,
    isFree: m.id.endsWith(':free') || m.pricing?.prompt === '0',
  }));

  models.sort((a, b) => {
    if (a.isFree && !b.isFree) return -1;
    if (!a.isFree && b.isFree) return 1;
    return a.name.localeCompare(b.name);
  });

  return models;
}

// ─── Ollama Health Check ──────────────────────────────────────────────────────

async function checkOllama(endpoint = 'http://localhost:11434') {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);
    const response = await fetch(`${endpoint}/api/tags`, { signal: controller.signal });
    clearTimeout(timeoutId);
    return response.ok;
  } catch {
    return false;
  }
}

async function getOllamaModels(endpoint = 'http://localhost:11434') {
  const response = await fetch(`${endpoint}/api/tags`);
  if (!response.ok) throw new Error('Failed to fetch Ollama models');
  const data = await response.json();
  return (data.models || []).map((m) => m.name);
}

// ─── Main Analysis Handler ────────────────────────────────────────────────────

async function handleAnalyze({ emailText, settings, ruleResult }) {
  const provider = settings.provider || 'ollama';
  const prompt = buildAnalysisPrompt(emailText, ruleResult);

  let llmResponse;

  // NOTE: All four provider cases must be kept in sync with runAnalysisPipeline() below.
  switch (provider) {
    case 'ollama':
      llmResponse = await callOllama(prompt, settings);
      break;
    case 'openai':
      llmResponse = await callOpenAI(prompt, settings);
      break;
    case 'gemini':
      llmResponse = await callGemini(prompt, settings);
      break;
    case 'openrouter':
      llmResponse = await callOpenRouter(prompt, settings);
      break;
    default:
      throw new Error('Unknown AI provider: ' + provider);
  }

  return llmResponse;
}

// ─── Passive Scanning ─────────────────────────────────────────────────────────

// In-flight passive scan promises, keyed by email hash.
// Prevents duplicate concurrent scans for the same email.
const activePassiveScans = new Map();

async function handlePassiveScan(emailText, source, tabId) {
  const settings = await getSettings();
  if (settings.autoScanEnabled === false) return;

  const hash = hashEmail(emailText);
  
  const cachedData = await chrome.storage.local.get(hash);
  if (cachedData[hash] && cachedData[hash].result) {
    return; // Already scanned and cached, do nothing
  }

  return runAnalysisPipeline(emailText, source, settings, true, tabId);
}

async function runAnalysisPipeline(emailText, source, settings, isPassive = false, tabId = null) {
  const hash = hashEmail(emailText);

  if (activePassiveScans.has(hash)) {
    return activePassiveScans.get(hash);
  }

  const scanPromise = (async () => {
    sendHeartbeatToDashboard().catch(() => {}); // Ping on scan start
    if (isPassive && tabId) {
      chrome.tabs.sendMessage(tabId, { type: 'SCAN_STARTED' }).catch(() => {});
    }

    try {
    // 1. Run local rules
    const { emailData, ruleResult } = await analyzeEmail(emailText);
    emailData.source = source;

    // 2. Call LLM
    const prompt = buildAnalysisPrompt(emailText, ruleResult);
    let llmResult;
    try {
      if (settings.provider === 'ollama') {
        llmResult = await callOllama(prompt, settings);
      } else if (settings.provider === 'openai') {
        llmResult = await callOpenAI(prompt, settings);
      } else if (settings.provider === 'gemini') {
        llmResult = await callGemini(prompt, settings);
      } else if (settings.provider === 'openrouter') {
        llmResult = await callOpenRouter(prompt, settings);
      } else {
        llmResult = generateOfflineFallback(ruleResult, settings.sensitivityThreshold, 'Unknown provider');
      }
    } catch (llmError) {
      console.warn('[Revelio] Passive scan LLM failed, using fallback:', llmError);
      llmResult = generateOfflineFallback(ruleResult, settings.sensitivityThreshold, llmError.message);
    }

    // 3. Compute Final Score & Verdict
    const finalScore = computeFinalScore(llmResult.llmScore, ruleResult.ruleScore);
    const verdict = scoreToVerdict(finalScore, settings.sensitivityThreshold);

    // 4. Act on findings (Notify on Suspicious or worse if passive)
    updateBadge(finalScore);

    if (isPassive && verdict !== 'Safe') {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: `Revelio: ${verdict}`,
        message: `Threat detected in open email (Score: ${finalScore}). ${llmResult.recommendedAction || ''}`,
        priority: 2
      });
    }

    // 5. Save to history & Update Cache
    const analysisResult = {
      emailData,
      ruleResult,
      llmResult,
      finalScore,
      timestamp: new Date().toISOString()
    };

    if (settings.autoSave !== false) {
      await saveAnalysis(analysisResult);
    }
    
    await cacheAnalysisResult(emailText, analysisResult);

    let activeModel = settings.ollamaModel || '';
    if (settings.provider === 'openai') activeModel = settings.openaiModel || '';
    else if (settings.provider === 'gemini') activeModel = settings.geminiModel || '';
    else if (settings.provider === 'openrouter') activeModel = settings.openrouterModel || '';

    // Send to SOC Dashboard (silent, non-blocking)
    const endpointInfo = {
      userEmail: settings.userEmail || 'unknown@localhost',
      userName: settings.userName || '',
      department: settings.department || '',
      hostname: settings.hostname || '',
      aiProvider: settings.provider || 'ollama',
      aiModelName: activeModel,
    };
    sendAlertToDashboard(analysisResult, endpointInfo).catch(() => {});
    return analysisResult;

  } catch (err) {
    console.error('[Revelio] Pipeline error:', err);
    throw err;
  } finally {
    if (isPassive && tabId) {
      chrome.tabs.sendMessage(tabId, { type: 'SCAN_FINISHED' }).catch(() => {});
    }
  }
  })();

  activePassiveScans.set(hash, scanPromise);
  try {
    return await scanPromise;
  } finally {
    activePassiveScans.delete(hash);
  }
}

// Prompt Builder is now imported from engine/prompts.js

// ─── AI Provider Implementations ─────────────────────────────────────────────

async function callOllama(prompt, settings) {
  const endpoint = settings.ollamaEndpoint || 'http://localhost:11434';
  let model = settings.ollamaModel || '';

  // Auto-detect model if none is selected or installed
  try {
    const tagsResp = await fetch(`${endpoint}/api/tags`);
    if (tagsResp.ok) {
      const tagsData = await tagsResp.json();
      if (tagsData && tagsData.models && tagsData.models.length > 0) {
        const availableModels = tagsData.models.map(m => m.name);
        if (!model || !availableModels.includes(model)) {
          // If no model is set or the set model doesn't exist, fallback to first available
          model = availableModels[0];
          // Save it back to settings to persist the choice
          saveSettings({ ollamaModel: model });
        }
      }
    }
  } catch (err) {
    // If we can't fetch tags, let it fail during the generation request
  }

  // Final fallback just in case
  model = model || 'deepseek-r1:8b';

  let response;
  try {
    response = await fetch(`${endpoint}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        prompt,
        stream: false,
        options: { temperature: 0.1, top_p: 0.9 },
      }),
    });
  } catch (err) {
    throw new Error('OLLAMA_OFFLINE');
  }

  if (!response.ok) {
    let errorMsg = await response.text().catch(() => '');
    try {
      const jsonMsg = JSON.parse(errorMsg);
      if (jsonMsg.error) errorMsg = jsonMsg.error;
    } catch (e) {}
    throw new Error(`Ollama (500): ${errorMsg}`);
  }

  const data = await response.json();
  return parseAIResponse(data.response);
}

async function callOpenAI(prompt, settings) {
  const apiKey = settings.openaiApiKey;
  if (!apiKey) throw new Error('OpenAI API key not configured');

  const model = settings.openaiModel || 'gpt-4o-mini';

  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.1,
      response_format: { type: 'json_object' },
    }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(`OpenAI error: ${err.error?.message || response.status}`);
  }

  const data = await response.json();
  const content = data.choices?.[0]?.message?.content;
  return parseAIResponse(content);
}

async function callGemini(prompt, settings) {
  const apiKey = settings.geminiApiKey;
  if (!apiKey) throw new Error('Gemini API key not configured');

  let model = settings.geminiModel || 'gemini-3.5-flash';

  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.1, responseMimeType: 'application/json' },
      }),
    }
  );

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(`Gemini error: ${err.error?.message || response.status}`);
  }

  const data = await response.json();
  const content = data.candidates?.[0]?.content?.parts?.[0]?.text;
  return parseAIResponse(content);
}

async function callOpenRouter(prompt, settings) {
  const apiKey = settings.openrouterApiKey;
  if (!apiKey) throw new Error('OpenRouter API key not configured');

  let model = settings.openrouterModel || 'deepseek/deepseek-r1:free';

  const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
      'HTTP-Referer': 'https://github.com/DiptanshuDhawan/Revelio',
      'X-Title': 'Revelio Extension'
    },
    body: JSON.stringify({
      model,
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.1,
    }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(`OpenRouter error: ${err.error?.message || response.status}`);
  }

  const data = await response.json();
  if (data.error) {
    throw new Error(`OpenRouter API error: ${data.error.message}`);
  }

  const content = data.choices?.[0]?.message?.content;
  if (!content) {
    throw new Error(`OpenRouter empty content. Raw data: ${JSON.stringify(data).substring(0, 100)}`);
  }
  return parseAIResponse(content);
}

// ─── Response Parser ──────────────────────────────────────────────────────────

function parseAIResponse(rawText) {
  if (!rawText) throw new Error('Empty response from AI');

  let cleaned = rawText.trim();

  // Strip <think>...</think> reasoning blocks (deepseek-r1, qwen3 models emit these)
  cleaned = cleaned.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();

  // Strip markdown fences if present
  cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '');

  // Strip any preamble text before the first { (e.g., "Here is the analysis:")
  const start = cleaned.indexOf('{');
  const end = cleaned.lastIndexOf('}');
  if (start === -1 || end === -1) throw new Error('No valid JSON in AI response');

  let jsonStr = cleaned.slice(start, end + 1);

  let parsed;
  try {
    parsed = JSON.parse(jsonStr);
  } catch (e) {
    // Retry with common fixes for small-model quirks
    try {
      let repaired = jsonStr;
      // Remove trailing commas before } or ]
      repaired = repaired.replace(/,\s*([}\]])/g, '$1');
      // Remove control characters (tabs/newlines inside strings are fine but literal ones break)
      repaired = repaired.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '');
      // Fix single quotes used instead of double quotes (naive but helps)
      // Only do this if there are no double quotes at all in the problematic areas
      if (!repaired.includes('"') && repaired.includes("'")) {
        repaired = repaired.replace(/'/g, '"');
      }
      parsed = JSON.parse(repaired);
    } catch (e2) {
      throw new Error('Invalid JSON from AI: ' + e.message);
    }
  }

  // Sanitize and normalize MITRE ATT&CK information
  let mitreAttack = { id: null, name: null, url: null };
  if (parsed.mitreAttack && parsed.mitreAttack.id) {
    let mitreId = String(parsed.mitreAttack.id).trim().toUpperCase().replace(/\s+/g, '');
    let mitreName = parsed.mitreAttack.name ? String(parsed.mitreAttack.name).trim() : '';
    let mitreUrl = null;

    // Check if it starts with digits only (e.g. 1566) and prepend 'T'
    if (/^\d{4}/.test(mitreId)) {
      mitreId = 'T' + mitreId;
    }

    const match = mitreId.match(/^(T\d{4})(?:\.(\d{3}))?$/);
    if (match) {
      let baseId = match[1];
      let subId = match[2];

      // If it is Phishing (T1566), validate the sub-techniques to prevent hallucinated ones
      if (baseId === 'T1566') {
        if (subId) {
          const validSubs = ['001', '002', '003', '004'];
          if (!validSubs.includes(subId)) {
            // Fallback to base technique if sub-technique is invalid (hallucinated)
            mitreId = 'T1566';
            subId = null;
          }
        }
      }

      if (subId) {
        mitreUrl = `https://attack.mitre.org/techniques/${baseId}/${subId}/`;
        if (!mitreName || mitreName.toLowerCase() === 'phishing') {
          if (subId === '001') mitreName = 'Spearphishing Attachment';
          else if (subId === '002') mitreName = 'Spearphishing Link';
          else if (subId === '003') mitreName = 'Spearphishing via Service';
          else if (subId === '004') mitreName = 'Spearphishing Voice';
        }
      } else {
        mitreUrl = `https://attack.mitre.org/techniques/${baseId}/`;
        if (!mitreName) {
          if (baseId === 'T1566') mitreName = 'Phishing';
        }
      }
    } else {
      // Non-standard format - fallback
      mitreUrl = `https://attack.mitre.org/techniques/${mitreId}/`;
    }

    mitreAttack = {
      id: mitreId,
      name: mitreName || 'Phishing',
      url: mitreUrl
    };
  }

  // Validate and normalize required fields
  return {
    llmScore: clamp(parseInt(parsed.llmScore) || 50, 0, 100),
    verdict: parsed.verdict || 'Suspicious',
    confidence: parsed.confidence || 'Medium',
    attackVector: parsed.attackVector || 'Unknown',
    categories: {
      impersonation: clamp(parseInt(parsed.categories?.impersonation) || 0, 0, 100),
      urgencyManipulation: clamp(parseInt(parsed.categories?.urgencyManipulation) || 0, 0, 100),
      socialEngineering: clamp(parseInt(parsed.categories?.socialEngineering) || 0, 0, 100),
      technicalIndicators: clamp(parseInt(parsed.categories?.technicalIndicators) || 0, 0, 100),
      aiGeneratedSigns: clamp(parseInt(parsed.categories?.aiGeneratedSigns) || 0, 0, 100),
    },
    threatNarrative: (parsed.threatNarrative && !parsed.threatNarrative.startsWith('<') && !parsed.threatNarrative.includes('No specific narrative')) 
      ? parsed.threatNarrative 
      : (Array.isArray(parsed.topFindings) && parsed.topFindings[0]?.detail) 
        ? parsed.topFindings[0].detail 
        : (parsed.analystNote || 'No specific narrative provided by the AI analysis.'),
    topFindings: Array.isArray(parsed.topFindings) ? parsed.topFindings.slice(0, 5).map(f => {
      if (typeof f === 'string') return { title: 'AI Finding', detail: f, severity: 'medium' };
      return {
        title: f.title || 'AI Finding',
        detail: f.detail || String(f),
        severity: ['critical', 'high', 'medium', 'low'].includes(f.severity?.toLowerCase()) ? f.severity.toLowerCase() : 'medium'
      };
    }) : [],
    suspiciousQuotes: Array.isArray(parsed.suspiciousQuotes) ? parsed.suspiciousQuotes.slice(0, 5) : [],
    mitreAttack,
    becRisk: Boolean(parsed.becRisk),
    spearPhishingRisk: Boolean(parsed.spearPhishingRisk),
    aiGeneratedRisk: Boolean(parsed.aiGeneratedRisk),
    becDetails: parsed.becDetails || null,
    recommendedAction: parsed.recommendedAction || 'Review this email carefully.',
    remediationSteps: Array.isArray(parsed.remediationSteps) ? parsed.remediationSteps.slice(0, 6) : [],
    analystNote: parsed.analystNote || '',
  };
}

function clamp(val, min, max) {
  return Math.min(Math.max(val, min), max);
}
