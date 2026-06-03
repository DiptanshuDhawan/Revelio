// PhishGuard AI — Storage Wrapper
// Async wrappers for chrome.storage.local with defaults and error handling.

'use strict';

const DEFAULT_SETTINGS = {
  initialized: false,
  provider: 'ollama',
  ollamaEndpoint: 'http://localhost:11434',
  ollamaModel: 'deepseek-r1:8b',
  openaiApiKey: '',
  openaiModel: 'gpt-4o-mini',
  geminiApiKey: '',
  geminiModel: 'gemini-1.5-flash',
  sensitivityThreshold: 50,
  autoScanEnabled: true,
  autoSave: true,
  showRuleBreakdown: true,
  maxHistoryEntries: 20,
  contextMenuEnabled: true,
  theme: 'dark',
};

// ─── Settings ─────────────────────────────────────────────────────────────────

export async function getSettings() {
  try {
    const data = await chrome.storage.local.get('settings');
    return { ...DEFAULT_SETTINGS, ...(data.settings || {}) };
  } catch (e) {
    console.error('[PhishGuard] getSettings error:', e);
    return { ...DEFAULT_SETTINGS };
  }
}

export async function saveSettings(settings) {
  try {
    const current = await getSettings();
    await chrome.storage.local.set({ settings: { ...current, ...settings } });
    return true;
  } catch (e) {
    console.error('[PhishGuard] saveSettings error:', e);
    return false;
  }
}

// ─── History / Analysis Storage ───────────────────────────────────────────────

export async function saveAnalysis(result) {
  try {
    const settings = await getSettings();
    const maxEntries = parseInt(settings.maxHistoryEntries) || 20;

    const data = await chrome.storage.local.get(['history', 'stats']);
    const history = Array.isArray(data.history) ? data.history : [];
    const stats = data.stats || { totalAnalyzed: 0, phishingCaught: 0 };

    // Create history entry
    const entry = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      timestamp: new Date().toISOString(),
      subject: result.emailData?.subject || result.subject || 'No Subject',
      previewText: (result.emailData?.body || '').slice(0, 80),
      finalScore: result.finalScore,
      verdict: result.llmResult?.verdict || 'Unknown',
      llmScore: result.llmResult?.llmScore,
      ruleScore: result.ruleResult?.ruleScore,
      attackVector: result.llmResult?.attackVector,
      confidence: result.llmResult?.confidence,
      becRisk: result.llmResult?.becRisk,
      spearPhishingRisk: result.llmResult?.spearPhishingRisk,
      mitreId: result.llmResult?.mitreAttack?.id,
      fullResult: result,
    };

    // Prepend and trim to max
    const newHistory = [entry, ...history].slice(0, maxEntries);

    // Update stats
    stats.totalAnalyzed = (stats.totalAnalyzed || 0) + 1;
    if (result.finalScore >= 40) {
      stats.phishingCaught = (stats.phishingCaught || 0) + 1;
    }
    stats.lastAnalysis = entry.timestamp;

    await chrome.storage.local.set({ history: newHistory, stats });
    return entry;
  } catch (e) {
    console.error('[PhishGuard] saveAnalysis error:', e);
    return null;
  }
}

export async function getHistory() {
  try {
    const data = await chrome.storage.local.get('history');
    return Array.isArray(data.history) ? data.history : [];
  } catch (e) {
    console.error('[PhishGuard] getHistory error:', e);
    return [];
  }
}

export async function clearHistory() {
  try {
    const allData = await chrome.storage.local.get(null);
    const cacheKeys = Object.keys(allData).filter((key) => key.startsWith('phishcache_'));
    await chrome.storage.local.remove(['history', 'stats', 'phishguard_last_cache_key', ...cacheKeys]);
    return true;
  } catch (e) {
    console.error('[PhishGuard] clearHistory error:', e);
    return false;
  }
}

export async function getStats() {
  try {
    const data = await chrome.storage.local.get('stats');
    return data.stats || { totalAnalyzed: 0, phishingCaught: 0, lastAnalysis: null };
  } catch (e) {
    return { totalAnalyzed: 0, phishingCaught: 0, lastAnalysis: null };
  }
}

// ─── History Export ───────────────────────────────────────────────────────────

export async function exportHistory() {
  try {
    const history = await getHistory();
    const stats = await getStats();
    const settings = await getSettings();

    const exportData = {
      exportedAt: new Date().toISOString(),
      extensionVersion: '1.0.0',
      stats,
      settings: { ...settings, openaiApiKey: '[REDACTED]', geminiApiKey: '[REDACTED]' },
      history: history.map((entry) => ({
        ...entry,
        fullResult: undefined, // Exclude full results for smaller export
      })),
    };

    return JSON.stringify(exportData, null, 2);
  } catch (e) {
    console.error('[PhishGuard] exportHistory error:', e);
    return JSON.stringify({ error: e.message });
  }
}

// ─── Feedback Storage ─────────────────────────────────────────────────────────

export async function saveFeedback(analysisId, isFalsePositive) {
  try {
    const data = await chrome.storage.local.get('feedback');
    const feedback = data.feedback || {};
    feedback[analysisId] = {
      isFalsePositive,
      timestamp: new Date().toISOString(),
    };
    await chrome.storage.local.set({ feedback });
    return true;
  } catch (e) {
    console.error('[PhishGuard] saveFeedback error:', e);
    return false;
  }
}
