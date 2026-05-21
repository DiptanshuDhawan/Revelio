// PhishGuard AI — Settings Page Controller

import { getSettings, saveSettings, getStats, clearHistory, exportHistory } from '../utils/storage.js';

let currentProvider = 'ollama';

document.addEventListener('DOMContentLoaded', async () => {
  const settings = await getSettings();
  const stats = await getStats();

  loadSettingsIntoUI(settings);
  loadStatsIntoUI(stats);
  attachEventListeners();
});

function loadSettingsIntoUI(settings) {
  currentProvider = settings.provider || 'ollama';
  switchProvider(currentProvider);

  const $ = (id) => document.getElementById(id);

  // Ollama
  if ($('s-ollama-endpoint')) $('s-ollama-endpoint').value = settings.ollamaEndpoint || 'http://localhost:11434';
  if ($('s-ollama-model')) {
    const known = ['deepseek-r1:8b', 'llama3.1', 'mistral', 'phi3', 'llama3.2', 'gemma2'];
    if (known.includes(settings.ollamaModel)) {
      $('s-ollama-model').value = settings.ollamaModel;
    } else if (settings.ollamaModel) {
      $('s-ollama-model').value = 'custom';
      if ($('s-ollama-model-custom')) {
        $('s-ollama-model-custom').style.display = 'block';
        $('s-ollama-model-custom').value = settings.ollamaModel;
      }
    }
  }

  // OpenAI
  if ($('s-openai-key')) $('s-openai-key').value = settings.openaiApiKey || '';
  if ($('s-openai-model')) $('s-openai-model').value = settings.openaiModel || 'gpt-4o-mini';

  // Gemini
  if ($('s-gemini-key')) $('s-gemini-key').value = settings.geminiApiKey || '';
  if ($('s-gemini-model')) $('s-gemini-model').value = settings.geminiModel || 'gemini-1.5-flash';

  // Grok
  if ($('s-grok-key')) $('s-grok-key').value = settings.grokApiKey || '';

  // Analysis settings
  if ($('sensitivity')) {
    $('sensitivity').value = settings.sensitivityThreshold || 50;
    if ($('sensitivity-val')) $('sensitivity-val').textContent = settings.sensitivityThreshold || 50;
  }
  if ($('auto-save')) $('auto-save').checked = settings.autoSave !== false;
  if ($('show-rules')) $('show-rules').checked = settings.showRuleBreakdown !== false;
  if ($('max-history')) $('max-history').value = String(settings.maxHistoryEntries || 20);
  if ($('context-menu')) $('context-menu').checked = settings.contextMenuEnabled !== false;
}

function loadStatsIntoUI(stats) {
  const $ = (id) => document.getElementById(id);
  if ($('stat-total')) $('stat-total').textContent = stats.totalAnalyzed || 0;
  if ($('stat-caught')) $('stat-caught').textContent = stats.phishingCaught || 0;
  if ($('stat-version')) $('stat-version').textContent = '1.0.0';
  if ($('stat-last')) {
    if (stats.lastAnalysis) {
      $('stat-last').textContent = new Date(stats.lastAnalysis).toLocaleDateString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric',
        hour: '2-digit', minute: '2-digit',
      });
    } else {
      $('stat-last').textContent = 'Never';
    }
  }
}

function switchProvider(provider) {
  currentProvider = provider;

  document.querySelectorAll('.prov-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.prov === provider);
  });

  ['ollama', 'openai', 'gemini', 'grok'].forEach((p) => {
    const el = document.getElementById(`cfg-${p}`);
    if (el) el.style.display = p === provider ? 'flex' : 'none';
  });
}

function collectSettings() {
  const $ = (id) => document.getElementById(id);

  let ollamaModel = $('s-ollama-model')?.value || 'deepseek-r1:8b';
  if (ollamaModel === 'custom') {
    ollamaModel = $('s-ollama-model-custom')?.value || 'deepseek-r1:8b';
  }

  return {
    provider: currentProvider,
    ollamaEndpoint: $('s-ollama-endpoint')?.value || 'http://localhost:11434',
    ollamaModel,
    openaiApiKey: $('s-openai-key')?.value || '',
    openaiModel: $('s-openai-model')?.value || 'gpt-4o-mini',
    geminiApiKey: $('s-gemini-key')?.value || '',
    geminiModel: $('s-gemini-model')?.value || 'gemini-1.5-flash',
    grokApiKey: $('s-grok-key')?.value || '',
    sensitivityThreshold: parseInt($('sensitivity')?.value) || 50,
    autoSave: $('auto-save')?.checked !== false,
    showRuleBreakdown: $('show-rules')?.checked !== false,
    maxHistoryEntries: parseInt($('max-history')?.value) || 20,
    contextMenuEnabled: $('context-menu')?.checked !== false,
  };
}

function attachEventListeners() {
  const $ = (id) => document.getElementById(id);

  // Provider switching
  document.querySelectorAll('.prov-btn').forEach((btn) => {
    btn.addEventListener('click', () => switchProvider(btn.dataset.prov));
  });

  // Ollama model custom input
  $('s-ollama-model')?.addEventListener('change', (e) => {
    const custom = $('s-ollama-model-custom');
    if (custom) custom.style.display = e.target.value === 'custom' ? 'block' : 'none';
  });

  // Save button
  $('save-btn')?.addEventListener('click', async () => {
    const settings = collectSettings();
    const ok = await saveSettings(settings);
    showToast(ok ? '✓ Settings saved!' : '✗ Save failed', ok ? 'success' : 'error');
  });

  // Sensitivity slider
  $('sensitivity')?.addEventListener('input', (e) => {
    if ($('sensitivity-val')) $('sensitivity-val').textContent = e.target.value;
  });

  // Test Ollama connection
  $('test-ollama-btn')?.addEventListener('click', async () => {
    const endpoint = $('s-ollama-endpoint')?.value || 'http://localhost:11434';
    const resultEl = $('ollama-test-result');
    const btn = $('test-ollama-btn');

    btn.textContent = 'Testing...';
    btn.disabled = true;

    try {
      const resp = await chrome.runtime.sendMessage({ type: 'CHECK_OLLAMA', endpoint });
      if (resp?.online) {
        resultEl.textContent = '✓ Connected! Ollama is running.';
        resultEl.className = 'test-result success';
        resultEl.style.display = 'block';

        // Try to load models
        try {
          const modelsResp = await chrome.runtime.sendMessage({ type: 'GET_OLLAMA_MODELS', endpoint });
          if (modelsResp?.success && modelsResp.models?.length > 0) {
            showOllamaModels(modelsResp.models);
          }
        } catch { /* ignore */ }
      } else {
        throw new Error('Not reachable');
      }
    } catch {
      resultEl.textContent = '✗ Cannot connect to Ollama. Is it running? Run: ollama serve';
      resultEl.className = 'test-result error';
      resultEl.style.display = 'block';
    }

    btn.textContent = 'Test Connection';
    btn.disabled = false;
  });

  // Password visibility toggles
  document.querySelectorAll('.toggle-visibility').forEach((btn) => {
    btn.addEventListener('click', () => {
      const input = document.getElementById(btn.dataset.target);
      if (input) {
        input.type = input.type === 'password' ? 'text' : 'password';
        btn.textContent = input.type === 'password' ? '👁' : '🙈';
      }
    });
  });

  // Export history
  $('export-history-btn')?.addEventListener('click', async () => {
    const json = await exportHistory();
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-history-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('History exported!', 'success');
  });

  // Clear history
  $('clear-all-btn')?.addEventListener('click', async () => {
    if (!confirm('Clear ALL analysis history? This cannot be undone.')) return;
    await clearHistory();
    const stats = await chrome.storage.local.get('stats');
    loadStatsIntoUI({ totalAnalyzed: 0, phishingCaught: 0, lastAnalysis: null });
    showToast('History cleared!', 'success');
  });
}

function showOllamaModels(models) {
  const listEl = document.getElementById('ollama-models-list');
  const chipsEl = document.getElementById('ollama-models-chips');
  if (!listEl || !chipsEl) return;

  chipsEl.innerHTML = '';
  models.forEach((m) => {
    const chip = document.createElement('button');
    chip.className = 'model-chip';
    chip.textContent = m;
    chip.addEventListener('click', () => {
      const select = document.getElementById('s-ollama-model');
      const custom = document.getElementById('s-ollama-model-custom');
      if (!select) return;
      const known = ['deepseek-r1:8b', 'llama3.1', 'mistral', 'phi3', 'llama3.2', 'gemma2'];
      if (known.includes(m)) {
        select.value = m;
        if (custom) custom.style.display = 'none';
      } else {
        select.value = 'custom';
        if (custom) { custom.style.display = 'block'; custom.value = m; }
      }
    });
    chipsEl.appendChild(chip);
  });

  listEl.style.display = 'block';
}

let toastTimer;
function showToast(msg, type = '') {
  const toast = document.getElementById('settings-toast');
  if (!toast) return;
  clearTimeout(toastTimer);
  toast.textContent = msg;
  toast.className = `settings-toast ${type} show`;
  toastTimer = setTimeout(() => toast.classList.remove('show'), 3000);
}
