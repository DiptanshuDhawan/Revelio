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
  const endpoint = settings.ollamaEndpoint || 'http://localhost:11434';
  if ($('s-ollama-endpoint')) $('s-ollama-endpoint').value = endpoint;
  
  if ($('s-ollama-model')) {
    const selectEl = $('s-ollama-model');
    // Save current value before we clear options
    const savedModel = settings.ollamaModel || '';
    
    // Try to fetch real models from Ollama to populate dropdown
    chrome.runtime.sendMessage({ type: 'GET_OLLAMA_MODELS', endpoint })
      .then(resp => {
        if (resp && resp.success && resp.models && resp.models.length > 0) {
          // Clear current options except "custom"
          const customOpt = selectEl.querySelector('option[value="custom"]');
          selectEl.innerHTML = '';
          
          let foundSaved = false;
          resp.models.forEach(m => {
            const opt = document.createElement('option');
            opt.value = m;
            opt.textContent = m;
            selectEl.appendChild(opt);
            if (m === savedModel) foundSaved = true;
          });
          
          if (customOpt) selectEl.appendChild(customOpt);
          
          if (foundSaved) {
            selectEl.value = savedModel;
          } else if (savedModel) {
            selectEl.value = 'custom';
            if ($('s-ollama-model-custom')) {
              $('s-ollama-model-custom').style.display = 'block';
              $('s-ollama-model-custom').value = savedModel;
            }
          } else {
            selectEl.value = resp.models[0];
            saveSettings({ ollamaModel: resp.models[0] });
          }
        } else {
          // Fallback if offline: just show the saved one
          const opt = document.createElement('option');
          opt.value = savedModel;
          opt.textContent = savedModel + ' (Saved)';
          selectEl.insertBefore(opt, selectEl.firstChild);
          selectEl.value = savedModel;
        }
      })
      .catch(() => {
        const opt = document.createElement('option');
        opt.value = savedModel;
        opt.textContent = savedModel + ' (Saved)';
        selectEl.insertBefore(opt, selectEl.firstChild);
        selectEl.value = savedModel;
      });
  }

  // OpenAI
  if ($('s-openai-key')) $('s-openai-key').value = settings.openaiApiKey || '';
  if ($('s-openai-model')) {
    const openaiKnown = ['gpt-4o-mini', 'gpt-4o', 'o1-mini', 'o1-preview'];
    if (openaiKnown.includes(settings.openaiModel) || !settings.openaiModel) {
      $('s-openai-model').value = settings.openaiModel || 'gpt-4o-mini';
    } else {
      $('s-openai-model').value = 'custom';
      if ($('s-openai-model-custom')) {
        $('s-openai-model-custom').style.display = 'block';
        $('s-openai-model-custom').value = settings.openaiModel;
      }
    }
  }

  // Gemini
  if ($('s-gemini-key')) $('s-gemini-key').value = settings.geminiApiKey || '';
  if ($('s-gemini-model')) {
    const geminiKnown = ['gemini-3.5-flash', 'gemini-3.1-flash-lite'];
    if (geminiKnown.includes(settings.geminiModel) || !settings.geminiModel) {
      $('s-gemini-model').value = settings.geminiModel || 'gemini-3.5-flash';
    } else {
      $('s-gemini-model').value = 'custom';
      if ($('s-gemini-model-custom')) {
        $('s-gemini-model-custom').style.display = 'block';
        $('s-gemini-model-custom').value = settings.geminiModel;
      }
    }
  }

  // Analysis settings
  if ($('sensitivity')) {
    $('sensitivity').value = settings.sensitivityThreshold || 50;
    if ($('sensitivity-val')) $('sensitivity-val').textContent = settings.sensitivityThreshold || 50;
  }
  if ($('auto-scan')) $('auto-scan').checked = settings.autoScanEnabled !== false;
  if ($('auto-save')) $('auto-save').checked = settings.autoSave !== false;
  if ($('show-rules')) $('show-rules').checked = settings.showRuleBreakdown !== false;
  if ($('max-history')) $('max-history').value = String(settings.maxHistoryEntries || 20);
  if ($('context-menu')) $('context-menu').checked = settings.contextMenuEnabled !== false;

  // URL Safety
  if ($('enable-safebrowsing')) {
    $('enable-safebrowsing').checked = settings.enableSafeBrowsing === true;
    if ($('cfg-safebrowsing')) $('cfg-safebrowsing').style.display = settings.enableSafeBrowsing === true ? 'block' : 'none';
  }
  if ($('s-safebrowsing-key')) $('s-safebrowsing-key').value = settings.safeBrowsingApiKey || '';

  if ($('enable-virustotal')) {
    $('enable-virustotal').checked = settings.enableVirusTotal === true;
    if ($('cfg-virustotal')) $('cfg-virustotal').style.display = settings.enableVirusTotal === true ? 'block' : 'none';
  }
  if ($('s-virustotal-key')) $('s-virustotal-key').value = settings.virusTotalApiKey || '';
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

  ['ollama', 'openai', 'gemini'].forEach((p) => {
    const el = document.getElementById(`cfg-${p}`);
    if (el) el.style.display = p === provider ? 'flex' : 'none';
  });
}

function collectSettings() {
  const $ = (id) => document.getElementById(id);

  let ollamaModel = $('s-ollama-model')?.value || '';
  if (ollamaModel === 'custom') {
    ollamaModel = $('s-ollama-model-custom')?.value || '';
  }
  
  let openaiModel = $('s-openai-model')?.value || 'gpt-4o-mini';
  if (openaiModel === 'custom') {
    openaiModel = $('s-openai-model-custom')?.value || 'gpt-4o-mini';
  }

  let geminiModel = $('s-gemini-model')?.value || 'gemini-3.5-flash';
  if (geminiModel === 'custom') {
    geminiModel = $('s-gemini-model-custom')?.value || 'gemini-3.5-flash';
  }

  return {
    provider: currentProvider,
    ollamaEndpoint: $('s-ollama-endpoint')?.value || 'http://localhost:11434',
    ollamaModel,
    openaiApiKey: $('s-openai-key')?.value || '',
    openaiModel,
    geminiApiKey: $('s-gemini-key')?.value || '',
    geminiModel,
    sensitivityThreshold: parseInt($('sensitivity')?.value) || 50,
    autoScanEnabled: $('auto-scan')?.checked !== false,
    autoSave: $('auto-save')?.checked !== false,
    showRuleBreakdown: $('show-rules')?.checked !== false,
    maxHistoryEntries: parseInt($('max-history')?.value) || 20,
    contextMenuEnabled: $('context-menu')?.checked !== false,
    enableSafeBrowsing: $('enable-safebrowsing')?.checked === true,
    safeBrowsingApiKey: $('s-safebrowsing-key')?.value || '',
    enableVirusTotal: $('enable-virustotal')?.checked === true,
    virusTotalApiKey: $('s-virustotal-key')?.value || '',
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

  $('s-openai-model')?.addEventListener('change', (e) => {
    const custom = $('s-openai-model-custom');
    if (custom) custom.style.display = e.target.value === 'custom' ? 'block' : 'none';
  });

  $('s-gemini-model')?.addEventListener('change', (e) => {
    const custom = $('s-gemini-model-custom');
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

  // URL Safety Toggles
  $('enable-safebrowsing')?.addEventListener('change', (e) => {
    if ($('cfg-safebrowsing')) $('cfg-safebrowsing').style.display = e.target.checked ? 'block' : 'none';
  });
  $('enable-virustotal')?.addEventListener('change', (e) => {
    if ($('cfg-virustotal')) $('cfg-virustotal').style.display = e.target.checked ? 'block' : 'none';
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
      
      // Since we dynamically populate the select, the option should exist
      let optionExists = Array.from(select.options).some(opt => opt.value === m);
      
      if (optionExists) {
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
