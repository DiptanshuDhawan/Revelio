// Revelio — Settings Page Controller
// Manages the full settings UI: provider selection, model config,
// sensitivity thresholds, SOC dashboard integration, and history controls.

import { getSettings, saveSettings, getStats, clearHistory, exportHistory } from '../utils/storage.js';

/** Shorthand for document.getElementById. Available to all functions in this file. */
const $ = (id) => document.getElementById(id);

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

  // Ollama
  const endpoint = settings.ollamaEndpoint || 'http://localhost:11434';
  if ($('s-ollama-endpoint')) $('s-ollama-endpoint').value = endpoint;
  fetchAndPopulateModels('ollama', { savedModel: settings.ollamaModel || '' });

  // OpenAI
  if ($('s-openai-key')) $('s-openai-key').value = settings.openaiApiKey || '';
  fetchAndPopulateModels('openai', { savedModel: settings.openaiModel || '' });

  // Gemini
  if ($('s-gemini-key')) $('s-gemini-key').value = settings.geminiApiKey || '';
  fetchAndPopulateModels('gemini', { savedModel: settings.geminiModel || '' });

  // OpenRouter
  if ($('s-openrouter-key')) $('s-openrouter-key').value = settings.openrouterApiKey || '';
  fetchAndPopulateModels('openrouter', { savedModel: settings.openrouterModel || '' });


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

  // Dashboard
  if ($('s-dashboard-url')) $('s-dashboard-url').value = settings.dashboardUrl || 'http://localhost:3000';
  if ($('s-dashboard-key')) $('s-dashboard-key').value = settings.dashboardApiKey || '';
  if ($('s-user-email')) $('s-user-email').value = settings.userEmail || '';
  if ($('s-user-name')) $('s-user-name').value = settings.userName || '';
  if ($('s-department')) $('s-department').value = settings.department || '';
  if ($('s-hostname')) $('s-hostname').value = settings.hostname || '';
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

  ['ollama', 'openai', 'gemini', 'openrouter'].forEach((p) => {
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

  let openrouterModel = $('s-openrouter-model')?.value || 'deepseek/deepseek-r1:free';
  if (openrouterModel === 'custom') {
    openrouterModel = $('s-openrouter-model-custom')?.value || 'deepseek/deepseek-r1:free';
  }

  return {
    provider: currentProvider,
    ollamaEndpoint: $('s-ollama-endpoint')?.value || 'http://localhost:11434',
    ollamaModel,
    openaiApiKey: $('s-openai-key')?.value || '',
    openaiModel,
    geminiApiKey: $('s-gemini-key')?.value || '',
    geminiModel,
    openrouterApiKey: $('s-openrouter-key')?.value || '',
    openrouterModel,
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
    dashboardUrl: $('s-dashboard-url')?.value || 'http://localhost:3000',
    dashboardApiKey: $('s-dashboard-key')?.value || '',
    userEmail: $('s-user-email')?.value || '',
    userName: $('s-user-name')?.value || '',
    department: $('s-department')?.value || '',
    hostname: $('s-hostname')?.value || '',
  };
}

function attachEventListeners() {
  const $ = (id) => document.getElementById(id);

  // Provider switching
  document.querySelectorAll('.prov-btn').forEach((btn) => {
    btn.addEventListener('click', () => switchProvider(btn.dataset.prov));
  });

  // Sidebar Scroll Spy and Navigation
  const sidebarItems = document.querySelectorAll('.sidebar-item');
  const scrollContainer = document.getElementById('scroll-container');
  
  // 1. Click to scroll
  sidebarItems.forEach(item => {
    item.addEventListener('click', () => {
      const targetId = item.dataset.target;
      const targetSection = document.getElementById(targetId);
      if (targetSection && scrollContainer) {
        // Find position of target relative to scroll container
        const containerRect = scrollContainer.getBoundingClientRect();
        const targetRect = targetSection.getBoundingClientRect();
        const scrollOffset = targetRect.top - containerRect.top + scrollContainer.scrollTop - 24; // 24px padding
        scrollContainer.scrollTo({ top: scrollOffset, behavior: 'smooth' });
      }
    });
  });

  // 2. Intersection Observer to highlight active item
  const observerOptions = {
    root: scrollContainer,
    rootMargin: '-20px 0px -60% 0px', // Trigger when section hits the upper third of screen
    threshold: 0
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const id = entry.target.id;
        // Remove active class from all
        sidebarItems.forEach(item => item.classList.remove('active', 'bg-[rgba(37,99,235,0.18)]', 'border', 'border-[rgba(37,99,235,0.4)]', 'text-[#e0eeff]'));
        sidebarItems.forEach(item => item.classList.add('hover:bg-[rgba(255,255,255,0.05)]', 'text-[rgba(255,255,255,0.45)]'));
        
        // Add active class to intersecting item
        const activeItem = document.querySelector(`.sidebar-item[data-target="${id}"]`);
        if (activeItem) {
          activeItem.classList.remove('hover:bg-[rgba(255,255,255,0.05)]', 'text-[rgba(255,255,255,0.45)]');
          activeItem.classList.add('active', 'bg-[rgba(37,99,235,0.18)]', 'border', 'border-[rgba(37,99,235,0.4)]', 'text-[#e0eeff]');
          
          // Also swap icon colors
          sidebarItems.forEach(item => {
             const svg = item.querySelector('svg');
             if (svg) {
                svg.classList.remove('text-[#4a9eff]');
                svg.classList.add('text-[rgba(255,255,255,0.3)]');
             }
          });
          const activeSvg = activeItem.querySelector('svg');
          if (activeSvg) {
             activeSvg.classList.remove('text-[rgba(255,255,255,0.3)]');
             activeSvg.classList.add('text-[#4a9eff]');
          }
        }
      }
    });
  }, observerOptions);

  ['sec-ai', 'sec-analysis', 'sec-url', 'sec-context', 'sec-dashboard', 'sec-stats', 'sec-about'].forEach(id => {
    const el = document.getElementById(id);
    if (el) observer.observe(el);
  });

  const handleModelChange = (e, customId) => {
    const custom = $(customId);
    if (custom) custom.style.display = e.target.value === 'custom' ? 'block' : 'none';
  };

  function attachCustomDropdownListeners(inputId, dropdownId, customInputId) {
    const input = $(inputId);
    const dropdown = $(dropdownId);
    const customBox = $(customInputId);
    if (!input || !dropdown) return;

    const showDropdown = () => {
      dropdown.style.display = 'flex';
      filterDropdown(input.value);
    };

    const filterDropdown = (query) => {
      query = query.toLowerCase();
      Array.from(dropdown.children).forEach(child => {
        const text = child.textContent.toLowerCase();
        const val = child.dataset.value.toLowerCase();
        if (text.includes(query) || val.includes(query) || val === 'custom') {
          child.style.display = 'block';
        } else {
          child.style.display = 'none';
        }
      });
    };

    input.addEventListener('focus', showDropdown);
    input.addEventListener('click', showDropdown);

    input.addEventListener('input', (e) => {
      filterDropdown(e.target.value);
      dropdown.style.display = 'flex';
      if (customBox) customBox.style.display = e.target.value === 'custom' ? 'block' : 'none';
    });

    dropdown.addEventListener('mousedown', (e) => {
      // Prevent the input from losing focus when clicking the scrollbar
      e.preventDefault();
      
      const item = e.target.closest('.custom-dropdown-item');
      if (item) {
        input.value = item.dataset.value;
        dropdown.style.display = 'none';
        if (customBox) customBox.style.display = input.value === 'custom' ? 'block' : 'none';
        input.dispatchEvent(new Event('change'));
      }
    });

    input.addEventListener('blur', () => {
      dropdown.style.display = 'none';
    });
  }

  ['ollama', 'openai', 'gemini'].forEach(prov => {
    $('s-' + prov + '-model')?.addEventListener('change', (e) => handleModelChange(e, 's-' + prov + '-model-custom'));
    $('s-' + prov + '-model')?.addEventListener('input', (e) => handleModelChange(e, 's-' + prov + '-model-custom'));
  });

  attachCustomDropdownListeners('s-openrouter-model', 'openrouter-dropdown', 's-openrouter-model-custom');

  // Dynamic Model Fetching Trigger Listeners (debounced input, blur, paste, refresh buttons)
  const debouncedOpenAIFetch = debounce(() => fetchAndPopulateModels('openai', { isUserTriggered: true }));
  const debouncedGeminiFetch = debounce(() => fetchAndPopulateModels('gemini', { isUserTriggered: true }));
  const debouncedOpenRouterFetch = debounce(() => fetchAndPopulateModels('openrouter', { isUserTriggered: true }));
  const debouncedOllamaFetch = debounce(() => fetchAndPopulateModels('ollama', { isUserTriggered: true }));

  $('s-openai-key')?.addEventListener('input', debouncedOpenAIFetch);
  $('s-openai-key')?.addEventListener('blur', () => fetchAndPopulateModels('openai', { isUserTriggered: false }));
  $('s-openai-key')?.addEventListener('paste', () => setTimeout(() => fetchAndPopulateModels('openai', { isUserTriggered: true }), 100));
  $('refresh-openai-models')?.addEventListener('click', () => fetchAndPopulateModels('openai', { isUserTriggered: true }));

  $('s-gemini-key')?.addEventListener('input', debouncedGeminiFetch);
  $('s-gemini-key')?.addEventListener('blur', () => fetchAndPopulateModels('gemini', { isUserTriggered: false }));
  $('s-gemini-key')?.addEventListener('paste', () => setTimeout(() => fetchAndPopulateModels('gemini', { isUserTriggered: true }), 100));
  $('refresh-gemini-models')?.addEventListener('click', () => fetchAndPopulateModels('gemini', { isUserTriggered: true }));

  $('s-openrouter-key')?.addEventListener('input', debouncedOpenRouterFetch);
  $('s-openrouter-key')?.addEventListener('blur', () => fetchAndPopulateModels('openrouter', { isUserTriggered: false }));
  $('s-openrouter-key')?.addEventListener('paste', () => setTimeout(() => fetchAndPopulateModels('openrouter', { isUserTriggered: true }), 100));
  $('refresh-openrouter-models')?.addEventListener('click', () => fetchAndPopulateModels('openrouter', { isUserTriggered: true }));

  $('s-ollama-endpoint')?.addEventListener('input', debouncedOllamaFetch);
  $('refresh-ollama-models')?.addEventListener('click', () => fetchAndPopulateModels('ollama', { isUserTriggered: true }));

  // Save button
  $('save-btn')?.addEventListener('click', async () => {
    const settings = collectSettings();
    const ok = await saveSettings(settings);
    if (ok) chrome.runtime.sendMessage({ type: 'FORCE_HEARTBEAT' }).catch(() => {});
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
    a.download = `revelio-history-${new Date().toISOString().slice(0, 10)}.json`;
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

// ─── Dynamic Model Discovery ──────────────────────────────────────────────────

function populateModelDropdown(selectEl, customInputEl, models, savedModel) {
  if (!selectEl || !models || models.length === 0) return;

  const previousSelection = savedModel || selectEl.value;
  
  // Check if there is a custom dropdown UI for this selectEl
  const customDropdownId = selectEl.id.replace('s-', '').replace('-model', '') + '-dropdown';
  const customDropdownEl = document.getElementById(customDropdownId);

  let targetEl = customDropdownEl || selectEl;
  targetEl.innerHTML = '';

  let foundMatch = false;

  models.forEach((m) => {
    const id = typeof m === 'object' ? m.id : m;
    const name = typeof m === 'object' ? m.name : m;

    if (customDropdownEl) {
      const div = document.createElement('div');
      div.className = 'px-3 py-2 text-[12px] text-[rgba(255,255,255,0.85)] hover:bg-[#2563eb] cursor-pointer custom-dropdown-item';
      div.textContent = name;
      div.dataset.value = id;
      targetEl.appendChild(div);
    } else {
      const opt = document.createElement('option');
      opt.value = id;
      opt.textContent = name;
      targetEl.appendChild(opt);
    }

    if (id === previousSelection) {
      foundMatch = true;
    }
  });

  // Always keep custom model option at the end
  if (customDropdownEl) {
    const customDiv = document.createElement('div');
    customDiv.className = 'px-3 py-2 text-[12px] text-[rgba(255,255,255,0.85)] hover:bg-[#2563eb] cursor-pointer custom-dropdown-item border-t border-[rgba(255,255,255,0.08)]';
    customDiv.textContent = 'Custom model name...';
    customDiv.dataset.value = 'custom';
    targetEl.appendChild(customDiv);
  } else {
    const customOpt = document.createElement('option');
    customOpt.value = 'custom';
    customOpt.textContent = 'Custom model name...';
    targetEl.appendChild(customOpt);
  }

  if (customDropdownEl) {
    selectEl.value = previousSelection || (typeof models[0] === 'object' ? models[0].id : models[0]);
    if (customInputEl) {
      customInputEl.style.display = selectEl.value === 'custom' ? 'block' : 'none';
    }
  } else if (foundMatch) {
    selectEl.value = previousSelection;
    if (customInputEl) customInputEl.style.display = 'none';
  } else if (previousSelection && previousSelection !== 'custom') {
    selectEl.value = 'custom';
    if (customInputEl) {
      customInputEl.style.display = 'block';
      customInputEl.value = previousSelection;
    }
  } else if (previousSelection === 'custom') {
    selectEl.value = 'custom';
    if (customInputEl) customInputEl.style.display = 'block';
  } else {
    const firstVal = typeof models[0] === 'object' ? models[0].id : models[0];
    selectEl.value = firstVal;
    if (customInputEl) customInputEl.style.display = 'none';
  }
}

async function fetchAndPopulateModels(provider, options = {}) {
  const { savedModel = '', isUserTriggered = false } = options;

  let selectEl, customEl, statusEl, credential;

  switch (provider) {
    case 'ollama':
      selectEl = $('s-ollama-model');
      customEl = $('s-ollama-model-custom');
      statusEl = $('s-ollama-model-status');
      credential = $('s-ollama-endpoint')?.value?.trim() || 'http://localhost:11434';
      break;
    case 'openai':
      selectEl = $('s-openai-model');
      customEl = $('s-openai-model-custom');
      statusEl = $('s-openai-model-status');
      credential = $('s-openai-key')?.value?.trim() || '';
      break;
    case 'gemini':
      selectEl = $('s-gemini-model');
      customEl = $('s-gemini-model-custom');
      statusEl = $('s-gemini-model-status');
      credential = $('s-gemini-key')?.value?.trim() || '';
      break;
    case 'openrouter':
      selectEl = $('s-openrouter-model');
      customEl = $('s-openrouter-model-custom');
      statusEl = $('s-openrouter-model-status');
      credential = $('s-openrouter-key')?.value?.trim() || '';
      break;
    default:
      return;
  }

  if (!selectEl) return;

  // If no credential provided and not Ollama, clear status and return
  if (provider !== 'ollama' && (!credential || credential.length < 5)) {
    if (statusEl) statusEl.textContent = '';
    return;
  }

  if (statusEl) {
    statusEl.textContent = '⏳ Loading models...';
    statusEl.className = 'text-[11px] text-amber-400/80 animate-pulse';
  }

  try {
    const resp = await chrome.runtime.sendMessage({
      type: 'GET_PROVIDER_MODELS',
      provider,
      apiKey: credential,
      endpoint: credential,
    });

    if (resp === undefined) {
      throw new Error('Extension updated. Please reload Revelio in chrome://extensions');
    }

    if (resp && resp.success && resp.models && resp.models.length > 0) {
      populateModelDropdown(selectEl, customEl, resp.models, savedModel || selectEl.value);
      if (statusEl) {
        statusEl.textContent = `✓ ${resp.models.length} models loaded`;
        statusEl.className = 'text-[11px] text-emerald-400';
      }
      if (provider === 'ollama') {
        showOllamaModels(resp.models);
      }
      if (isUserTriggered) {
        showToast(`✓ Loaded ${resp.models.length} models for ${provider.toUpperCase()}`, 'success');
      }
    } else {
      throw new Error(resp?.error || 'No models returned');
    }
  } catch (err) {
    if (statusEl) {
      statusEl.textContent = isUserTriggered ? '⚠️ Could not load models' : '';
      statusEl.className = 'text-[11px] text-rose-400';
    }
    if (isUserTriggered) {
      showToast(`Failed to fetch models: ${err.message?.slice(0, 80)}`, 'error');
    }
  }
}

function debounce(fn, ms = 600) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

