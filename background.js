// PhishGuard AI — Background Service Worker (Manifest V3)
// All external API calls are routed through here to avoid CORS issues in the popup.

import { getSettings, saveSettings } from './utils/storage.js';

// ─── Context Menu Setup ───────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'phishguard-analyze',
    title: '🛡️ Analyze with PhishGuard AI',
    contexts: ['selection'],
  });

  // Default settings initialization
  getSettings().then((settings) => {
    if (!settings.initialized) {
      saveSettings({
        initialized: true,
        provider: 'ollama',
        ollamaEndpoint: 'http://localhost:11434',
        ollamaModel: 'deepseek-r1:8b',
        openaiApiKey: '',
        openaiModel: 'gpt-4o-mini',
        geminiApiKey: '',
        geminiModel: 'gemini-1.5-flash',
        grokApiKey: '',
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
});

// ─── Context Menu Click Handler ───────────────────────────────────────────────

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'phishguard-analyze') return;

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
});

// ─── Message Handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'ANALYZE') {
    handleAnalyze(message)
      .then((result) => sendResponse({ success: true, data: result }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // Keep message channel open for async response
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

  if (message.type === 'GET_OLLAMA_MODELS') {
    getOllamaModels(message.endpoint)
      .then((models) => sendResponse({ success: true, models }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }
});

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

async function handleAnalyze({ emailText, settings }) {
  const provider = settings.provider || 'ollama';
  const prompt = buildAnalysisPrompt(emailText);

  let llmResponse;

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
    case 'grok':
      llmResponse = await callGrok(prompt, settings);
      break;
    default:
      throw new Error('Unknown AI provider: ' + provider);
  }

  return llmResponse;
}

// ─── Prompt Builder ───────────────────────────────────────────────────────────

function buildAnalysisPrompt(emailText) {
  return `You are PhishGuard, an elite AI analyst trained by a team of senior SOC engineers, threat intelligence specialists, and red team operators with 15+ years of combined experience in email security, phishing investigation, and business email compromise (BEC) forensics.

Your mission: analyze emails with the precision of a forensic investigator and the communication clarity of a CISO-level executive briefing.

You have deep expertise in:
- Social engineering psychology and manipulation techniques
- Technical email authentication (SPF, DKIM, DMARC, email headers)
- MITRE ATT&CK framework, specifically the Initial Access and Phishing tactic (T1566)
- Business Email Compromise (BEC) patterns and financial fraud tactics
- AI-generated phishing detection (hallmarks of LLM-written emails)
- Spear-phishing vs mass phishing differentiation
- Domain spoofing, homograph attacks, and lookalike infrastructure
- Urgency and authority manipulation (pretexting, impersonation, fear tactics)

ANALYSIS APPROACH (Chain-of-Thought — execute internally):
1. Read the full email. Note sender, subject, tone, and intent.
2. Identify the primary attack vector (if any): credential theft, malware delivery, financial fraud, information gathering, or account takeover.
3. Check for brand impersonation, domain mismatches, or authority abuse.
4. Evaluate psychological manipulation: urgency, fear, scarcity, authority, social proof.
5. Assess writing style: AI-generated patterns (overly formal, unnaturally perfect grammar, generic corporate template feel, excessive action button language).
6. Identify spear-phishing signals: personalized details, specific company references, named individuals, role-specific language.
7. Map to MITRE ATT&CK if applicable.
8. Formulate a specific, actionable recommendation.

OUTPUT: Respond ONLY with a valid JSON object. No markdown fences. No text outside JSON.

{
  "llmScore": <integer 0-100, phishing probability>,
  "verdict": "<Safe | Suspicious | Likely Phishing | Confirmed Phishing>",
  "confidence": "<Low | Medium | High>",
  "attackVector": "<Credential Theft | Malware Delivery | Financial Fraud | Info Gathering | Account Takeover | Unknown | N/A>",
  "categories": {
    "impersonation": <0-100>,
    "urgencyManipulation": <0-100>,
    "socialEngineering": <0-100>,
    "technicalIndicators": <0-100>,
    "aiGeneratedSigns": <0-100>
  },
  "topFindings": [
    "<specific finding 1 with reference to email content>",
    "<specific finding 2>",
    "<specific finding 3>"
  ],
  "suspiciousQuotes": [
    "<verbatim suspicious phrase from email 1>",
    "<verbatim suspicious phrase from email 2>"
  ],
  "mitreAttack": {
    "id": "<T1566 or sub-technique or null>",
    "name": "<technique name or null>",
    "url": "<https://attack.mitre.org/... or null>"
  },
  "becRisk": <true|false>,
  "spearPhishingRisk": <true|false>,
  "aiGeneratedRisk": <true|false>,
  "becDetails": "<if becRisk true: describe the BEC pattern, else null>",
  "recommendedAction": "<specific, actionable instruction for the recipient>",
  "remediationSteps": [
    "<step 1>",
    "<step 2>",
    "<step 3>",
    "<step 4>",
    "<step 5>"
  ],
  "analystNote": "<one sentence of expert color commentary a SOC analyst would add>"
}

EMAIL TO ANALYZE:
---
${emailText}
---`;
}

// ─── AI Provider Implementations ─────────────────────────────────────────────

async function callOllama(prompt, settings) {
  const endpoint = settings.ollamaEndpoint || 'http://localhost:11434';
  const model = settings.ollamaModel || 'deepseek-r1:8b';

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
    const text = await response.text().catch(() => '');
    throw new Error(`Ollama error ${response.status}: ${text}`);
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

  const model = settings.geminiModel || 'gemini-1.5-flash';

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

async function callGrok(prompt, settings) {
  const apiKey = settings.grokApiKey;
  if (!apiKey) throw new Error('Grok API key not configured');

  const response = await fetch('https://api.x.ai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: 'grok-beta',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.1,
    }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(`Grok error: ${err.error?.message || response.status}`);
  }

  const data = await response.json();
  const content = data.choices?.[0]?.message?.content;
  return parseAIResponse(content);
}

// ─── Response Parser ──────────────────────────────────────────────────────────

function parseAIResponse(rawText) {
  if (!rawText) throw new Error('Empty response from AI');

  // Strip markdown fences if present
  let cleaned = rawText.trim();
  cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '');

  // Find JSON object boundaries
  const start = cleaned.indexOf('{');
  const end = cleaned.lastIndexOf('}');
  if (start === -1 || end === -1) throw new Error('No valid JSON in AI response');

  const jsonStr = cleaned.slice(start, end + 1);

  let parsed;
  try {
    parsed = JSON.parse(jsonStr);
  } catch (e) {
    throw new Error('Invalid JSON from AI: ' + e.message);
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
    topFindings: Array.isArray(parsed.topFindings) ? parsed.topFindings.slice(0, 5) : [],
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
