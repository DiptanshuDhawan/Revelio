// Revelio — Report Exporter
// Generates formatted clipboard reports and print-ready PDF views.

'use strict';

// ─── Text Formatting Helpers ──────────────────────────────────────────────────

function padRight(str, len) {
  return str.toString().padEnd(len);
}

function asciiBar(score, width = 20) {
  const filled = Math.round((score / 100) * width);
  return '█'.repeat(filled) + '░'.repeat(width - filled);
}

function formatScore(score) {
  if (score === null || score === undefined) return 'N/A';
  return String(score).padStart(3);
}

// ─── Copy to Clipboard ────────────────────────────────────────────────────────

export async function copyToClipboard(analysisResult) {
  const r = analysisResult;
  const llm = r.llmResult || {};
  const rule = r.ruleResult || {};
  const cats = llm.categories || {};
  const now = new Date().toLocaleString();

  const lines = [
    '═══════════════════════════════════════════════════════',
    '  REVELIO — THREAT ANALYSIS REPORT',
    `  Generated: ${now}`,
    '═══════════════════════════════════════════════════════',
    '',
    `  RISK SCORE: ${r.finalScore}/100 — ${llm.verdict || 'Unknown'}`,
    `  AI Score: ${llm.llmScore ?? 'N/A'} | Rule Score: ${rule.ruleScore ?? 'N/A'}`,
    `  Confidence: ${llm.confidence || 'N/A'} | Attack Vector: ${llm.attackVector || 'N/A'}`,
    '',
  ];

  // Special risk badges
  const badges = [];
  if (llm.becRisk) badges.push('[BEC RISK]');
  if (llm.spearPhishingRisk) badges.push('[SPEAR-PHISHING]');
  if (llm.aiGeneratedRisk) badges.push('[AI-GENERATED]');
  if (badges.length > 0) {
    lines.push(`  Risk Flags: ${badges.join(' ')}`);
    lines.push('');
  }

  // Category scores
  lines.push('  CATEGORY SCORES:');
  const categoryLabels = {
    impersonation: '🎭 Impersonation',
    urgencyManipulation: '⏰ Urgency Manipulation',
    socialEngineering: '🧠 Social Engineering',
    technicalIndicators: '🔗 Technical Indicators',
    aiGeneratedSigns: '🤖 AI-Generated Signs',
  };

  for (const [key, label] of Object.entries(categoryLabels)) {
    const score = cats[key] ?? 0;
    lines.push(`  ${padRight(label, 24)} ${asciiBar(score)} ${formatScore(score)}`);
  }
  lines.push('');

  // Top findings
  if (llm.topFindings && llm.topFindings.length > 0) {
    lines.push('  TOP FINDINGS:');
    llm.topFindings.forEach((f, i) => {
      lines.push(`  ${i + 1}. ${f}`);
    });
    lines.push('');
  }

  // Suspicious quotes
  if (llm.suspiciousQuotes && llm.suspiciousQuotes.length > 0) {
    lines.push('  SUSPICIOUS QUOTES:');
    llm.suspiciousQuotes.forEach((q) => {
      lines.push(`  ▶ "${q}"`);
    });
    lines.push('');
  }

  // Remediation
  if (llm.remediationSteps && llm.remediationSteps.length > 0) {
    lines.push('  REMEDIATION STEPS:');
    llm.remediationSteps.forEach((step, i) => {
      lines.push(`  ${i + 1}. ${step}`);
    });
    lines.push('');
  }

  // MITRE ATT&CK
  if (llm.mitreAttack?.id) {
    lines.push(`  MITRE ATT&CK: ${llm.mitreAttack.id} — ${llm.mitreAttack.name || ''}`);
    if (llm.mitreAttack.url) lines.push(`  Reference: ${llm.mitreAttack.url}`);
    lines.push('');
  }

  // Analyst note
  if (llm.analystNote) {
    lines.push(`  Analyst Note: ${llm.analystNote}`);
    lines.push('');
  }

  lines.push('═══════════════════════════════════════════════════════');

  const reportText = lines.join('\n');

  try {
    await navigator.clipboard.writeText(reportText);
    return true;
  } catch (e) {
    // Fallback for restricted contexts
    const ta = document.createElement('textarea');
    ta.value = reportText;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  }
}

// ─── Export PDF ───────────────────────────────────────────────────────────────

export async function exportPDF(analysisResult) {
  const r = analysisResult;
  const llm = r.llmResult || {};
  const rule = r.ruleResult || {};
  const cats = llm.categories || {};

  const reportData = {
    generatedAt: new Date().toISOString(),
    verdict: llm.verdict || 'Unknown Threat',
    attackVector: llm.attackVector || 'Unknown Vector',
    confidence: llm.confidence || 'Medium',
    scores: {
      ai: llm.llmScore ?? 0,
      rules: rule.ruleScore ?? 0,
      final: r.finalScore ?? 0
    },
    tags: [],
    signals: {
      impersonation: cats.impersonation ?? 0,
      urgency: cats.urgencyManipulation ?? 0,
      socialEngineering: cats.socialEngineering ?? 0,
      technicalDeception: cats.technicalIndicators ?? 0,
      aiGenerated: cats.aiGeneratedSigns ?? 0
    },
    findings: [],
    recommendedAction: llm.remediationSteps?.[0] || llm.recommendedAction || 'Exercise extreme caution.',
    mitre: {
      id: llm.mitreAttack?.id || '',
      name: llm.mitreAttack?.name || '',
      url: llm.mitreAttack?.url || ''
    },
    version: chrome.runtime.getManifest().version || '1.0.0'
  };

  if (llm.becRisk) reportData.tags.push({ label: 'BEC Risk', type: 'red' });
  if (llm.spearPhishingRisk) reportData.tags.push({ label: 'Spear-Phishing', type: 'red' });
  if (llm.aiGeneratedRisk) reportData.tags.push({ label: 'AI-Generated', type: 'amber' });

  (rule.findings || []).filter(f => !f.passed).forEach(f => {
    reportData.findings.push({
      title: f.name,
      description: f.finding,
      evidence: f.quote || null,
      severity: f.severity || 'low'
    });
  });

  (llm.topFindings || []).forEach(f => {
    reportData.findings.push({
      title: f.title || 'AI Finding',
      description: f.detail || f.description || '',
      evidence: null,
      severity: f.severity || 'high'
    });
  });

  try {
    const base64Data = btoa(encodeURIComponent(JSON.stringify(reportData)));
    const url = chrome.runtime.getURL('report/report.html') + '#' + base64Data;
    chrome.tabs.create({ url });
  } catch (e) {
    console.error('Failed to generate report:', e);
    alert('Failed to generate report: ' + e.message);
  }
}