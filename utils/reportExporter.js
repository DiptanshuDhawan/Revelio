// PhishGuard AI — Report Exporter
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

export function exportPDF(analysisResult) {
  const r = analysisResult;
  const llm = r.llmResult || {};
  const rule = r.ruleResult || {};
  const cats = llm.categories || {};
  const now = new Date().toLocaleString();

  const score = r.finalScore || 0;
  const verdictColor = score >= 86 ? '#ef4444' : score >= 70 ? '#f97316' : score >= 40 ? '#f59e0b' : '#22c55e';
  const gaugeColor = verdictColor;

  // SVG Gauge for print
  const radius = 60;
  const circumference = Math.PI * radius;
  const dashOffset = circumference - (score / 100) * circumference;

  const categoryRows = Object.entries({
    '🎭 Impersonation': cats.impersonation,
    '⏰ Urgency Manipulation': cats.urgencyManipulation,
    '🧠 Social Engineering': cats.socialEngineering,
    '🔗 Technical Indicators': cats.technicalIndicators,
    '🤖 AI-Generated Signs': cats.aiGeneratedSigns,
  }).map(([label, val]) => {
    const pct = (val || 0) + '%';
    const color = val >= 70 ? '#ef4444' : val >= 40 ? '#f59e0b' : '#22c55e';
    return `
      <tr>
        <td style="padding: 6px 0; font-weight: 500;">${label}</td>
        <td style="padding: 6px 0;">
          <div style="background:#e5e7eb;border-radius:4px;height:10px;width:200px;overflow:hidden;">
            <div style="background:${color};height:100%;width:${pct};border-radius:4px;"></div>
          </div>
        </td>
        <td style="padding:6px 8px;font-weight:bold;color:${color};">${val ?? 0}</td>
      </tr>`;
  }).join('');

  const findingsHTML = (llm.topFindings || []).map((f, i) =>
    `<li style="margin-bottom:8px;">${f}</li>`
  ).join('');

  const remediationHTML = (llm.remediationSteps || []).map((s, i) =>
    `<li style="margin-bottom:8px;">${s}</li>`
  ).join('');

  const quotesHTML = (llm.suspiciousQuotes || []).map((q) =>
    `<div style="background:#fef2f2;border-left:4px solid #ef4444;padding:8px 12px;margin-bottom:8px;border-radius:0 4px 4px 0;font-style:italic;color:#991b1b;">"${q}"</div>`
  ).join('');

  const badgesHTML = [
    llm.becRisk ? '<span style="background:#fef3c7;color:#92400e;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;margin-right:6px;">BEC RISK</span>' : '',
    llm.spearPhishingRisk ? '<span style="background:#fce7f3;color:#9d174d;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;margin-right:6px;">SPEAR-PHISHING</span>' : '',
    llm.aiGeneratedRisk ? '<span style="background:#ede9fe;color:#5b21b6;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;margin-right:6px;">AI-GENERATED</span>' : '',
  ].filter(Boolean).join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Revelio — Threat Analysis Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #111827; background: #f9fafb; }
    .page { max-width: 900px; margin: 0 auto; padding: 40px; background: white; }
    .header { display: flex; align-items: center; gap: 16px; border-bottom: 3px solid #1e40af; padding-bottom: 20px; margin-bottom: 30px; }
    .header-icon { width: 48px; height: 48px; background: linear-gradient(135deg, #1d4ed8, #7c3aed); border-radius: 12px; display: flex; align-items: center; justify-content: center; }
    .header h1 { font-size: 24px; font-weight: 800; color: #1e40af; }
    .header p { font-size: 13px; color: #6b7280; margin-top: 2px; }
    .score-section { display: flex; align-items: center; gap: 40px; background: linear-gradient(135deg, #0f172a, #1e293b); color: white; border-radius: 16px; padding: 30px; margin-bottom: 24px; }
    .gauge-wrap { text-align: center; }
    .score-details { flex: 1; }
    .score-details h2 { font-size: 36px; font-weight: 900; color: ${verdictColor}; }
    .score-details p { color: #94a3b8; margin-top: 4px; }
    .score-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 16px; }
    .score-item { background: rgba(255,255,255,0.05); border-radius: 8px; padding: 8px 12px; }
    .score-item label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }
    .score-item span { font-size: 16px; font-weight: 700; color: white; display: block; }
    .section { margin-bottom: 24px; }
    .section h3 { font-size: 16px; font-weight: 700; color: #1e293b; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; margin-bottom: 16px; }
    .finding-card { border-left: 4px solid #e5e7eb; padding: 10px 14px; margin-bottom: 10px; border-radius: 0 8px 8px 0; background: #f8fafc; }
    .finding-card.critical { border-color: #ef4444; }
    .finding-card.high { border-color: #f97316; }
    .finding-card.medium { border-color: #f59e0b; }
    .finding-card.low { border-color: #22c55e; }
    .mitre-badge { display: inline-block; background: #1e40af; color: white; padding: 4px 12px; border-radius: 20px; font-size: 13px; font-weight: 600; }
    .recommended { background: #fef3c7; border-radius: 8px; padding: 12px 16px; color: #92400e; font-weight: 500; }
    .footer { margin-top: 40px; border-top: 1px solid #e5e7eb; padding-top: 16px; color: #9ca3af; font-size: 12px; text-align: center; }
    @media print {
      body { background: white; }
      .page { padding: 20px; }
      @page { margin: 1cm; }
    }
  </style>
</head>
<body>
<div class="page">
  <!-- Header -->
  <div class="header">
    <div class="header-icon">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>
    </div>
    <div>
      <h1>Revelio — Threat Analysis Report</h1>
      <p>Generated: ${now}</p>
    </div>
  </div>

  <!-- Score Section -->
  <div class="score-section">
    <div class="gauge-wrap">
      <svg width="140" height="80" viewBox="0 0 140 80">
        <defs>
          <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="#22c55e"/>
            <stop offset="50%" stop-color="#f59e0b"/>
            <stop offset="100%" stop-color="#ef4444"/>
          </linearGradient>
        </defs>
        <path d="M 10 75 A 60 60 0 0 1 130 75" fill="none" stroke="#334155" stroke-width="12" stroke-linecap="round"/>
        <path d="M 10 75 A 60 60 0 0 1 130 75" fill="none" stroke="${gaugeColor}" stroke-width="12"
          stroke-linecap="round" stroke-dasharray="${circumference}" stroke-dashoffset="${dashOffset}"
          style="transform-origin:70px 75px;transform:rotate(0deg)"/>
        <text x="70" y="68" text-anchor="middle" font-size="22" font-weight="900" fill="white">${score}</text>
        <text x="70" y="78" text-anchor="middle" font-size="9" fill="#94a3b8">/ 100</text>
      </svg>
      <div style="color:${verdictColor};font-weight:900;font-size:13px;margin-top:4px;">${llm.verdict || 'Unknown'}</div>
    </div>
    <div class="score-details">
      <h2>${llm.verdict || 'Unknown'}</h2>
      <p>${llm.attackVector ? 'Attack Vector: ' + llm.attackVector : ''}</p>
      <div class="score-grid" style="margin-top:12px;">
        <div class="score-item"><label>AI Score</label><span>${llm.llmScore ?? 'N/A'}</span></div>
        <div class="score-item"><label>Rule Score</label><span>${rule.ruleScore ?? 'N/A'}</span></div>
        <div class="score-item"><label>Confidence</label><span>${llm.confidence || 'N/A'}</span></div>
        <div class="score-item"><label>Final Score</label><span style="color:${verdictColor};">${score}</span></div>
      </div>
      ${badgesHTML ? `<div style="margin-top:12px;">${badgesHTML}</div>` : ''}
    </div>
  </div>

  <!-- Category Scores -->
  <div class="section">
    <h3>Category Scores</h3>
    <table style="width:100%;border-collapse:collapse;">${categoryRows}</table>
  </div>

  <!-- Top Findings -->
  ${findingsHTML ? `<div class="section"><h3>AI Top Findings</h3><ol style="padding-left:20px;color:#374151;line-height:1.6;">${findingsHTML}</ol></div>` : ''}

  <!-- Suspicious Quotes -->
  ${quotesHTML ? `<div class="section"><h3>Suspicious Quotes</h3>${quotesHTML}</div>` : ''}

  <!-- Rule Engine Findings -->
  ${rule.findings ? `<div class="section"><h3>Rule Engine Results</h3>
  ${rule.findings.map((f) => `
    <div class="finding-card ${f.severity}">
      <div style="font-weight:600;font-size:14px;">${f.passed ? '✓' : '⚠'} ${f.name}</div>
      <div style="font-size:13px;color:#4b5563;margin-top:4px;">${f.finding}</div>
      ${f.quote ? `<div style="font-size:12px;color:#ef4444;margin-top:4px;font-family:monospace;">"${f.quote}"</div>` : ''}
    </div>`).join('')}
  </div>` : ''}

  <!-- Recommended Action -->
  ${llm.recommendedAction ? `
  <div class="section">
    <h3>Recommended Action</h3>
    <div class="recommended">⚠ ${llm.recommendedAction}</div>
  </div>` : ''}

  <!-- Remediation Steps -->
  ${remediationHTML ? `<div class="section"><h3>Remediation Steps</h3><ol style="padding-left:20px;color:#374151;line-height:1.8;">${remediationHTML}</ol></div>` : ''}

  <!-- MITRE ATT&CK -->
  ${llm.mitreAttack?.id ? `
  <div class="section">
    <h3>MITRE ATT&CK</h3>
    <span class="mitre-badge">${llm.mitreAttack.id} — ${llm.mitreAttack.name || 'Phishing'}</span>
    <p style="font-size:13px;color:#6b7280;margin-top:8px;">Reference: <a href="${llm.mitreAttack.url}">${llm.mitreAttack.url}</a></p>
  </div>` : ''}

  <!-- Analyst Note -->
  ${llm.analystNote ? `
  <div class="section">
    <h3>Analyst Note</h3>
    <p style="color:#374151;font-style:italic;">${llm.analystNote}</p>
  </div>` : ''}

  <div class="footer">
    <p>Report generated by Revelio v1.0.0 — Confidential Security Analysis</p>
    <p>This report is intended for authorized security personnel only.</p>
  </div>
</div>
<script>setTimeout(() => window.print(), 500);</script>
</body>
</html>`;

  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  window.open(url, '_blank');
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}
