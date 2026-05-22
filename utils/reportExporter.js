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
  const now = new Date().toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC';

  const score = r.finalScore || 0;
  const verdictColor = score >= 86 ? '#ef4444' : score >= 70 ? '#f97316' : score >= 40 ? '#f59e0b' : '#10b981';

  // ── Helpers ──
  function scoreColor(v) {
    return v >= 70 ? '#ef4444' : v >= 40 ? '#f59e0b' : '#10b981';
  }
  function severityColor(sev) {
    return sev === 'critical' ? '#ef4444' : sev === 'high' ? '#f97316' : sev === 'medium' ? '#f59e0b' : '#10b981';
  }
  function iconFor(sev) {
    return sev === 'critical' || sev === 'high' ? 'warning' : sev === 'medium' ? 'info' : 'check_circle';
  }

  // ── Category Scores ──
  const categoryDefs = [
    { key: 'impersonation',        label: 'Impersonation',        icon: 'person_off' },
    { key: 'urgencyManipulation',  label: 'Urgency Manipulation',  icon: 'timer' },
    { key: 'socialEngineering',    label: 'Social Engineering',    icon: 'psychology' },
    { key: 'technicalIndicators',  label: 'Technical Indicators',  icon: 'code' },
    { key: 'aiGeneratedSigns',     label: 'AI-Generated Signs',    icon: 'smart_toy' },
  ];
  const categoryRowsHTML = categoryDefs.map(({ key, label, icon }) => {
    const val = cats[key] ?? 0;
    const col = scoreColor(val);
    return `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">
      <div style="display:flex;align-items:center;gap:8px;width:38%;">
        <span class="material-symbols-outlined" style="color:#87929a;font-size:18px;">${icon}</span>
        <span style="font-family:Inter,sans-serif;font-size:14px;color:#bdc8d1;">${label}</span>
      </div>
      <div style="flex:1;background:#303539;height:8px;border-radius:9999px;overflow:hidden;margin:0 16px;">
        <div style="background:${col};height:100%;width:${val}%;border-radius:9999px;"></div>
      </div>
      <div style="width:36px;text-align:right;font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;color:${col};">${val}</div>
    </div>`;
  }).join('');

  // ── AI Top Findings ──
  const findingsHTML = (llm.topFindings || []).map((f, i) => `
    <div style="display:flex;align-items:flex-start;gap:10px;background:rgba(30,41,59,0.4);border:1px solid rgba(255,255,255,0.08);border-left:3px solid #ef4444;border-radius:0 8px 8px 0;padding:12px 14px;margin-bottom:10px;backdrop-filter:blur(12px);">
      <span class="material-symbols-outlined" style="color:#ef4444;font-size:18px;margin-top:1px;">warning</span>
      <p style="font-family:Inter,sans-serif;font-size:13px;color:#bdc8d1;margin:0;">${f}</p>
    </div>`).join('');

  // ── Rule Engine Findings ──
  const ruleFindings = (rule.findings || []).filter(f => !f.passed).map(f => {
    const col = severityColor(f.severity);
    const icon = iconFor(f.severity);
    return `
    <div style="display:flex;align-items:flex-start;gap:10px;background:rgba(30,41,59,0.4);border:1px solid rgba(255,255,255,0.08);border-left:3px solid ${col};border-radius:0 8px 8px 0;padding:12px 14px;margin-bottom:10px;backdrop-filter:blur(12px);">
      <span class="material-symbols-outlined" style="color:${col};font-size:18px;margin-top:1px;">${icon}</span>
      <div style="flex:1;">
        <div style="font-family:Inter,sans-serif;font-size:13px;font-weight:700;color:#dee3e8;margin-bottom:4px;">${f.name}</div>
        <div style="font-family:Inter,sans-serif;font-size:12px;color:#bdc8d1;">${f.finding}</div>
        ${f.quote ? `<code style="display:block;margin-top:6px;font-family:'JetBrains Mono',monospace;font-size:11px;color:${col};background:#303539;border:1px solid rgba(62,72,79,0.5);padding:4px 8px;border-radius:4px;">"${f.quote}"</code>` : ''}
      </div>
    </div>`;
  }).join('');

  // ── Remediation Steps ──
  const remediationHTML = (llm.remediationSteps || []).map((s, i) => `
    <li style="font-family:Inter,sans-serif;font-size:13px;color:#bdc8d1;margin-bottom:10px;line-height:1.6;">${s}</li>`).join('');

  // ── Risk Badges ──
  const badgesHTML = [
    llm.becRisk ? `<span style="padding:3px 10px;border-radius:4px;border:1px solid rgba(241,160,43,0.5);background:rgba(241,160,43,0.15);color:#ffc176;font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;">BEC Risk</span>` : '',
    llm.spearPhishingRisk ? `<span style="padding:3px 10px;border-radius:4px;border:1px solid rgba(239,68,68,0.5);background:rgba(239,68,68,0.15);color:#ffb4ab;font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;">Spear-Phishing</span>` : '',
    llm.aiGeneratedRisk ? `<span style="padding:3px 10px;border-radius:4px;border:1px solid rgba(142,213,255,0.3);background:rgba(142,213,255,0.1);color:#8ed5ff;font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;">AI-Generated</span>` : '',
  ].filter(Boolean).join(' ');

  const separatorLine = `<div style="height:1px;background:linear-gradient(90deg,transparent,rgba(255,255,255,0.1),transparent);margin:28px 0;"></div>`;

  const html = `<!DOCTYPE html>
<html class="dark" lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Revelio — Threat Analysis Report</title>
  <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet"/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&family=Geist:wght@400;600;700&display=swap" rel="stylesheet"/>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { background:#0f1418; color:#dee3e8; font-family:Inter,sans-serif; font-size:14px; line-height:20px; min-height:100vh; }
    .glass-panel { background:rgba(30,41,59,0.4); backdrop-filter:blur(12px); border:1px solid rgba(255,255,255,0.08); }
    .critical-glow { box-shadow:0 0 20px rgba(239,68,68,0.15); }
    .separator-line { height:1px; background:linear-gradient(90deg,transparent,rgba(255,255,255,0.1),transparent); margin:28px 0; }
    .threat-gauge-conic {
      background: conic-gradient(from 180deg at 50% 100%, #10b981 0deg, #f59e0b 90deg, #ef4444 180deg);
      mask-image: radial-gradient(circle at 50% 100%, transparent 55%, black 56%);
      -webkit-mask-image: radial-gradient(circle at 50% 100%, transparent 55%, black 56%);
    }
    section { margin-bottom:0; }
    @media print {
      body { background:#0f1418 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
      @page { margin:0.8cm; }
    }
  </style>
</head>
<body style="padding:0;">
  <!-- Header -->
  <header style="background:#0f1418;border-bottom:1px solid #3e484f;position:sticky;top:0;z-index:50;backdrop-filter:blur(8px);">
    <div style="max-width:860px;margin:0 auto;padding:16px 40px;display:flex;justify-content:space-between;align-items:center;">
      <div style="display:flex;align-items:center;gap:10px;">
        <span class="material-symbols-outlined" style="color:#8ed5ff;font-size:24px;">shield</span>
        <h1 style="font-family:Geist,sans-serif;font-size:18px;font-weight:700;color:#8ed5ff;letter-spacing:-0.02em;">Revelio</h1>
      </div>
      <div style="text-align:right;">
        <div style="font-family:Geist,sans-serif;font-size:16px;font-weight:600;color:#dee3e8;">Threat Analysis Report</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#87929a;text-transform:uppercase;letter-spacing:0.05em;margin-top:2px;">Generated: ${now}</div>
      </div>
    </div>
  </header>

  <main style="max-width:860px;margin:0 auto;padding:32px 40px;">

    <!-- Executive Summary -->
    <section class="glass-panel critical-glow" style="border-radius:12px;padding:28px;display:flex;gap:32px;align-items:center;border-left:4px solid ${verdictColor};position:relative;overflow:hidden;margin-bottom:28px;">
      <div style="position:absolute;inset:0;opacity:0.03;pointer-events:none;background-image:radial-gradient(${verdictColor} 1px, transparent 1px);background-size:24px 24px;"></div>

      <!-- Gauge -->
      <div style="flex-shrink:0;display:flex;flex-direction:column;align-items:center;position:relative;z-index:1;padding-right:20px;">
        <div style="position:relative;width:200px;height:100px;">
          <div class="threat-gauge-conic" style="position:absolute;inset:0;opacity:0.25;border-radius:100px 100px 0 0;"></div>
          <div class="threat-gauge-conic" style="position:absolute;inset:0;border-radius:100px 100px 0 0;clip-path:polygon(0 0,100% 0,100% 100%,0 100%);"></div>
          <div style="position:absolute;bottom:0;left:0;right:0;display:flex;flex-direction:column;align-items:center;padding-bottom:4px;">
            <span style="font-family:Geist,sans-serif;font-size:48px;font-weight:700;color:${verdictColor};line-height:1;">${score}</span>
            <span style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#87929a;text-transform:uppercase;margin-top:4px;">/ 100</span>
          </div>
        </div>
      </div>

      <!-- Verdict Details -->
      <div style="flex:1;position:relative;z-index:1;">
        <h2 style="font-family:Geist,sans-serif;font-size:18px;font-weight:700;color:${verdictColor};text-transform:uppercase;letter-spacing:0.08em;display:flex;align-items:center;gap:8px;margin-bottom:4px;">
          <span class="material-symbols-outlined" style="font-size:20px;">warning</span>
          ${llm.verdict || 'Unknown'}
        </h2>
        <p style="font-family:Inter,sans-serif;font-size:13px;color:#bdc8d1;margin-bottom:20px;">${llm.attackVector ? 'Attack Vector: ' + llm.attackVector : ''}</p>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:0;">
          ${[['AI Score', llm.llmScore ?? 'N/A', '#dee3e8'], ['Rule Score', rule.ruleScore ?? 'N/A', '#dee3e8'], ['Confidence', llm.confidence || 'N/A', '#dee3e8'], ['Final Score', score, verdictColor]].map(([lbl, val, col]) => `
          <div style="background:#171c20;border:1px solid rgba(62,72,79,0.3);border-radius:8px;padding:10px 14px;display:flex;justify-content:space-between;align-items:center;">
            <span style="font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:500;color:#87929a;text-transform:uppercase;letter-spacing:0.05em;">${lbl}</span>
            <span style="font-family:Geist,sans-serif;font-size:18px;font-weight:600;color:${col};">${val}</span>
          </div>`).join('')}
        </div>
        ${badgesHTML ? `<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:20px;">${badgesHTML}</div>` : ''}
      </div>
    </section>

    ${separatorLine}

    <!-- Category Scores -->
    <section style="margin-bottom:28px;">
      <h3 style="font-family:Geist,sans-serif;font-size:16px;font-weight:600;color:#dee3e8;display:flex;align-items:center;gap:8px;margin-bottom:20px;">
        <span class="material-symbols-outlined" style="color:#38bdf8;font-size:20px;">analytics</span>
        Category Scores
      </h3>
      ${categoryRowsHTML}
    </section>

    ${separatorLine}

    <!-- AI Top Findings -->
    ${findingsHTML ? `
    <section style="margin-bottom:28px;">
      <h3 style="font-family:Geist,sans-serif;font-size:16px;font-weight:600;color:#dee3e8;display:flex;align-items:center;gap:8px;margin-bottom:16px;">
        <span class="material-symbols-outlined" style="color:#38bdf8;font-size:20px;">list_alt</span>
        AI Top Findings
      </h3>
      ${findingsHTML}
    </section>
    ${separatorLine}` : ''}

    <!-- Rule Engine Results -->
    ${ruleFindings ? `
    <section style="margin-bottom:28px;">
      <h3 style="font-family:Geist,sans-serif;font-size:16px;font-weight:600;color:#dee3e8;display:flex;align-items:center;gap:8px;margin-bottom:16px;">
        <span class="material-symbols-outlined" style="color:#38bdf8;font-size:20px;">rule</span>
        Rule Engine Results
      </h3>
      ${ruleFindings}
    </section>
    ${separatorLine}` : ''}

    <!-- Recommended Action & Remediation -->
    <section style="margin-bottom:28px;">
      <h3 style="font-family:Geist,sans-serif;font-size:16px;font-weight:600;color:#dee3e8;display:flex;align-items:center;gap:8px;margin-bottom:16px;">
        <span class="material-symbols-outlined" style="color:#38bdf8;font-size:20px;">medical_services</span>
        Recommended Action
      </h3>
      ${llm.recommendedAction ? `
      <div style="background:rgba(241,160,43,0.08);border:1px solid rgba(241,160,43,0.25);border-radius:8px;padding:14px 16px;display:flex;align-items:flex-start;gap:10px;margin-bottom:20px;">
        <span class="material-symbols-outlined" style="color:#f1a02b;font-size:20px;margin-top:1px;">report_problem</span>
        <p style="font-family:Inter,sans-serif;font-size:13px;color:#bdc8d1;"><strong style="color:#f1a02b;">Do not click any links, do not provide any information, and do not open any attachments.</strong> ${llm.recommendedAction}</p>
      </div>` : ''}
      ${remediationHTML ? `
      <h4 style="font-family:Inter,sans-serif;font-size:13px;font-weight:700;color:#dee3e8;margin-bottom:12px;">Remediation Steps</h4>
      <ol style="padding-left:20px;list-style:decimal;">${remediationHTML}</ol>` : ''}
    </section>

    ${separatorLine}

    <!-- MITRE & Analyst Note -->
    <section style="display:grid;grid-template-columns:1fr 1fr;gap:32px;margin-bottom:28px;">
      ${llm.mitreAttack?.id ? `
      <div>
        <h3 style="font-family:Geist,sans-serif;font-size:16px;font-weight:600;color:#dee3e8;display:flex;align-items:center;gap:8px;margin-bottom:14px;">
          <span class="material-symbols-outlined" style="color:#38bdf8;font-size:20px;">account_tree</span>
          MITRE ATT&amp;CK
        </h3>
        <div style="display:inline-flex;align-items:center;gap:8px;background:rgba(56,189,248,0.08);border:1px solid rgba(56,189,248,0.25);border-radius:9999px;padding:6px 14px;margin-bottom:10px;">
          <span style="font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;color:#c4e7ff;">${llm.mitreAttack.id}</span>
          <span style="color:#87929a;">—</span>
          <span style="font-family:Inter,sans-serif;font-size:13px;color:#dee3e8;">${llm.mitreAttack.name || 'Phishing'}</span>
        </div>
        <p style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#87929a;text-transform:uppercase;letter-spacing:0.05em;">Reference:</p>
        <a href="${llm.mitreAttack.url}" style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#8ed5ff;word-break:break-all;">${llm.mitreAttack.url}</a>
      </div>` : '<div></div>'}
      ${llm.analystNote ? `
      <div>
        <h3 style="font-family:Geist,sans-serif;font-size:16px;font-weight:600;color:#dee3e8;display:flex;align-items:center;gap:8px;margin-bottom:14px;">
          <span class="material-symbols-outlined" style="color:#38bdf8;font-size:20px;">edit_note</span>
          Analyst Note
        </h3>
        <blockquote style="border-left:2px solid #3e484f;padding-left:14px;font-family:Inter,sans-serif;font-size:13px;font-style:italic;color:#bdc8d1;opacity:0.85;">"${llm.analystNote}"</blockquote>
      </div>` : ''}
    </section>

  </main>

  <!-- Footer -->
  <footer style="background:#0f1418;border-top:1px solid #3e484f;padding:20px 40px;text-align:center;margin-top:8px;">
    <p style="font-family:Inter,sans-serif;font-size:12px;color:#87929a;opacity:0.8;max-width:600px;margin:0 auto;">Report generated by Revelio v1.0.0 — Confidential Security Analysis. This report is intended for authorized security personnel only.</p>
    <div style="display:flex;justify-content:center;gap:24px;margin-top:10px;">
      <span style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#87929a;text-transform:uppercase;letter-spacing:0.08em;">Privacy Policy</span>
      <span style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#87929a;text-transform:uppercase;letter-spacing:0.08em;">Terms of Service</span>
      <span style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#87929a;text-transform:uppercase;letter-spacing:0.08em;">Support</span>
    </div>
  </footer>

  <script>setTimeout(() => window.print(), 600);</script>
</body>
</html>`;

  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  window.open(url, '_blank');
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}