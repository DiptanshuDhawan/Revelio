function exportPDF() { window.print(); }

function getSeverityConfig(severity) {
  const s = (severity || 'low').toLowerCase();
  if (s === 'critical') return { dot: '#ef4444', badge: 'sev-badge red tag', evidenceColor: 'rgba(239,68,68,0.7)' };
  if (s === 'high') return { dot: '#f97316', badge: 'sev-badge orange tag', evidenceColor: 'rgba(249,115,22,0.7)' };
  if (s === 'medium') return { dot: '#fbbf24', badge: 'sev-badge amber tag', evidenceColor: 'rgba(251,191,36,0.7)' };
  return { dot: '#22c55e', badge: 'sev-badge green tag', evidenceColor: 'rgba(34,197,94,0.7)' };
}

function getTagIcon(label) {
  const l = (label || '').toLowerCase();
  if (l.includes('bec')) return 'ti-alert-triangle';
  if (l.includes('phishing')) return 'ti-mail-forward';
  if (l.includes('fraud')) return 'ti-currency-dollar';
  if (l.includes('t1')) return 'ti-target';
  return 'ti-tag';
}

function renderTopNav(data) {
  const nav = document.getElementById('topnav');
  const score = data.scores?.final || 0;
  let pillClass = 'green', pillText = 'Safe', pillIcon = 'ti-shield-check';
  if (score >= 70) { pillClass = 'red'; pillText = 'Threat detected'; pillIcon = 'ti-alert-triangle'; }
  else if (score >= 30) { pillClass = 'amber'; pillText = 'Suspicious'; pillIcon = 'ti-alert-circle'; }
  
  let formattedDate = 'Unknown Date';
  if (data.generatedAt) {
    try {
      const d = new Date(data.generatedAt);
      const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
      const time = d.toISOString().substring(11, 16);
      formattedDate = `${d.getUTCDate()} ${months[d.getUTCMonth()]} ${d.getUTCFullYear()} · ${time} UTC`;
    } catch(e) {}
  }

  nav.innerHTML = `
    <div class="topnav-left">
      <img src="../icons/Revelio%20logo.png" style="height: 45px; width: 100px; object-fit: contain; margin-left: -52px; margin-top: 9px; scale: 2.0;" alt="Revelio logo" />
      <div style="display: flex; flex-direction: column; justify-content: center; margin-left: -30px; z-index: 10;">
        <div style="font-family: Geist, Inter, sans-serif; font-size: 1rem; font-weight: 700; line-height: 1; letter-spacing: 0.01em; color: #e6f4ff; text-shadow: 0 0 18px rgba(142, 213, 255, 0.18);">Revelio</div>
        <div style="font-family: Inter, sans-serif; font-size: 0.5rem; font-weight: 600; line-height: 1.3; letter-spacing: 0.14em; text-transform: uppercase; color: rgba(196, 231, 255, 0.72);">Threat Intelligence</div>
      </div>
    </div>
    <div class="topnav-right">
      <div class="threat-pill ${pillClass}"><i class="ti ${pillIcon}"></i> ${pillText}</div>
      <div class="timestamp" id="tn-time"></div>
      <button class="export-btn" id="export-pdf-action"><i class="ti ti-download"></i> Export PDF</button>
    </div>
  `;
  document.getElementById('tn-time').textContent = formattedDate;
  document.getElementById('export-pdf-action').addEventListener('click', exportPDF);
}

function getThemeColors(score) {
  if (score < 40) return { main: '#22c55e', bg: 'rgba(34,197,94,0.12)', text: 'var(--green-soft, #4ade80)' };
  if (score < 80) return { main: '#f59e0b', bg: 'rgba(245,158,11,0.12)', text: 'var(--amber-soft, #fbbf24)' };
  return { main: '#ef4444', bg: 'rgba(239,68,68,0.12)', text: 'var(--red-soft, #f87171)' };
}

function renderBanner(data) {
  const banner = document.getElementById('verdict-banner');
  banner.innerHTML = `
    <div class="vb-left">
      <div class="vb-eyebrow">Threat analysis report</div>
      <div class="vb-heading" id="vb-verdict"></div>
      <div class="vb-sub">Business email compromise · <span id="vb-vector"></span></div>
      <div class="vb-tags" id="vb-tags"></div>
    </div>
    <div class="vb-right">
      <div class="score-ring-wrap">
        <canvas id="score-ring" role="img" aria-label="Score ring"></canvas>
        <div class="score-number"><span id="vb-score"></span><span>/100</span></div>
      </div>
      <div class="score-label">Threat score</div>
      <div class="mini-chips">
        <div class="chip">
          <div class="chip-val" id="chip-ai"></div>
          <div class="chip-lbl">AI</div>
        </div>
        <div class="chip-divider"></div>
        <div class="chip">
          <div class="chip-val" id="chip-rules"></div>
          <div class="chip-lbl">Rules</div>
        </div>
        <div class="chip-divider"></div>
        <div class="chip">
          <div class="chip-val" id="chip-conf"></div>
          <div class="chip-lbl">Conf</div>
        </div>
      </div>
    </div>
  `;
  document.getElementById('vb-verdict').textContent = data.verdict || 'Unknown';
  document.getElementById('vb-vector').textContent = data.attackVector || 'Unknown Vector';
  
  const tagsContainer = document.getElementById('vb-tags');
  (data.tags || []).forEach(t => {
    const el = document.createElement('div');
    el.className = `tag ${t.type || 'blue'}`;
    el.innerHTML = `<i class="ti ${getTagIcon(t.label)}"></i> <span class="tag-lbl"></span>`;
    el.querySelector('.tag-lbl').textContent = t.label;
    tagsContainer.appendChild(el);
  });
  
  const finalScore = data.scores?.final || 0;
  document.getElementById('vb-score').textContent = finalScore;

  // Apply theme to body
  if (finalScore < 40) document.body.className = 'theme-safe';
  else if (finalScore < 80) document.body.className = 'theme-suspicious';
  else document.body.className = 'theme-malicious';

  const theme = getThemeColors(finalScore);
  
  if (window.Chart) {
    new Chart(document.getElementById('score-ring'), {
      type: 'doughnut',
      data: {
        datasets: [{
          data: [finalScore, 100 - finalScore],
          backgroundColor: [theme.main, 'rgba(255,255,255,0.05)'],
          borderWidth: 0
        }]
      },
      options: { cutout: '75%', animation: { duration: 900 }, events: [], plugins: { tooltip: { enabled: false } } }
    });
  }

  const aiScore = data.scores?.ai || 0;
  const rulesScore = data.scores?.rules || 0;
  const conf = data.confidence || 'Low';
  
  const elAi = document.getElementById('chip-ai');
  elAi.textContent = aiScore;
  if (aiScore >= 70) elAi.classList.add('red');
  else if (aiScore >= 30) elAi.classList.add('amber');
  else elAi.classList.add('green');
  
  const elRules = document.getElementById('chip-rules');
  elRules.textContent = rulesScore;
  if (rulesScore >= 70) elRules.classList.add('red');
  else if (rulesScore >= 30) elRules.classList.add('amber');
  else elRules.classList.add('green');
  
  const elConf = document.getElementById('chip-conf');
  elConf.textContent = conf;
  const cl = conf.toLowerCase();
  if (cl === 'high') elConf.classList.add('red');
  else if (cl === 'medium') elConf.classList.add('amber');
  else elConf.classList.add('green');
}

function renderRadarChart(signals, finalScore) {
  if (!window.Chart) return;
  
  const theme = getThemeColors(finalScore);
  const sigs = signals || {};
  const dataArr = [
    sigs.impersonation || 0,
    sigs.urgency || 0,
    sigs.socialEngineering || 0,
    sigs.technicalDeception || 0,
    sigs.aiGenerated || 0
  ];
  
  const ctx = document.getElementById('radar-canvas');
  new Chart(ctx, {
    type: 'radar',
    data: {
      labels: ['Impersonation', 'Urgency', 'Social eng.', 'Tech. deception', 'AI-generated'],
      datasets: [{
        data: dataArr,
        backgroundColor: theme.bg,
        borderColor: theme.main,
        borderWidth: 1.5,
        pointBackgroundColor: theme.main,
        pointBorderColor: '#07090f',
        pointRadius: 4,
        pointHoverRadius: 6
      }]
    },
    options: {
      maintainAspectRatio: false,
      scales: {
        r: {
          min: 0, max: 100, stepSize: 25,
          grid: { color: 'rgba(255,255,255,0.07)' },
          angleLines: { color: 'rgba(255,255,255,0.07)' },
          ticks: { color: 'rgba(255,255,255,0.18)', backdropColor: 'transparent', font: { size: 9 } },
          pointLabels: { color: 'rgba(255,255,255,0.4)', font: { size: 10 } }
        }
      },
      plugins: { legend: { display: false } }
    }
  });
}

function renderSignalBars(signals, finalScore) {
  const theme = getThemeColors(finalScore);
  const sigs = signals || {};
  const config = [
    { key: 'impersonation', icon: 'ti-user-x', label: 'Impersonation' },
    { key: 'urgency', icon: 'ti-alarm', label: 'Urgency' },
    { key: 'socialEngineering', icon: 'ti-brain', label: 'Social eng.' },
    { key: 'technicalDeception', icon: 'ti-code', label: 'Tech. deception' },
    { key: 'aiGenerated', icon: 'ti-robot', label: 'AI-generated' }
  ];
  
  let html = '';
  config.forEach(c => {
    const score = sigs[c.key] || 0;
    const fillW = Math.min(100, Math.max(0, score));
    const fillC = score > 0 ? theme.main : 'rgba(255,255,255,0.15)';
    const textC = score > 0 ? theme.text : 'rgba(255,255,255,0.2)';
    html += `
      <div class="signal-row">
        <i class="ti ${c.icon} sig-icon"></i>
        <div class="sig-name">${c.label}</div>
        <div class="sig-track"><div class="sig-fill" style="width: ${fillW}%; background: ${fillC}"></div></div>
        <div class="sig-score" style="color: ${textC}">${score}</div>
      </div>
    `;
  });
  return html;
}

function renderTwoCol(data) {
  const cont = document.getElementById('two-col');
  const finalScore = data.scores?.final || 0;
  cont.innerHTML = `
    <div class="panel-card">
      <div class="panel-header">
        <div class="icon-badge blue"><i class="ti ti-chart-radar"></i></div>
        <div class="panel-title">Threat fingerprint</div>
      </div>
      <div class="radar-body">
        <canvas id="radar-canvas" role="img" aria-label="Threat fingerprint radar chart"></canvas>
      </div>
    </div>
    <div class="panel-card">
      <div class="panel-header">
        <div class="icon-badge red"><i class="ti ti-activity"></i></div>
        <div class="panel-title">Signal breakdown</div>
      </div>
      <div id="signal-list"></div>
    </div>
  `;
  document.getElementById('signal-list').innerHTML = renderSignalBars(data.signals, finalScore);
  renderRadarChart(data.signals, finalScore);
}

function renderFindings(findings) {
  const panel = document.getElementById('findings-panel');
  panel.innerHTML = `
    <div class="panel-card">
      <div class="panel-header">
        <div class="icon-badge red"><i class="ti ti-filter"></i></div>
        <div class="panel-title">Rule engine · ${findings.length} findings</div>
      </div>
      <div class="findings-body" id="findings-list"></div>
    </div>
  `;
  const list = document.getElementById('findings-list');
  findings.forEach(f => {
    const conf = getSeverityConfig(f.severity);
    const w = document.createElement('div');
    w.className = 'finding-wrap';
    
    const top = document.createElement('div');
    top.className = 'finding-top';
    top.innerHTML = `
      <div class="sev-dot" style="background: ${conf.dot}"></div>
      <div class="finding-content">
        <div class="finding-title"></div>
        <div class="finding-desc"></div>
      </div>
      <div class="${conf.badge}">${f.severity || 'low'}</div>
    `;
    top.querySelector('.finding-title').textContent = f.title || 'Unknown Finding';
    top.querySelector('.finding-desc').textContent = f.description || '';
    w.appendChild(top);
    
    if (f.evidence) {
      const ev = document.createElement('div');
      ev.className = 'finding-evidence';
      ev.style.color = conf.evidenceColor;
      ev.textContent = f.evidence;
      w.appendChild(ev);
    }
    list.appendChild(w);
  });
}

function renderAction(actionText) {
  const banner = document.getElementById('action-banner');
  if (!actionText) { banner.style.display = 'none'; return; }
  
  const firstSentence = actionText.split('.')[0] + '.';
  banner.innerHTML = `
    <div class="ab-icon"><i class="ti ti-ban"></i></div>
    <div class="ab-text">
      <div class="ab-title"></div>
      <div class="ab-body"></div>
    </div>
  `;
  banner.querySelector('.ab-title').textContent = firstSentence;
  banner.querySelector('.ab-body').textContent = actionText;
}

function renderMitre(mitre) {
  const panel = document.getElementById('mitre-panel');
  if (!mitre.id) { panel.style.display = 'none'; return; }
  panel.innerHTML = `
    <div class="mitre-badge"><i class="ti ti-tag"></i> <span id="mitre-id"></span></div>
    <div class="mitre-name" id="mitre-name"></div>
    <div>
      <span class="mitre-ref">Reference</span>
      <a class="mitre-link" id="mitre-link" target="_blank" rel="noopener"></a>
    </div>
  `;
  document.getElementById('mitre-id').textContent = mitre.id;
  document.getElementById('mitre-name').textContent = mitre.name || '';
  const lnk = document.getElementById('mitre-link');
  lnk.href = mitre.url || '#';
  lnk.textContent = mitre.url || '';
}

function renderFooter(data) {
  const footer = document.getElementById('footer');
  footer.innerHTML = `
    <div class="footer-left">Revelio v<span id="f-ver"></span> — Confidential security analysis · Authorised personnel only</div>
    <div class="footer-right">
      <a href="#">Privacy</a>
      <a href="#">Terms</a>
      <a href="#">Support</a>
    </div>
  `;
  document.getElementById('f-ver').textContent = data.version || '1.0.0';
}

document.addEventListener('DOMContentLoaded', () => {
  let data = {};
  if (window.reportData) {
    data = window.reportData;
  } else if (window.location.hash) {
    try {
      const hashData = window.location.hash.substring(1);
      data = JSON.parse(decodeURIComponent(atob(hashData)));
    } catch(e) {
      console.error('Failed to parse report data from hash', e);
    }
  }

  renderTopNav(data);
  renderBanner(data);
  renderTwoCol(data);
  renderFindings(data.findings || []);
  renderAction(data.recommendedAction);
  renderMitre(data.mitre || {});
  renderFooter(data);
});
