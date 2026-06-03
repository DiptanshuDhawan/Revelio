// PhishGuard AI — Content Script
// Deep Gmail + Outlook email extractor. Fires automatically when popup asks.

(function () {
  'use strict';

  if (window.__phishguardInjected) return;
  window.__phishguardInjected = true;

  // ─── Message Listener ───────────────────────────────────────────────────────
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'EXTRACT_EMAIL') {
      try {
        const result = extractCurrentEmail();
        sendResponse(result);
      } catch (e) {
        sendResponse({ emailText: null, source: null, error: e.message });
      }
      return false; // synchronous
    }
    if (message.type === 'PING') {
      sendResponse({ pong: true, url: window.location.href });
      return false;
    }
  });

  // ─── Main Dispatcher ────────────────────────────────────────────────────────
  function extractCurrentEmail() {
    const host = window.location.hostname;

    if (host.includes('mail.google.com')) return extractGmail();
    if (host.includes('outlook.live.com') || host.includes('outlook.office.com') || host.includes('outlook.office365.com')) return extractOutlook();

    // Fallback: try selected text first, then heuristic page scrape
    return extractFallback();
  }

  // ════════════════════════════════════════════════════════════════════════════
  // GMAIL EXTRACTOR
  // Gmail's DOM is heavily obfuscated. We try many selector strategies.
  // ════════════════════════════════════════════════════════════════════════════
  function extractGmail() {
    // ── 1. Find the open/focused email container ─────────────────────────────
    // Gmail renders the reading pane as `.adn` (message view) or `.ha` (thread)
    // The currently expanded message has class `.a3s` for body
    const openMessages = document.querySelectorAll('.a3s.aiL, .a3s');
    const msgEl = openMessages.length > 0 ? openMessages[openMessages.length - 1] : null;

    // ── 2. Subject ────────────────────────────────────────────────────────────
    const subjectEl =
      document.querySelector('h2.hP') ||                        // Reading pane
      document.querySelector('[data-thread-id] h2') ||
      document.querySelector('.ha h2') ||
      document.querySelector('title');                          // Last resort
    const subject = subjectEl
      ? subjectEl.textContent.trim().replace(/^PhishGuard AI.*/, '').trim()
      : '';

    // ── 3. Sender ─────────────────────────────────────────────────────────────
    // .gD is Gmail's sender span — has name="" and email="" attributes
    let fromName = '', fromEmail = '', toField = '', dateField = '', replyTo = '';

    // Try the expanded header first (click ▾ to expand shows full headers)
    const senderEl = document.querySelector('.gD');
    if (senderEl) {
      fromName  = senderEl.getAttribute('name')  || senderEl.getAttribute('data-name')  || '';
      fromEmail = senderEl.getAttribute('email') || senderEl.getAttribute('data-hovercard-id') || '';
    }

    // Try the collapsed "from" line as fallback
    if (!fromEmail) {
      const fromSpan = document.querySelector('.go, .g2');
      if (fromSpan) fromName = fromSpan.textContent.trim();
    }

    // ── 4. To field ───────────────────────────────────────────────────────────
    const toEl = document.querySelector('[email].g2, .hb .g2, .ajy .g2');
    if (toEl) {
      toField = toEl.getAttribute('email') || toEl.textContent.trim();
    }

    // ── 5. Date ───────────────────────────────────────────────────────────────
    const dateEl =
      document.querySelector('.g3') ||
      document.querySelector('[title*="202"]') ||
      document.querySelector('.ads');
    if (dateEl) dateField = dateEl.getAttribute('title') || dateEl.textContent.trim();

    // ── 6. Reply-To ───────────────────────────────────────────────────────────
    // Gmail shows Reply-To in expanded headers pane (.ajz rows)
    document.querySelectorAll('.ajz').forEach(row => {
      const label = row.querySelector('.adn')?.textContent.trim() || '';
      const val   = row.querySelector('.g2, .gD')?.textContent.trim() || '';
      if (/reply.to/i.test(label)) replyTo = val;
    });

    // ── 7. Body text ─────────────────────────────────────────────────────────
    let bodyText = '';
    if (msgEl) {
      // Clone and remove quoted sections for cleaner body
      const clone = msgEl.cloneNode(true);
      clone.querySelectorAll('.gmail_quote, .gmail_signature, blockquote').forEach(el => el.remove());
      bodyText = clone.innerText || clone.textContent || '';
    }

    // If no body found through .a3s, try the full reading pane
    if (!bodyText.trim()) {
      const pane = document.querySelector('.AO, .nH.aHU, [role="main"]');
      if (pane) bodyText = pane.innerText?.slice(0, 8000) || '';
    }

    if (!bodyText.trim() && !subject) {
      return { emailText: null, source: 'gmail', error: 'No email open in Gmail. Please open an email first.' };
    }

    // ── 8. Build pseudo-headers + body ───────────────────────────────────────
    const headers = [];
    if (fromName || fromEmail) {
      headers.push(`From: ${fromName}${fromEmail ? ` <${fromEmail}>` : ''}`);
    }
    if (toField)    headers.push(`To: ${toField}`);
    if (replyTo)    headers.push(`Reply-To: ${replyTo}`);
    if (subject)    headers.push(`Subject: ${subject}`);
    if (dateField)  headers.push(`Date: ${dateField}`);
    else            headers.push(`Date: ${new Date().toUTCString()}`);

    const emailText = headers.join('\n') + '\n\n' + bodyText.trim();

    return {
      emailText,
      source: 'gmail',
      subject,
      fromName,
      fromEmail,
    };
  }

  // ════════════════════════════════════════════════════════════════════════════
  // OUTLOOK EXTRACTOR (Outlook.com / OWA / Office 365)
  // ════════════════════════════════════════════════════════════════════════════
  function extractOutlook() {
    // ── Subject ───────────────────────────────────────────────────────────────
    const subjectEl =
      document.querySelector('[data-testid="subject"]') ||
      document.querySelector('[aria-label*="Subject"]') ||
      document.querySelector('.SubjectText') ||
      document.querySelector('h1[role="heading"]') ||
      document.querySelector('.allowTextSelection h1') ||
      document.querySelector('[class*="subjectLine"]');
    const subject = subjectEl ? subjectEl.textContent.trim() : '';

    // ── From ──────────────────────────────────────────────────────────────────
    const fromEl =
      document.querySelector('[data-testid="senderName"]') ||
      document.querySelector('[aria-label*="From"]') ||
      document.querySelector('.ms-Persona-primaryText') ||
      document.querySelector('[class*="sender"]');
    const fromName  = fromEl ? fromEl.textContent.trim() : '';

    // Email address often in a tooltip or aria attribute
    const fromEmailEl =
      document.querySelector('[data-testid="senderEmail"]') ||
      document.querySelector('[title*="@"]');
    const fromEmail = fromEmailEl
      ? (fromEmailEl.getAttribute('title') || fromEmailEl.textContent).match(/[\w.+-]+@[\w.-]+/)?.[0] || ''
      : '';

    // ── To ────────────────────────────────────────────────────────────────────
    const toEl = document.querySelector('[data-testid="toRecipients"], [aria-label*="To:"]');
    const toField = toEl ? toEl.textContent.trim() : '';

    // ── Date ──────────────────────────────────────────────────────────────────
    const dateEl =
      document.querySelector('[data-testid="receivedTime"]') ||
      document.querySelector('time') ||
      document.querySelector('[aria-label*="sent"]');
    const dateField = dateEl
      ? (dateEl.getAttribute('title') || dateEl.getAttribute('datetime') || dateEl.textContent.trim())
      : new Date().toUTCString();

    // ── Body ─────────────────────────────────────────────────────────────────
    const bodyEl =
      document.querySelector('[data-testid="emailBodyContent"]') ||
      document.querySelector('[aria-label="Message body"]') ||
      document.querySelector('.ReadMsgBody') ||
      document.querySelector('[class*="body"]') ||
      document.querySelector('[role="main"] .allowTextSelection') ||
      document.querySelector('[contenteditable="false"][class*="content"]');

    let bodyText = '';
    if (bodyEl) {
      const clone = bodyEl.cloneNode(true);
      clone.querySelectorAll('blockquote, [class*="quote"], [class*="previousMessage"]').forEach(el => el.remove());
      bodyText = clone.innerText || clone.textContent || '';
    }

    if (!bodyText.trim() && !subject) {
      return { emailText: null, source: 'outlook', error: 'No email open in Outlook. Please open an email first.' };
    }

    const headers = [];
    if (fromName || fromEmail) headers.push(`From: ${fromName}${fromEmail ? ` <${fromEmail}>` : ''}`);
    if (toField)    headers.push(`To: ${toField}`);
    if (subject)    headers.push(`Subject: ${subject}`);
    headers.push(`Date: ${dateField}`);

    return {
      emailText: headers.join('\n') + '\n\n' + bodyText.trim(),
      source: 'outlook',
      subject,
      fromName,
      fromEmail,
    };
  }

  // ════════════════════════════════════════════════════════════════════════════
  // FALLBACK: any page (selected text, or main content area)
  // ════════════════════════════════════════════════════════════════════════════
  function extractFallback() {
    const selected = window.getSelection()?.toString()?.trim();
    if (selected && selected.length > 80) {
      return { emailText: selected, source: 'selection' };
    }

    // Generic: try main content area
    const main =
      document.querySelector('[role="main"]') ||
      document.querySelector('main') ||
      document.querySelector('article');

    const text = main?.innerText?.trim();
    if (text && text.length > 100) {
      return { emailText: text.slice(0, 10000), source: 'page' };
    }

    return { emailText: null, source: null, error: 'Could not find email content on this page.' };
  }

  // ─── Passive Background Scanning ─────────────────────────────────────────────
  let lastScannedHash = 0;
  
  function hashCode(str) {
    let hash = 0;
    for (let i = 0, len = str.length; i < len; i++) {
        let chr = str.charCodeAt(i);
        hash = (hash << 5) - hash + chr;
        hash |= 0; 
    }
    return hash;
  }

  function scanPassive() {
    try {
      const result = extractCurrentEmail();
      if (result && result.emailText && result.emailText.length > 50) {
        const currentHash = hashCode(result.emailText.slice(0, 500)); // Hash first 500 chars
        if (currentHash !== lastScannedHash) {
          lastScannedHash = currentHash;
          chrome.runtime.sendMessage({ 
            type: 'PASSIVE_SCAN', 
            emailText: result.emailText,
            source: result.source 
          });
        }
      }
    } catch (e) {
      // Ignore extraction errors in passive mode
    }
  }

  let scanTimeout;
  const observer = new MutationObserver(() => {
    clearTimeout(scanTimeout);
    scanTimeout = setTimeout(scanPassive, 2000); // Wait 2s after DOM settles
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // Initial check
  setTimeout(scanPassive, 3000);})();
