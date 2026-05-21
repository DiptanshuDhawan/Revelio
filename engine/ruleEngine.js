// PhishGuard AI — Rule Engine
// Implements multi-layer rule-based phishing detection.

'use strict';

// ─── Brand / Domain Map ───────────────────────────────────────────────────────

const BRAND_DOMAIN_MAP = {
  paypal: ['paypal.com'],
  google: ['google.com', 'gmail.com', 'googlemail.com'],
  microsoft: ['microsoft.com', 'live.com', 'outlook.com', 'hotmail.com', 'office.com', 'microsoftonline.com'],
  apple: ['apple.com', 'icloud.com'],
  amazon: ['amazon.com', 'aws.amazon.com'],
  netflix: ['netflix.com'],
  facebook: ['facebook.com', 'meta.com', 'fb.com'],
  instagram: ['instagram.com'],
  twitter: ['twitter.com', 'x.com'],
  linkedin: ['linkedin.com'],
  dropbox: ['dropbox.com'],
  docusign: ['docusign.com', 'docusign.net'],
  fedex: ['fedex.com'],
  ups: ['ups.com'],
  irs: ['irs.gov'],
  'bank of america': ['bankofamerica.com', 'bofa.com'],
  chase: ['chase.com', 'jpmorgan.com'],
  'wells fargo': ['wellsfargo.com'],
  dhl: ['dhl.com'],
  usps: ['usps.com'],
  stripe: ['stripe.com'],
  coinbase: ['coinbase.com'],
  binance: ['binance.com'],
};

const KNOWN_BRAND_DOMAINS = Object.values(BRAND_DOMAIN_MAP).flat();

// ─── Suspicious TLDs ─────────────────────────────────────────────────────────

const SUSPICIOUS_TLDS = ['.ru', '.cn', '.xyz', '.top', '.click', '.loan', '.work',
  '.gq', '.tk', '.ml', '.ga', '.cf', '.pw', '.rest', '.buzz', '.icu',
  '.bar', '.cam', '.monster', '.cyou'];

// ─── URL Shortener Domains ────────────────────────────────────────────────────

const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl', 'rb.gy',
  'is.gd', 'buff.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'tr.im',
  'lnk.to', 'adf.ly', 'bit.do'];

// ─── Urgency Keywords ─────────────────────────────────────────────────────────

const URGENCY_KEYWORDS = [
  'urgent', 'immediately', 'action required', 'verify now', 'account suspended',
  'limited time', 'expires in', '24 hours', '48 hours', '72 hours',
  'click here now', 'respond immediately', 'unusual activity', 'security alert',
  'final notice', 'act now', 'time sensitive', 'account will be', 'will be suspended',
  'will be terminated', 'within 24', 'your account has been', 'immediate action',
  'failure to respond', 'last chance', 'deadline', 'overdue', 'past due',
];

// ─── Personal Data Keywords ───────────────────────────────────────────────────

const PERSONAL_DATA_KEYWORDS = [
  'ssn', 'social security', 'password', 'credit card', 'cvv', 'cvc',
  'otp', 'one-time password', 'one time password', 'pin number',
  'bank account', 'routing number', 'date of birth', "mother's maiden",
  'social security number', 'card number', 'expiry date', 'expiration date',
  'security code', 'secret question', 'secret answer',
];

// ─── Generic Greeting Patterns ────────────────────────────────────────────────

const GENERIC_GREETINGS = [
  /dear customer/i, /dear user/i, /dear account holder/i, /dear member/i,
  /dear valued/i, /hello user/i, /^greetings[,\s]/im, /to whom it may concern/i,
  /dear client/i, /dear subscriber/i, /dear sir or madam/i,
];

// ─── Invoice / Financial Keywords ────────────────────────────────────────────

const FINANCIAL_KEYWORDS = [
  'invoice', 'payment due', 'wire transfer', 'gift card', 'itunes',
  'google play', 'purchase order', 'remittance', 'fund transfer', 'bitcoin',
  'cryptocurrency', 'western union', 'money gram', 'urgent payment',
  'overdue invoice', 'bank transfer', 'transaction failed',
];

// ─── Free Email Providers ─────────────────────────────────────────────────────

const FREE_EMAIL_PROVIDERS = [
  'gmail.com', 'yahoo.com', 'hotmail.com', 'protonmail.com', 'outlook.com',
  'aol.com', 'ymail.com', 'mail.com', 'inbox.com', 'zoho.com',
  'guerrillamail.com', 'mailinator.com', 'temp-mail.org',
];

// ─── Levenshtein Distance ─────────────────────────────────────────────────────

function levenshtein(a, b) {
  if (!a || !b) return Math.max((a || '').length, (b || '').length);
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => [i]);
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) dp[i][j] = dp[i - 1][j - 1];
      else dp[i][j] = 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
    }
  }
  return dp[m][n];
}

// ─── Domain Extractor ─────────────────────────────────────────────────────────

function extractDomain(email) {
  if (!email) return '';
  const match = email.match(/@([\w.-]+)$/);
  return match ? match[1].toLowerCase() : '';
}

function extractRootDomain(domain) {
  if (!domain) return '';
  const parts = domain.split('.');
  if (parts.length <= 2) return domain;
  return parts.slice(-2).join('.');
}

function getTLD(domain) {
  if (!domain) return '';
  const parts = domain.split('.');
  return '.' + parts[parts.length - 1];
}

// ─── Rule 1: Urgency Keywords ─────────────────────────────────────────────────

function checkUrgencyKeywords(emailData) {
  const text = `${emailData.subject || ''} ${emailData.body || ''}`.toLowerCase();
  const foundKeywords = URGENCY_KEYWORDS.filter((kw) => text.includes(kw.toLowerCase()));
  const count = foundKeywords.length;

  let score = 0;
  if (count >= 5) score = 85;
  else if (count >= 3) score = 60;
  else if (count >= 1) score = 30;

  const quote = foundKeywords.length > 0
    ? foundKeywords.slice(0, 3).join(', ')
    : null;

  return {
    id: 'URGENCY_KEYWORDS',
    name: 'Urgency Keyword Detection',
    severity: score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low',
    score,
    passed: score === 0,
    finding: score === 0
      ? 'No urgency manipulation keywords detected.'
      : `Found ${count} urgency keyword${count !== 1 ? 's' : ''}: "${foundKeywords.slice(0, 3).join('", "')}"`,
    quote,
    count,
    foundKeywords,
  };
}

// ─── Rule 2: Sender Brand Spoofing ────────────────────────────────────────────

function checkSenderBrandSpoof(emailData) {
  const displayName = (emailData.fromDisplay || '').toLowerCase();
  const fromEmail = (emailData.fromEmail || '').toLowerCase();
  const fromDomain = extractDomain(fromEmail);

  for (const [brand, legit_domains] of Object.entries(BRAND_DOMAIN_MAP)) {
    if (displayName.includes(brand)) {
      const domainMatches = legit_domains.some(
        (ld) => fromDomain === ld || fromDomain.endsWith('.' + ld)
      );
      if (!domainMatches) {
        return {
          id: 'SENDER_BRAND_SPOOF',
          name: 'Brand Impersonation Detected',
          severity: 'critical',
          score: 95,
          passed: false,
          finding: `Display name references "${brand}" but sender domain is "${fromDomain}" — not an official ${brand} domain.`,
          quote: `From: ${emailData.fromDisplay} <${emailData.fromEmail}>`,
        };
      }
    }
  }

  return {
    id: 'SENDER_BRAND_SPOOF',
    name: 'Brand Impersonation Check',
    severity: 'low',
    score: 0,
    passed: true,
    finding: 'No brand impersonation detected in sender display name.',
    quote: null,
  };
}

// ─── Rule 3: Reply-To Mismatch ────────────────────────────────────────────────

function checkReplyToMismatch(emailData) {
  if (!emailData.replyTo || !emailData.fromEmail) {
    return {
      id: 'REPLY_TO_MISMATCH',
      name: 'Reply-To Mismatch',
      severity: 'low',
      score: 0,
      passed: true,
      finding: 'No Reply-To header present or From email not available.',
      quote: null,
    };
  }

  const fromDomain = extractRootDomain(extractDomain(emailData.fromEmail));
  const replyDomain = extractRootDomain(extractDomain(emailData.replyTo));

  if (fromDomain && replyDomain && fromDomain !== replyDomain) {
    return {
      id: 'REPLY_TO_MISMATCH',
      name: 'Reply-To Domain Mismatch',
      severity: 'high',
      score: 75,
      passed: false,
      finding: `Reply-To domain "${replyDomain}" differs from From domain "${fromDomain}". Replies would go to a different server.`,
      quote: `From: ${emailData.fromEmail} / Reply-To: ${emailData.replyTo}`,
    };
  }

  return {
    id: 'REPLY_TO_MISMATCH',
    name: 'Reply-To Consistency Check',
    severity: 'low',
    score: 0,
    passed: true,
    finding: 'Reply-To domain matches sender domain.',
    quote: null,
  };
}

// ─── Rule 4: Personal Data Request ───────────────────────────────────────────

function checkPersonalDataRequest(emailData) {
  const text = `${emailData.subject || ''} ${emailData.body || ''}`.toLowerCase();
  const found = PERSONAL_DATA_KEYWORDS.filter((kw) => text.includes(kw));

  const rawScore = Math.min(found.length * 40, 95);
  const score = found.length > 0 ? Math.max(rawScore, 40) : 0;

  return {
    id: 'PERSONAL_DATA_REQUEST',
    name: 'Personal Data Request',
    severity: score >= 80 ? 'critical' : score >= 40 ? 'high' : 'low',
    score,
    passed: score === 0,
    finding: found.length > 0
      ? `Email requests sensitive personal information: "${found.slice(0, 3).join('", "')}"—a hallmark of credential phishing.`
      : 'No requests for sensitive personal information detected.',
    quote: found.length > 0 ? found.slice(0, 2).join(', ') : null,
    foundKeywords: found,
  };
}

// ─── Rule 5: Generic Greeting ─────────────────────────────────────────────────

function checkGenericGreeting(emailData) {
  const body = emailData.body || '';
  const found = GENERIC_GREETINGS.find((pattern) => pattern.test(body));

  if (found) {
    const match = body.match(found);
    return {
      id: 'GENERIC_GREETING',
      name: 'Generic / Mass-Target Greeting',
      severity: 'medium',
      score: 50,
      passed: false,
      finding: 'Email uses a non-personalized generic greeting, suggesting a mass phishing campaign rather than a targeted message.',
      quote: match ? match[0].trim() : 'Generic greeting detected',
    };
  }

  return {
    id: 'GENERIC_GREETING',
    name: 'Personalization Check',
    severity: 'low',
    score: 0,
    passed: true,
    finding: 'Email uses a personalized greeting.',
    quote: null,
  };
}

// ─── Rule 6: Display Name Mismatch ───────────────────────────────────────────

function checkDisplayNameMismatch(emailData) {
  const displayName = (emailData.fromDisplay || '').toLowerCase().trim();
  const fromEmail = (emailData.fromEmail || '').toLowerCase().trim();

  if (!displayName || !fromEmail) {
    return {
      id: 'DISPLAY_NAME_MISMATCH',
      name: 'Display Name Analysis',
      severity: 'low',
      score: 0,
      passed: true,
      finding: 'Insufficient data for display name mismatch check.',
      quote: null,
    };
  }

  const emailUser = fromEmail.split('@')[0] || '';
  const emailDomain = extractRootDomain(extractDomain(fromEmail));

  // Check if the display name is something like a company name but the email is random
  const displayWords = displayName.replace(/[^a-z\s]/g, '').split(/\s+/).filter(Boolean);
  const emailDomainWords = emailDomain.replace(/\.[a-z]+$/, '').split(/[.-]/);

  // If display name has none of the email domain words in it, it's suspicious
  const overlap = displayWords.some((word) =>
    word.length > 3 && (emailDomainWords.some((dw) => dw.includes(word) || word.includes(dw)))
  );

  // Check for suspicious random email patterns (numbers + letters = random)
  const isRandomEmail = /^[a-z]{1,3}\d+[a-z]@/.test(fromEmail) ||
    /^[\w]{2,4}\d{4,}@/.test(fromEmail);

  const isFreeProvider = FREE_EMAIL_PROVIDERS.includes(emailDomain + '.com') ||
    FREE_EMAIL_PROVIDERS.includes(emailDomain);

  if (!overlap && (isRandomEmail || (isFreeProvider && displayWords.length >= 2))) {
    return {
      id: 'DISPLAY_NAME_MISMATCH',
      name: 'Display Name vs Email Mismatch',
      severity: 'high',
      score: 80,
      passed: false,
      finding: `Display name "${emailData.fromDisplay}" appears unrelated to sender email "${emailData.fromEmail}". This is a common phishing technique.`,
      quote: `From: "${emailData.fromDisplay}" <${emailData.fromEmail}>`,
    };
  }

  return {
    id: 'DISPLAY_NAME_MISMATCH',
    name: 'Display Name Consistency',
    severity: 'low',
    score: 0,
    passed: true,
    finding: 'Sender display name appears consistent with email address.',
    quote: null,
  };
}

// ─── Rule 7: Suspicious TLD ───────────────────────────────────────────────────

function checkSuspiciousTLD(emailData) {
  const fromDomain = extractDomain(emailData.fromEmail || '');
  const tld = getTLD(fromDomain);

  if (SUSPICIOUS_TLDS.includes(tld)) {
    return {
      id: 'SUSPICIOUS_DOMAIN_TLD',
      name: 'Suspicious Sender Domain TLD',
      severity: 'high',
      score: 70,
      passed: false,
      finding: `Sender uses a "${tld}" TLD domain (${fromDomain}), which is frequently associated with spam, phishing, and cybercriminal infrastructure.`,
      quote: emailData.fromEmail || fromDomain,
    };
  }

  return {
    id: 'SUSPICIOUS_DOMAIN_TLD',
    name: 'Sender Domain TLD Check',
    severity: 'low',
    score: 0,
    passed: true,
    finding: 'Sender domain uses a common, non-suspicious TLD.',
    quote: null,
  };
}

// ─── Rule 8: Dangerous Attachment ────────────────────────────────────────────

const DANGEROUS_EXTENSIONS = ['.exe', '.vbs', '.js', '.bat', '.scr', '.cmd', '.com',
  '.pif', '.msi', '.dll', '.ps1', '.jar', '.hta', '.reg'];

const DOUBLE_EXT_PATTERN = /\.[a-z]{2,5}\.(exe|bat|vbs|scr|cmd|pif|js|jar)$/i;

function checkDangerousAttachment(emailData) {
  const attachments = emailData.attachments || [];
  // Also scan body for attachment mentions
  const bodyMentions = (emailData.body || '').match(/[\w\s-]+\.[a-z]{2,5}(\.[a-z]{2,5})?/gi) || [];

  const allFiles = [...attachments, ...bodyMentions.slice(0, 10)];

  for (const fname of allFiles) {
    const lower = fname.toLowerCase().trim();
    if (DOUBLE_EXT_PATTERN.test(lower)) {
      return {
        id: 'DANGEROUS_ATTACHMENT',
        name: 'Double Extension / Dangerous File Detected',
        severity: 'critical',
        score: 90,
        passed: false,
        finding: `Potentially malicious file attachment detected: "${fname}". Double extensions are used to disguise executables as harmless documents.`,
        quote: fname,
      };
    }
    const ext = lower.match(/\.[a-z]+$/)?.[0];
    if (ext && DANGEROUS_EXTENSIONS.includes(ext)) {
      return {
        id: 'DANGEROUS_ATTACHMENT',
        name: 'Dangerous Attachment Extension',
        severity: 'critical',
        score: 90,
        passed: false,
        finding: `Email references a potentially dangerous file type: "${fname}" — executable or scripting files should never be sent via email.`,
        quote: fname,
      };
    }
  }

  return {
    id: 'DANGEROUS_ATTACHMENT',
    name: 'Attachment Safety Check',
    severity: 'low',
    score: 0,
    passed: true,
    finding: 'No dangerous or executable attachments detected.',
    quote: null,
  };
}

// ─── Rule 9: Lookalike URL Detection ─────────────────────────────────────────

function checkLookalikeURLs(emailData) {
  const urls = emailData.urls || [];

  for (const urlObj of urls) {
    const href = (urlObj.href || urlObj).toLowerCase();
    try {
      const urlDomain = new URL(href.startsWith('http') ? href : 'https://' + href).hostname
        .replace('www.', '');
      const rootDomain = extractRootDomain(urlDomain);

      for (const knownDomain of KNOWN_BRAND_DOMAINS) {
        const knownRoot = extractRootDomain(knownDomain);
        if (rootDomain === knownRoot) break; // exact match, not lookalike

        const distance = levenshtein(rootDomain, knownRoot);
        if (distance > 0 && distance <= 2 && rootDomain.length >= 4) {
          return {
            id: 'LOOKALIKE_URL',
            name: 'Lookalike Domain Detected',
            severity: 'critical',
            score: 90,
            passed: false,
            finding: `URL "${rootDomain}" appears to be a lookalike of legitimate domain "${knownRoot}" (edit distance: ${distance}). This is a common spoofing technique.`,
            quote: href,
          };
        }
      }
    } catch {
      // Invalid URL, skip
    }
  }

  return {
    id: 'LOOKALIKE_URL',
    name: 'URL Lookalike Domain Check',
    severity: 'low',
    score: 0,
    passed: true,
    finding: 'No lookalike domains detected in URLs.',
    quote: null,
  };
}

// ─── Rule 10: Free Email Impersonation ───────────────────────────────────────

function checkFreeEmailImpersonation(emailData) {
  const displayName = (emailData.fromDisplay || '').toLowerCase();
  const fromEmail = (emailData.fromEmail || '').toLowerCase();
  const domain = extractDomain(fromEmail);

  const isFree = FREE_EMAIL_PROVIDERS.some(
    (p) => domain === p || domain.endsWith('.' + p)
  );

  if (!isFree) {
    return {
      id: 'FREE_EMAIL_IMPERSONATION',
      name: 'Free Email Provider Check',
      severity: 'low',
      score: 0,
      passed: true,
      finding: 'Sender uses a custom domain email address.',
      quote: null,
    };
  }

  // Check if display name sounds corporate
  const corporateTriggers = ['support', 'security', 'admin', 'service', 'team', 'noreply',
    'no-reply', 'billing', 'account', 'helpdesk', 'help desk', 'it department',
    'payroll', 'hr ', 'finance', 'management', 'ceo', 'cfo', 'director'];

  const looks_corporate = corporateTriggers.some((kw) => displayName.includes(kw));

  if (looks_corporate) {
    return {
      id: 'FREE_EMAIL_IMPERSONATION',
      name: 'Corporate Impersonation via Free Email',
      severity: 'high',
      score: 65,
      passed: false,
      finding: `Display name "${emailData.fromDisplay}" suggests a corporate entity, but uses a free email provider (${domain}). Legitimate businesses use custom domains.`,
      quote: `From: ${emailData.fromDisplay} <${fromEmail}>`,
    };
  }

  return {
    id: 'FREE_EMAIL_IMPERSONATION',
    name: 'Free Email Provider Check',
    severity: 'low',
    score: 0,
    passed: true,
    finding: 'Free email provider used but display name does not suggest corporate impersonation.',
    quote: null,
  };
}

// ─── Rule 11: HTML Link Text vs Href Mismatch ────────────────────────────────

function checkHTMLObfuscation(emailData) {
  const body = emailData.body || '';

  // Pattern: <a href="...">visible text</a>
  const linkPattern = /href=["']([^"']+)["'][^>]*>([^<]+)</gi;
  let match;
  const mismatches = [];

  while ((match = linkPattern.exec(body)) !== null) {
    const href = match[1].trim();
    const visibleText = match[2].trim();

    // Check if visible text looks like a URL/domain but doesn't match href
    const looksLikeURL = /\.(com|org|net|gov|io|co)\b/i.test(visibleText);
    if (!looksLikeURL) continue;

    try {
      const hrefDomain = new URL(href.startsWith('http') ? href : 'https://' + href).hostname;
      const textDomain = visibleText.replace(/https?:\/\//i, '').split('/')[0].trim();

      const hrefRoot = extractRootDomain(hrefDomain.replace('www.', ''));
      const textRoot = extractRootDomain(textDomain.replace('www.', '').toLowerCase());

      if (textRoot && hrefRoot && textRoot !== hrefRoot && !href.startsWith('#')) {
        mismatches.push({ displayText: visibleText, actualHref: href });
      }
    } catch {
      // Invalid URL
    }
  }

  if (mismatches.length > 0) {
    const first = mismatches[0];
    return {
      id: 'HTML_OBFUSCATION',
      name: 'Deceptive Link Text (HTML Obfuscation)',
      severity: 'critical',
      score: 85,
      passed: false,
      finding: `Found ${mismatches.length} link(s) where display text shows a different domain than the actual link. Example: shows "${first.displayText}" but goes to "${first.actualHref}".`,
      quote: `Displays: "${first.displayText}" → Actually: "${first.actualHref}"`,
    };
  }

  return {
    id: 'HTML_OBFUSCATION',
    name: 'Link Text Authenticity Check',
    severity: 'low',
    score: 0,
    passed: true,
    finding: 'No deceptive link text found. Link display text matches actual destinations.',
    quote: null,
  };
}

// ─── Rule 12: Invoice / Financial Trigger ────────────────────────────────────

function checkInvoiceFinancial(emailData) {
  const text = `${emailData.subject || ''} ${emailData.body || ''}`.toLowerCase();
  const found = FINANCIAL_KEYWORDS.filter((kw) => text.includes(kw.toLowerCase()));

  if (found.length >= 2) {
    return {
      id: 'INVOICE_FINANCIAL',
      name: 'Financial Fraud Trigger Language',
      severity: 'high',
      score: 55,
      passed: false,
      finding: `Email contains ${found.length} financial trigger words: "${found.slice(0, 3).join('", "')}". Combined with other signals, this may indicate a BEC or invoice fraud attack.`,
      quote: found.slice(0, 2).join(', '),
    };
  } else if (found.length === 1) {
    return {
      id: 'INVOICE_FINANCIAL',
      name: 'Financial Trigger Language',
      severity: 'medium',
      score: 30,
      passed: false,
      finding: `Email mentions financial term: "${found[0]}". Monitor in combination with other signals.`,
      quote: found[0],
    };
  }

  return {
    id: 'INVOICE_FINANCIAL',
    name: 'Financial Trigger Check',
    severity: 'low',
    score: 0,
    passed: true,
    finding: 'No financial fraud trigger language detected.',
    quote: null,
  };
}

// ─── Composite Score Calculator ───────────────────────────────────────────────

function calculateRuleScore(findings) {
  if (!findings || findings.length === 0) return 0;

  const triggeredFindings = findings.filter((f) => !f.passed && f.score > 0);
  if (triggeredFindings.length === 0) return 0;

  // Weighted scoring: highest-scoring rule gets more weight
  const scores = triggeredFindings.map((f) => f.score).sort((a, b) => b - a);

  // Primary signal (highest score) gets 50% weight, rest shared
  const primary = scores[0];
  const secondary = scores.slice(1);

  if (secondary.length === 0) return Math.round(primary * 0.7); // Single indicator, dampened

  const secondaryAvg = secondary.reduce((s, v) => s + v, 0) / secondary.length;
  const score = primary * 0.55 + secondaryAvg * 0.45;

  // Boost for multiple critical findings
  const criticalCount = triggeredFindings.filter((f) => f.severity === 'critical').length;
  const boost = Math.min(criticalCount * 5, 20);

  return Math.min(Math.round(score + boost), 100);
}

// ─── Main Export ──────────────────────────────────────────────────────────────

export function runRuleEngine(emailData) {
  const findings = [
    checkUrgencyKeywords(emailData),
    checkSenderBrandSpoof(emailData),
    checkReplyToMismatch(emailData),
    checkPersonalDataRequest(emailData),
    checkGenericGreeting(emailData),
    checkDisplayNameMismatch(emailData),
    checkSuspiciousTLD(emailData),
    checkDangerousAttachment(emailData),
    checkLookalikeURLs(emailData),
    checkFreeEmailImpersonation(emailData),
    checkHTMLObfuscation(emailData),
    checkInvoiceFinancial(emailData),
  ];

  const ruleScore = calculateRuleScore(findings);

  return {
    ruleScore,
    findings,
    triggeredCount: findings.filter((f) => !f.passed).length,
    totalChecks: findings.length,
  };
}

export { BRAND_DOMAIN_MAP, KNOWN_BRAND_DOMAINS, URL_SHORTENERS, SUSPICIOUS_TLDS, levenshtein };
