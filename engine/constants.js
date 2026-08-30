// Revelio — Detection Constants
// Centralised data for the rule engine and URL scanner.
//
// All other modules import from here instead of defining their own copies.
// This is the single source of truth for every detection list and score weight.

'use strict';

// ─── Brand / Domain Map ───────────────────────────────────────────────────────
// Maps brand names (lowercase) to their known legitimate sending domains.
// Used for display-name spoofing detection and URL lookalike checks.

export const BRAND_DOMAIN_MAP = {
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

/** All legitimate brand domains as a flat array, for fast set-membership checks. */
export const KNOWN_BRAND_DOMAINS = Object.values(BRAND_DOMAIN_MAP).flat();

// ─── Suspicious TLDs ─────────────────────────────────────────────────────────
// TLDs frequently abused for phishing infrastructure.

export const SUSPICIOUS_TLDS = [
  '.ru', '.cn', '.xyz', '.top', '.click', '.loan', '.work',
  '.gq', '.tk', '.ml', '.ga', '.cf', '.pw', '.rest', '.buzz', '.icu',
  '.bar', '.cam', '.monster', '.cyou',
];

// ─── URL Shortener Domains ────────────────────────────────────────────────────
// Known URL-shortening services. Shorteners mask the true destination domain.

export const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl', 'rb.gy',
  'is.gd', 'buff.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'tr.im',
  'lnk.to', 'adf.ly', 'bit.do',
];

// ─── Urgency Keywords ─────────────────────────────────────────────────────────
// Phrases that create artificial time pressure — a core social-engineering tactic.

export const URGENCY_KEYWORDS = [
  'urgent', 'immediately', 'action required', 'verify now', 'account suspended',
  'limited time', 'expires in', '24 hours', '48 hours', '72 hours',
  'click here now', 'respond immediately', 'unusual activity', 'security alert',
  'final notice', 'act now', 'time sensitive', 'account will be', 'will be suspended',
  'will be terminated', 'within 24', 'your account has been', 'immediate action',
  'failure to respond', 'last chance', 'deadline', 'overdue', 'past due',
];

// ─── Personal Data Keywords ───────────────────────────────────────────────────
// Terms that indicate credential harvesting or data-exfiltration attempts.

export const PERSONAL_DATA_KEYWORDS = [
  'ssn', 'social security', 'password', 'credit card', 'cvv', 'cvc',
  'otp', 'one-time password', 'one time password', 'pin number',
  'bank account', 'routing number', 'date of birth', "mother's maiden",
  'social security number', 'card number', 'expiry date', 'expiration date',
  'security code', 'secret question', 'secret answer',
];

// ─── Generic Greeting Patterns ────────────────────────────────────────────────
// Non-personalised salutations indicate mass phishing (not a targeted attack).

export const GENERIC_GREETINGS = [
  /dear customer/i, /dear user/i, /dear account holder/i, /dear member/i,
  /dear valued/i, /hello user/i, /^greetings[,\s]/im, /to whom it may concern/i,
  /dear client/i, /dear subscriber/i, /dear sir or madam/i,
];

// ─── Financial / Invoice Keywords ────────────────────────────────────────────
// Language associated with BEC (Business Email Compromise) and invoice fraud.

export const FINANCIAL_KEYWORDS = [
  'invoice', 'payment due', 'wire transfer', 'gift card', 'itunes',
  'google play', 'purchase order', 'remittance', 'fund transfer', 'bitcoin',
  'cryptocurrency', 'western union', 'money gram', 'urgent payment',
  'overdue invoice', 'bank transfer', 'transaction failed',
];

// ─── Free Email Providers ─────────────────────────────────────────────────────
// Legitimate businesses use custom domains, not free providers.

export const FREE_EMAIL_PROVIDERS = [
  'gmail.com', 'yahoo.com', 'hotmail.com', 'protonmail.com', 'outlook.com',
  'aol.com', 'ymail.com', 'mail.com', 'inbox.com', 'zoho.com',
  'guerrillamail.com', 'mailinator.com', 'temp-mail.org',
];

// ─── Score Weights ────────────────────────────────────────────────────────────
// Controls how LLM and rule-engine scores are blended into the final score.
// LLM carries more weight because it evaluates semantic context, not just patterns.

/** Weight applied to the LLM contextual score. Must sum to 1.0 with RULE_WEIGHT. */
export const LLM_WEIGHT = 0.6;

/** Weight applied to the deterministic rule-engine score. Must sum to 1.0 with LLM_WEIGHT. */
export const RULE_WEIGHT = 0.4;

// ─── Verdict Thresholds ───────────────────────────────────────────────────────
// Base score thresholds for each verdict tier (before sensitivity offset is applied).
// Sensitivity offset formula: offset = (sensitivity - 50) * 0.4

/** Minimum blended score (0-100) to classify as "Confirmed Phishing". */
export const THRESHOLD_CONFIRMED = 86;

/** Minimum blended score (0-100) to classify as "Likely Phishing". */
export const THRESHOLD_LIKELY = 70;

/** Minimum blended score (0-100) to classify as "Suspicious". */
export const THRESHOLD_SUSPICIOUS = 40;

// ─── Cache ────────────────────────────────────────────────────────────────────

/** How long (ms) a cached analysis result is considered fresh. */
export const CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes

// ─── Timing ───────────────────────────────────────────────────────────────────

/** Timeout (ms) for SOC Dashboard API calls — prevents blocking if the dashboard is unreachable. */
export const DASHBOARD_TIMEOUT_MS = 5_000;

/** Timeout (ms) for Ollama health-check pings. */
export const OLLAMA_HEALTH_TIMEOUT_MS = 3_000;
