// PhishGuard AI — URL Scanner
// Extracts and analyzes URLs from email text for phishing indicators.

'use strict';

import { KNOWN_BRAND_DOMAINS, URL_SHORTENERS, SUSPICIOUS_TLDS, levenshtein } from '../engine/ruleEngine.js';

// ─── IP Address Pattern ───────────────────────────────────────────────────────

const IP_PATTERN = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/;

// ─── URL Extraction Patterns ──────────────────────────────────────────────────

const HREF_PATTERN = /href=["']([^"'#][^"']*?)["']/gi;
const PLAIN_URL_PATTERN = /https?:\/\/[^\s<>"'}\]]+/gi;
const DISPLAY_TEXT_PATTERN = /<a[^>]*href=["'][^"']*["'][^>]*>([^<]*)<\/a>/gi;

// ─── Domain Extractor ─────────────────────────────────────────────────────────

function extractRootDomain(hostname) {
  if (!hostname) return '';
  const clean = hostname.replace(/^www\./, '').toLowerCase();
  const parts = clean.split('.');
  if (parts.length <= 2) return clean;
  return parts.slice(-2).join('.');
}

function getHostname(urlStr) {
  try {
    const normalized = urlStr.startsWith('http') ? urlStr : 'https://' + urlStr;
    return new URL(normalized).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function getTLD(hostname) {
  if (!hostname) return '';
  const parts = hostname.split('.');
  return '.' + parts[parts.length - 1];
}

// ─── Risk Analysis for a Single URL ──────────────────────────────────────────

function analyzeURL(href, displayText) {
  const hostname = getHostname(href);
  const rootDomain = extractRootDomain(hostname);
  const tld = getTLD(hostname);

  const isHTTPS = href.toLowerCase().startsWith('https://');
  const isIP = IP_PATTERN.test(hostname);
  const isShortener = URL_SHORTENERS.some(
    (s) => hostname === s || hostname.endsWith('.' + s)
  );

  // Suspicious TLD check
  const suspiciousTLD = SUSPICIOUS_TLDS.includes(tld);

  // Lookalike detection
  let isLookalike = false;
  let lookalikeBrand = null;

  for (const knownDomain of KNOWN_BRAND_DOMAINS) {
    const knownRoot = extractRootDomain(knownDomain);
    if (rootDomain === knownRoot) {
      // Exact match — legitimate, not lookalike
      isLookalike = false;
      break;
    }
    const dist = levenshtein(rootDomain, knownRoot);
    if (dist > 0 && dist <= 2 && rootDomain.length >= 4) {
      isLookalike = true;
      // Find the brand name for this domain
      for (const [brand, domains] of Object.entries(
        // Import inline to avoid circular ref issues
        {
          paypal: ['paypal.com'], google: ['google.com', 'gmail.com'],
          microsoft: ['microsoft.com', 'live.com', 'outlook.com'],
          apple: ['apple.com'], amazon: ['amazon.com'], netflix: ['netflix.com'],
          facebook: ['facebook.com', 'meta.com'], fedex: ['fedex.com'], ups: ['ups.com'],
          irs: ['irs.gov'], docusign: ['docusign.com'], chase: ['chase.com'],
        }
      )) {
        if (domains.some((d) => extractRootDomain(d) === knownRoot)) {
          lookalikeBrand = brand;
          break;
        }
      }
      break;
    }
  }

  // Build risk tags
  const riskTags = [];
  if (isIP) riskTags.push('IP-Based');
  if (isShortener) riskTags.push('URL Shortener');
  if (isLookalike) riskTags.push(`Lookalike (${lookalikeBrand || 'brand'})`);
  if (!isHTTPS) riskTags.push('No HTTPS');
  if (suspiciousTLD) riskTags.push(`Suspicious TLD (${tld})`);

  // Compute risk score
  let riskScore = 0;
  if (isIP) riskScore += 60;
  if (isShortener) riskScore += 45;
  if (isLookalike) riskScore += 90;
  if (!isHTTPS) riskScore += 20;
  if (suspiciousTLD) riskScore += 35;
  riskScore = Math.min(riskScore, 100);

  // Check for display text mismatch (shown as one URL, goes to another)
  let hasMismatch = false;
  if (displayText && displayText.trim()) {
    const dispHost = getHostname(displayText.includes('://') ? displayText : 'https://' + displayText);
    if (dispHost) {
      const dispRoot = extractRootDomain(dispHost);
      if (dispRoot && dispRoot !== rootDomain) {
        hasMismatch = true;
        riskTags.push('Link Text Mismatch');
        riskScore = Math.min(riskScore + 30, 100);
      }
    }
  }

  return {
    displayText: displayText || href,
    href,
    hostname,
    rootDomain,
    isIP,
    isShortener,
    isLookalike,
    lookalikeBrand,
    isHTTPS,
    suspiciousTLD,
    hasMismatch,
    riskScore,
    riskTags,
  };
}

// ─── Main Export ──────────────────────────────────────────────────────────────

export function extractAndAnalyzeURLs(emailText) {
  const text = emailText || '';
  const urlMap = new Map(); // href → displayText

  // Extract href="..." URLs with associated display text
  const linkPattern = /<a[^>]*href=["']([^"'#][^"']*?)["'][^>]*>([^<]*)<\/a>/gi;
  let linkMatch;
  while ((linkMatch = linkPattern.exec(text)) !== null) {
    const href = linkMatch[1].trim();
    const display = linkMatch[2].trim();
    if (href && !href.startsWith('mailto:') && !href.startsWith('tel:')) {
      if (!urlMap.has(href)) urlMap.set(href, display);
    }
  }

  // Extract href without display text
  const hrefOnly = /href=["']([^"'#][^"']*?)["']/gi;
  let hrefMatch;
  while ((hrefMatch = hrefOnly.exec(text)) !== null) {
    const href = hrefMatch[1].trim();
    if (href && !href.startsWith('mailto:') && !href.startsWith('tel:') && !urlMap.has(href)) {
      urlMap.set(href, href);
    }
  }

  // Extract plain URLs
  const plainMatches = text.match(PLAIN_URL_PATTERN) || [];
  for (const url of plainMatches) {
    const cleaned = url.replace(/[.,;!?)\]]+$/, ''); // strip trailing punctuation
    if (!urlMap.has(cleaned)) {
      urlMap.set(cleaned, cleaned);
    }
  }

  // Analyze all unique URLs
  const results = [];
  for (const [href, displayText] of urlMap) {
    if (href.length > 5 && href.length < 2000) {
      const analysis = analyzeURL(href, displayText);
      results.push(analysis);
    }
  }

  // Sort by risk score descending
  return results.sort((a, b) => b.riskScore - a.riskScore).slice(0, 50);
}
