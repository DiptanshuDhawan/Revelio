// PhishGuard AI — Email Header Parser
// Parses raw email headers into structured data with authentication results.

'use strict';

// ─── Header Field Extractor ───────────────────────────────────────────────────

function extractHeader(rawText, headerName) {
  // Match "Header-Name: value" possibly with folded lines (lines starting with whitespace)
  const pattern = new RegExp(`^${headerName}:\\s*(.+?)(?=\\n[^\\s]|$)`, 'im');
  const match = rawText.match(pattern);
  if (!match) return null;

  // Unfold folded header lines
  return match[1].replace(/\n\s+/g, ' ').trim();
}

// ─── Email Address Extractor ──────────────────────────────────────────────────

function parseEmailAddress(headerValue) {
  if (!headerValue) return { display: '', email: '' };

  // "Display Name <email@domain.com>" format
  const angleBracket = headerValue.match(/^"?([^"<]*?)"?\s*<([^>]+)>$/);
  if (angleBracket) {
    return {
      display: angleBracket[1].trim().replace(/^["']|["']$/g, ''),
      email: angleBracket[2].trim().toLowerCase(),
    };
  }

  // Plain email address
  const plain = headerValue.match(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/i);
  if (plain) {
    return { display: '', email: plain[0].toLowerCase() };
  }

  return { display: headerValue, email: '' };
}

function extractDomain(email) {
  const match = (email || '').match(/@([\w.-]+)$/);
  return match ? match[1].toLowerCase() : '';
}

function extractRootDomain(domain) {
  if (!domain) return '';
  const parts = domain.split('.');
  return parts.length <= 2 ? domain : parts.slice(-2).join('.');
}

// ─── Authentication Results Parser ───────────────────────────────────────────

function parseAuthResults(authHeader) {
  if (!authHeader) return { spf: 'not-present', dkim: 'not-present', dmarc: 'not-present' };

  const authText = authHeader.toLowerCase();

  function extractResult(protocol) {
    // Try "protocol=pass/fail/none/neutral"
    const pattern = new RegExp(`\\b${protocol}=([\\w-]+)`, 'i');
    const match = authText.match(pattern);
    if (!match) return 'not-present';

    const result = match[1].toLowerCase();
    if (result === 'pass') return 'pass';
    if (result === 'fail' || result === 'hardfail') return 'fail';
    if (result === 'softfail' || result === 'neutral') return 'softfail';
    if (result === 'none') return 'none';
    return result;
  }

  return {
    spf: extractResult('spf'),
    dkim: extractResult('dkim'),
    dmarc: extractResult('dmarc'),
  };
}

// ─── Received Header IP Extractor ─────────────────────────────────────────────

function extractFirstHopIP(rawText) {
  // Find all "Received: from ..." headers and get the last one (first hop)
  const receivedHeaders = [];
  const pattern = /^Received:\s*(.+?)(?=\n[^\s]|$)/gim;
  let match;
  while ((match = pattern.exec(rawText)) !== null) {
    receivedHeaders.push(match[1].replace(/\n\s+/g, ' ').trim());
  }

  if (receivedHeaders.length === 0) return null;

  // The last Received header is the oldest (first hop from sender)
  const lastReceived = receivedHeaders[receivedHeaders.length - 1];

  // Extract IP from "from [ip] by ..." or "[ip]"
  const ipMatch = lastReceived.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/);
  return ipMatch ? ipMatch[1] : null;
}

// ─── Main Export ──────────────────────────────────────────────────────────────

export function parseHeaders(rawText) {
  if (!rawText || typeof rawText !== 'string') {
    return createEmptyHeaders();
  }

  // Check if we even have proper headers (look for "From:" or "Subject:" near the top)
  const first500 = rawText.slice(0, 500);
  const hasHeaders = /^(From|To|Subject|Date|Message-ID|Received):/im.test(first500);

  if (!hasHeaders) {
    return createEmptyHeaders();
  }

  const fromRaw = extractHeader(rawText, 'From');
  const fromParsed = parseEmailAddress(fromRaw);

  const toRaw = extractHeader(rawText, 'To');
  const toParsed = parseEmailAddress(toRaw);

  const ccRaw = extractHeader(rawText, 'Cc');

  const replyToRaw = extractHeader(rawText, 'Reply-To');
  const replyToParsed = parseEmailAddress(replyToRaw);

  const returnPathRaw = extractHeader(rawText, 'Return-Path');
  const returnPathParsed = parseEmailAddress(returnPathRaw);

  const subject = extractHeader(rawText, 'Subject') || '';
  const date = extractHeader(rawText, 'Date') || '';
  const messageId = extractHeader(rawText, 'Message-ID') || '';
  const xMailer = extractHeader(rawText, 'X-Mailer') || '';
  const xOriginatingIP = extractHeader(rawText, 'X-Originating-IP') || '';
  const xForwardedFor = extractHeader(rawText, 'X-Forwarded-For') || '';

  // Authentication results
  const authResultsRaw = extractHeader(rawText, 'Authentication-Results') ||
    extractHeader(rawText, 'ARC-Authentication-Results') || '';
  const authResults = parseAuthResults(authResultsRaw);

  // DKIM-Signature presence (basic)
  const hasDKIMSignature = /^DKIM-Signature:/im.test(rawText);
  if (hasDKIMSignature && authResults.dkim === 'not-present') {
    authResults.dkim = 'present-unverified';
  }

  // Compute flags
  const fromDomain = extractRootDomain(extractDomain(fromParsed.email));
  const replyToDomain = replyToParsed.email
    ? extractRootDomain(extractDomain(replyToParsed.email))
    : null;
  const returnPathDomain = returnPathParsed.email
    ? extractRootDomain(extractDomain(returnPathParsed.email))
    : null;

  const replyToDiffersFromFrom = !!(
    replyToDomain && fromDomain && replyToDomain !== fromDomain
  );

  const returnPathDiffersFromFrom = !!(
    returnPathDomain && fromDomain && returnPathDomain !== fromDomain
  );

  const firstHopIP = extractFirstHopIP(rawText) || xOriginatingIP || null;

  return {
    // Raw values
    fromRaw,
    toRaw,
    ccRaw,
    replyToRaw,
    returnPathRaw,

    // Parsed values
    fromDisplay: fromParsed.display,
    fromEmail: fromParsed.email,
    to: toParsed.email || toRaw || '',
    replyTo: replyToParsed.email || replyToRaw || '',
    returnPath: returnPathParsed.email || returnPathRaw || '',
    subject,
    date,
    messageId,
    xMailer,
    xOriginatingIP,
    xForwardedFor,

    // Authentication
    spfResult: authResults.spf,
    dkimResult: authResults.dkim,
    dmarcResult: authResults.dmarc,
    authResultsRaw,
    hasDKIMSignature,

    // Computed flags
    replyToDiffersFromFrom,
    returnPathDiffersFromFrom,
    fromDomain,
    replyToDomain,
    returnPathDomain,
    firstHopIP,

    // Metadata
    hasHeaders: true,
  };
}

function createEmptyHeaders() {
  return {
    fromRaw: null, toRaw: null, ccRaw: null, replyToRaw: null, returnPathRaw: null,
    fromDisplay: '', fromEmail: '', to: '', replyTo: '', returnPath: '',
    subject: '', date: '', messageId: '', xMailer: '', xOriginatingIP: '',
    xForwardedFor: '',
    spfResult: 'not-present', dkimResult: 'not-present', dmarcResult: 'not-present',
    authResultsRaw: '', hasDKIMSignature: false,
    replyToDiffersFromFrom: false, returnPathDiffersFromFrom: false,
    fromDomain: '', replyToDomain: null, returnPathDomain: null, firstHopIP: null,
    hasHeaders: false,
  };
}
