// PhishGuard AI — Analyzer Orchestrator
// Coordinates rule engine + LLM analysis and computes final risk score.

'use strict';

import { runRuleEngine } from './ruleEngine.js';
import { extractAndAnalyzeURLs } from '../utils/urlScanner.js';
import { parseHeaders } from '../utils/headerParser.js';

// ─── Email Data Extractor ─────────────────────────────────────────────────────

export function parseEmailData(rawText) {
  const text = rawText || '';

  // Try to parse structured headers from the top
  const headers = parseHeaders(text);

  // Extract body: everything after the first blank line
  const blankLineIdx = text.search(/\n\s*\n/);
  const body = blankLineIdx !== -1 ? text.slice(blankLineIdx + 2).trim() : text;

  // Extract URLs from the full text
  const urls = extractAndAnalyzeURLs(text);

  // Extract attachments mentioned in text (filename patterns)
  const attachmentPattern = /\b[\w\s-]+\.[a-zA-Z]{2,5}\b/g;
  const attachmentCandidates = (text.match(attachmentPattern) || []).filter((f) => {
    const ext = f.match(/\.[a-zA-Z]+$/)?.[0]?.toLowerCase();
    return ext && ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.exe', '.js',
      '.bat', '.vbs', '.scr', '.pif', '.cmd', '.hta', '.jar', '.msi'].includes(ext);
  });

  return {
    raw: text,
    subject: headers.subject || extractSubjectFromBody(text),
    fromDisplay: headers.fromDisplay || '',
    fromEmail: headers.fromEmail || '',
    replyTo: headers.replyTo || '',
    returnPath: headers.returnPath || '',
    to: headers.to || '',
    body,
    urls,
    attachments: attachmentCandidates.slice(0, 10),
    headers,
  };
}

function extractSubjectFromBody(text) {
  const match = text.match(/^Subject:\s*(.+)$/im);
  return match ? match[1].trim() : '';
}

// ─── Final Score Calculation ──────────────────────────────────────────────────

export function computeFinalScore(llmScore, ruleScore) {
  return Math.min(100, Math.round(llmScore * 0.6 + ruleScore * 0.4));
}

// ─── Verdict from Score ───────────────────────────────────────────────────────

export function scoreToVerdict(score, sensitivity = 50) {
  const offset = (sensitivity - 50) * 0.4;
  if (score >= Math.max(0, Math.min(100, 86 + offset))) return 'Confirmed Phishing';
  if (score >= Math.max(0, Math.min(100, 70 + offset))) return 'Likely Phishing';
  if (score >= Math.max(0, Math.min(100, 40 + offset))) return 'Suspicious';
  return 'Safe';
}

// ─── Main Analysis Function ───────────────────────────────────────────────────

export async function analyzeEmail(rawEmailText) {
  const emailData = parseEmailData(rawEmailText);
  const ruleResult = runRuleEngine(emailData);

  return {
    emailData,
    ruleResult,
  };
}
