// Revelio — Analysis Orchestrator
// Coordinates the rule engine and LLM analysis, then computes the blended risk score.

'use strict';

import { runRuleEngine } from './ruleEngine.js';
import { extractAndAnalyzeURLs } from '../utils/urlScanner.js';
import { parseHeaders } from '../utils/headerParser.js';
import {
  LLM_WEIGHT,
  RULE_WEIGHT,
  THRESHOLD_CONFIRMED,
  THRESHOLD_LIKELY,
  THRESHOLD_SUSPICIOUS,
} from './constants.js';

// ─── Email Data Extractor ─────────────────────────────────────────────────────

/**
 * Parses raw email text into a structured data object used by the rule engine.
 *
 * @param {string} rawText  Raw email text (headers + body).
 * @returns {object}        Structured email data object.
 */
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

/**
 * Blends the LLM score and rule-engine score into a single final risk score.
 * LLM carries more weight (60%) as it evaluates semantic context.
 *
 * @param {number} llmScore   Contextual score from the LLM (0-100).
 * @param {number} ruleScore  Deterministic score from the rule engine (0-100).
 * @returns {number}          Final blended score (0-100).
 */
export function computeFinalScore(llmScore, ruleScore) {
  return Math.min(100, Math.round(llmScore * LLM_WEIGHT + ruleScore * RULE_WEIGHT));
}

// ─── Verdict from Score ───────────────────────────────────────────────────────

/**
 * Converts a final risk score into a human-readable verdict string.
 * The sensitivity setting shifts all thresholds up or down by up to ±20 points.
 *
 * @param {number} score        Final blended score (0-100).
 * @param {number} sensitivity  User-configured sensitivity (0-100, default 50).
 * @returns {'Safe'|'Suspicious'|'Likely Phishing'|'Confirmed Phishing'}
 */
export function scoreToVerdict(score, sensitivity = 50) {
  // Positive offset = more sensitive (lower thresholds), negative = less sensitive.
  const offset = (sensitivity - 50) * 0.4;
  if (score >= Math.max(0, Math.min(100, THRESHOLD_CONFIRMED + offset))) return 'Confirmed Phishing';
  if (score >= Math.max(0, Math.min(100, THRESHOLD_LIKELY    + offset))) return 'Likely Phishing';
  if (score >= Math.max(0, Math.min(100, THRESHOLD_SUSPICIOUS + offset))) return 'Suspicious';
  return 'Safe';
}

// ─── Main Analysis Function ───────────────────────────────────────────────────

/**
 * Parses the raw email text and runs all deterministic detection rules.
 * The LLM step happens separately in background.js after this returns.
 *
 * @param {string} rawEmailText  Raw email text (headers + body).
 * @returns {Promise<{ emailData: object, ruleResult: object }>}
 */
export async function analyzeEmail(rawEmailText) {
  const emailData = parseEmailData(rawEmailText);
  const ruleResult = runRuleEngine(emailData);

  return {
    emailData,
    ruleResult,
  };
}
