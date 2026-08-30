// Revelio — LLM Prompt Templates
// Centralised prompt management for all AI providers.
// Keeping prompts in one place makes it easy to tune instructions without
// touching provider-specific code in background.js.

'use strict';

// ─── System Prompt ────────────────────────────────────────────────────────────

export const SYSTEM_PROMPT = `You are Revelio, an expert email security analyst. You analyze emails for phishing threats and return structured JSON results. You have expertise in social engineering, email authentication (SPF/DKIM/DMARC), MITRE ATT&CK (T1566), BEC fraud, AI-generated phishing, spear-phishing, domain spoofing, and urgency manipulation.

IMPORTANT: You are a JSON API. Your entire response must be a single valid JSON object. No text before or after. No markdown. No explanation.`;

// ─── Analysis Prompt Builder ──────────────────────────────────────────────────

import { scoreToVerdict } from './analyzer.js';

/**
 * Builds the full prompt to send to any LLM provider.
 * The optional ruleContext injects deterministic pre-analysis results so the
 * LLM can use them as supporting evidence rather than starting from scratch.
 *
 * @param {string} emailText       Raw email text.
 * @param {object|null} ruleContext  Result object from runRuleEngine(), or null.
 * @returns {string}               Complete prompt string ready for the LLM.
 */
export function buildAnalysisPrompt(emailText, ruleContext = null) {
  const ruleSection = ruleContext
    ? `\n\nRULE ENGINE PRE-ANALYSIS (supporting context only):
Rule Score: ${ruleContext.ruleScore}/100
Triggered Rules: ${ruleContext.findings
    .filter((f) => !f.passed)
    .map((f) => f.name)
    .join(', ') || 'None'}
`
    : '';

  return `${SYSTEM_PROMPT}

TASK: Analyze the email below for phishing indicators. Think through these steps internally (do NOT write your reasoning):
1. Examine sender, subject, tone, intent
2. Identify attack vector: credential theft, malware, financial fraud, info gathering, account takeover
3. Check for brand impersonation, domain mismatches, authority abuse
4. Evaluate manipulation tactics: urgency, fear, scarcity, authority
5. Check for AI-generated writing patterns
6. Map to MITRE ATT&CK T1566 sub-techniques if applicable
${ruleSection}
Respond with ONLY this JSON structure (no other text):

{"llmScore":"<0-100>","verdict":"<Safe|Suspicious|Likely Phishing|Confirmed Phishing>","confidence":"<Low|Medium|High>","attackVector":"<vector>","categories":{"impersonation":"<0-100>","urgencyManipulation":"<0-100>","socialEngineering":"<0-100>","technicalIndicators":"<0-100>","aiGeneratedSigns":"<0-100>"},"threatNarrative":"<2-3 sentences explaining the threat or safety>","topFindings":[{"title":"<finding title>","detail":"<finding description>","severity":"<critical|high|medium|low>"}],"suspiciousQuotes":["<quote 1>"],"mitreAttack":{"id":"<T-code>","name":"<technique name>","url":"<mitre url>"},"becRisk":false,"spearPhishingRisk":false,"aiGeneratedRisk":false,"becDetails":"<details if BEC risk is true>","recommendedAction":"<one actionable recommendation>","remediationSteps":["<step 1>","<step 2>"],"analystNote":"<brief analyst summary>"}

FIELD RULES:
- llmScore: integer 0 to 100 (phishing probability)
- verdict: exactly one of "Safe", "Suspicious", "Likely Phishing", "Confirmed Phishing"
- confidence: exactly one of "Low", "Medium", "High"
- attackVector: one of "Credential Theft", "Malware Delivery", "Financial Fraud", "Info Gathering", "Account Takeover", "Unknown", "N/A"
- categories: each value is integer 0 to 100
- threatNarrative: MANDATORY 2-3 sentences summarizing the email and explaining why it is safe or a threat
- analystNote: MANDATORY 1 sentence explaining the final decision
- topFindings: 1-4 objects, severity is "critical", "high", "medium", or "low"
- suspiciousQuotes: 0-3 verbatim phrases copied from the email
- mitreAttack.id: "T1566", "T1566.001", "T1566.002", "T1566.003", "T1566.004", or null
- remediationSteps: 3-5 actionable steps specific to this email

EMAIL TO ANALYZE:
---
${emailText}
---`;
}


// ─── Fallback Analysis for Offline Mode ──────────────────────────────────────

/**
 * Generates a rule-engine-only analysis result when the LLM is unavailable.
 * The returned object is shaped identically to a real LLM result so the UI
 * renders without any special-case logic.
 *
 * @param {object} ruleResult    Result from runRuleEngine().
 * @param {number} sensitivity   User sensitivity setting (0-100, default 50).
 * @param {string} fallbackReason  Human-readable reason the LLM failed.
 * @returns {object}             LLM-shaped analysis result.
 */
export function generateOfflineFallback(ruleResult, sensitivity = 50, fallbackReason = 'Unknown error') {
  const score = ruleResult.ruleScore;
  const findings = ruleResult.findings || [];
  const triggered = findings.filter((f) => !f.passed);

  let verdict = scoreToVerdict(score, sensitivity);

  const topFindings = triggered
    .sort((a, b) => b.score - a.score)
    .slice(0, 3)
    .map((f) => ({
      title: f.name,
      detail: f.finding,
      severity: f.severity || 'medium'
    }));

  return {
    llmScore: score,
    verdict,
    confidence: 'Medium',
    attackVector: 'Unknown',
    categories: {
      impersonation: triggered.find((f) => f.id === 'SENDER_BRAND_SPOOF')?.score || 0,
      urgencyManipulation: triggered.find((f) => f.id === 'URGENCY_KEYWORDS')?.score || 0,
      socialEngineering: triggered.find((f) => f.id === 'GENERIC_GREETING')?.score || 0,
      technicalIndicators: triggered.find((f) => f.id === 'REPLY_TO_MISMATCH')?.score || 0,
      aiGeneratedSigns: 0,
    },
    threatNarrative: 'AI analysis is currently offline. This assessment is based entirely on static rule-engine checks and deterministic heuristics. Connect an AI provider for a complete narrative analysis.',
    topFindings: topFindings.length > 0
      ? topFindings
      : [{
          title: 'Rule Engine Analysis Complete',
          detail: 'Connect an AI provider for deeper semantic insights and threat narrative.',
          severity: 'low'
        }],
    suspiciousQuotes: triggered.filter((f) => f.quote).slice(0, 2).map((f) => f.quote),
    mitreAttack: { id: 'T1566', name: 'Phishing', url: 'https://attack.mitre.org/techniques/T1566/' },
    becRisk: false,
    spearPhishingRisk: false,
    aiGeneratedRisk: false,
    becDetails: null,
    recommendedAction: score >= 70
      ? 'Do not click links or download attachments. Report to IT security.'
      : score >= 40
      ? 'Verify the sender via another channel before taking action.'
      : 'No immediate threats detected, but always remain cautious.',
    remediationSteps: [
      'Do not click any links in this email until verified.',
      'Contact the sender through a known, trusted channel to confirm authenticity.',
      'Report this email to your IT security team.',
      'Do not provide any personal information in response to this email.',
      'If you clicked any links, run a security scan on your device immediately.',
    ],
    analystNote: `[AI Engine Offline. Reason: ${fallbackReason}. Analysis based on rule engine only.]`,
    _offlineMode: true,
  };
}
