// PhishGuard AI — LLM Prompt Templates
// Centralized prompt management for all AI providers.

'use strict';

// ─── System Prompt ────────────────────────────────────────────────────────────

export const SYSTEM_PROMPT = `You are PhishGuard, an expert email security analyst. You analyze emails for phishing threats and return structured JSON results. You have expertise in social engineering, email authentication (SPF/DKIM/DMARC), MITRE ATT&CK (T1566), BEC fraud, AI-generated phishing, spear-phishing, domain spoofing, and urgency manipulation.

IMPORTANT: You are a JSON API. Your entire response must be a single valid JSON object. No text before or after. No markdown. No explanation.`;

// ─── Analysis Prompt Builder ──────────────────────────────────────────────────

import { scoreToVerdict } from './analyzer.js';

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

{"llmScore":0,"verdict":"Safe","confidence":"Medium","attackVector":"N/A","categories":{"impersonation":"<0-100>","urgencyManipulation":"<0-100>","socialEngineering":"<0-100>","technicalIndicators":"<0-100>","aiGeneratedSigns":"<0-100>"},"threatNarrative":"","topFindings":[{"title":"","detail":"","severity":"low"}],"suspiciousQuotes":[],"mitreAttack":{"id":null,"name":null,"url":null},"becRisk":false,"spearPhishingRisk":false,"aiGeneratedRisk":false,"becDetails":null,"recommendedAction":"","remediationSteps":["","",""],"analystNote":""}

FIELD RULES:
- llmScore: integer 0 to 100 (phishing probability)
- verdict: exactly one of "Safe", "Suspicious", "Likely Phishing", "Confirmed Phishing"
- confidence: exactly one of "Low", "Medium", "High"
- attackVector: one of "Credential Theft", "Malware Delivery", "Financial Fraud", "Info Gathering", "Account Takeover", "Unknown", "N/A"
- categories: each value is integer 0 to 100
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

export function generateOfflineFallback(ruleResult, sensitivity = 50) {
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
    analystNote: '[AI provider offline — analysis based on rule engine only. Connect Ollama or configure an API key for full AI analysis.]',
    _offlineMode: true,
  };
}
