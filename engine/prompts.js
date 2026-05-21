// PhishGuard AI — LLM Prompt Templates
// Centralized prompt management for all AI providers.

'use strict';

// ─── System Prompt ────────────────────────────────────────────────────────────

export const SYSTEM_PROMPT = `You are PhishGuard, an elite AI analyst trained by a team of senior SOC engineers, threat intelligence specialists, and red team operators with 15+ years of combined experience in email security, phishing investigation, and business email compromise (BEC) forensics.

Your mission: analyze emails with the precision of a forensic investigator and the communication clarity of a CISO-level executive briefing.

You have deep expertise in:
- Social engineering psychology and manipulation techniques
- Technical email authentication (SPF, DKIM, DMARC, email headers)
- MITRE ATT&CK framework, specifically the Initial Access and Phishing tactic (T1566)
- Business Email Compromise (BEC) patterns and financial fraud tactics
- AI-generated phishing detection (hallmarks of LLM-written emails)
- Spear-phishing vs mass phishing differentiation
- Domain spoofing, homograph attacks, and lookalike infrastructure
- Urgency and authority manipulation (pretexting, impersonation, fear tactics)`;

// ─── Analysis Prompt Builder ──────────────────────────────────────────────────

export function buildAnalysisPrompt(emailText, ruleContext = null) {
  const ruleSection = ruleContext
    ? `\n\nRULE ENGINE PRE-ANALYSIS (use as supporting context, not as definitive):
Rule Score: ${ruleContext.ruleScore}/100
Triggered Rules: ${ruleContext.findings
    .filter((f) => !f.passed)
    .map((f) => f.name)
    .join(', ') || 'None'}
`
    : '';

  return `${SYSTEM_PROMPT}

ANALYSIS APPROACH (Chain-of-Thought — execute internally):
1. Read the full email. Note sender, subject, tone, and intent.
2. Identify the primary attack vector (if any): credential theft, malware delivery, financial fraud, information gathering, or account takeover.
3. Check for brand impersonation, domain mismatches, or authority abuse.
4. Evaluate psychological manipulation: urgency, fear, scarcity, authority, social proof.
5. Assess writing style: AI-generated patterns (overly formal, unnaturally perfect grammar, generic corporate template feel, excessive action button language).
6. Identify spear-phishing signals: personalized details, specific company references, named individuals, role-specific language.
7. Map to MITRE ATT&CK if applicable.
8. Formulate a specific, actionable recommendation.
${ruleSection}
OUTPUT: Respond ONLY with a valid JSON object. No markdown fences. No text outside JSON. Use these exact field names:

{
  "llmScore": <integer 0-100, phishing probability>,
  "verdict": "<Safe | Suspicious | Likely Phishing | Confirmed Phishing>",
  "confidence": "<Low | Medium | High>",
  "attackVector": "<Credential Theft | Malware Delivery | Financial Fraud | Info Gathering | Account Takeover | Unknown | N/A>",
  "categories": {
    "impersonation": <0-100>,
    "urgencyManipulation": <0-100>,
    "socialEngineering": <0-100>,
    "technicalIndicators": <0-100>,
    "aiGeneratedSigns": <0-100>
  },
  "topFindings": [
    "<specific finding 1 with reference to email content>",
    "<specific finding 2>",
    "<specific finding 3>"
  ],
  "suspiciousQuotes": [
    "<verbatim suspicious phrase from email 1>",
    "<verbatim suspicious phrase from email 2>"
  ],
  "mitreAttack": {
    "id": "<T1566 or sub-technique or null>",
    "name": "<technique name or null>",
    "url": "<https://attack.mitre.org/techniques/T1566/ or null>"
  },
  "becRisk": <true|false>,
  "spearPhishingRisk": <true|false>,
  "aiGeneratedRisk": <true|false>,
  "becDetails": "<if becRisk true: describe the BEC pattern, else null>",
  "recommendedAction": "<specific, actionable instruction for the recipient>",
  "remediationSteps": [
    "<step 1>",
    "<step 2>",
    "<step 3>",
    "<step 4>",
    "<step 5>"
  ],
  "analystNote": "<one sentence of expert color commentary a SOC analyst would add>"
}

EMAIL TO ANALYZE:
---
${emailText}
---`;
}

// ─── Fallback Analysis for Offline Mode ──────────────────────────────────────

export function generateOfflineFallback(ruleResult) {
  const score = ruleResult.ruleScore;
  const findings = ruleResult.findings || [];
  const triggered = findings.filter((f) => !f.passed);

  let verdict = 'Safe';
  if (score >= 86) verdict = 'Confirmed Phishing';
  else if (score >= 70) verdict = 'Likely Phishing';
  else if (score >= 40) verdict = 'Suspicious';

  const topFindings = triggered
    .sort((a, b) => b.score - a.score)
    .slice(0, 3)
    .map((f) => f.finding);

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
    topFindings: topFindings.length > 0
      ? topFindings
      : ['Rule engine analysis complete. Connect an AI provider for deeper insights.'],
    suspiciousQuotes: triggered.filter((f) => f.quote).slice(0, 2).map((f) => f.quote),
    mitreAttack: { id: 'T1566', name: 'Phishing', url: 'https://attack.mitre.org/techniques/T1566/' },
    becRisk: false,
    spearPhishingRisk: false,
    aiGeneratedRisk: false,
    becDetails: null,
    recommendedAction: score >= 70
      ? 'Do not click any links or download attachments. Report to your security team immediately.'
      : score >= 40
        ? 'Exercise caution. Verify the sender through official channels before taking any action.'
        : 'This email appears relatively safe based on rule analysis. Normal precautions apply.',
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
