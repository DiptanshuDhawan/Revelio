/**
 * Mapping of confusable Unicode characters to their Latin equivalents
 * Used for detecting IDN (Internationalized Domain Name) homograph attacks.
 */
export const HOMOGLYPH_MAP = {
  // Cyrillic
  'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', 'і': 'i',
  'ѕ': 's', 'ј': 'j', 'ԛ': 'q', 'ԝ': 'w',
  // Greek
  'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'h', 'ι': 'i', 'κ': 'k', 'μ': 'm',
  'ν': 'n', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'y', 'χ': 'x', 'ω': 'w',
  // Lookalike symbols
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b',
  'ǃ': '!', '？': '?', '．': '.', '／': '/', '：': ':', '；': ';',
  '＠': '@', '［': '[', '］': ']', '｛': '{', '｝': '}'
};

export function normalizeHomoglyphs(text) {
  if (!text) return text;
  let normalized = '';
  let replacedCount = 0;
  for (const char of text.toLowerCase()) {
    if (HOMOGLYPH_MAP[char]) {
      normalized += HOMOGLYPH_MAP[char];
      replacedCount++;
    } else {
      normalized += char;
    }
  }
  return { normalized, replacedCount };
}

export function detectHomoglyphAttack(hostname, knownBrands) {
  if (!hostname) return null;
  
  // Direct check for punycode (xn--)
  if (hostname.includes('xn--')) {
    return { isHomoglyph: true, type: 'punycode', target: null };
  }

  const { normalized, replacedCount } = normalizeHomoglyphs(hostname);
  
  if (replacedCount > 0) {
    // Check if the normalized version matches a known brand
    for (const brand of knownBrands) {
      if (normalized.includes(brand)) {
        return { isHomoglyph: true, type: 'unicode_substitution', target: brand };
      }
    }
    // If it has substitutions but doesn't match a brand directly, still suspicious
    return { isHomoglyph: true, type: 'unicode_substitution', target: null };
  }
  
  return { isHomoglyph: false, type: null, target: null };
}
