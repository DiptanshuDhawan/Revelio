// Revelio — Analysis Cache
// Shared helpers for hashing emails and reading/writing per-email analysis
// results to chrome.storage.local.
//
// This is the single source of truth for cache operations.
// Both background.js (service worker) and popup.js (renderer) import from here,
// ensuring the key algorithm and TTL are never out of sync between the two contexts.

'use strict';

import { CACHE_TTL_MS } from '../engine/constants.js';

// ─── Email Fingerprinting ─────────────────────────────────────────────────────

/**
 * Produces a stable storage key for an email by hashing the first 2,000
 * characters with a djb2-style algorithm.
 *
 * NOT cryptographic — only used for local cache keying.
 *
 * @param {string} text  Raw email text (headers + body).
 * @returns {string}     A cache key, e.g. "reveliocache_v1_1a2b3c".
 */
export function hashEmail(text) {
  let hash = 5381;
  for (let i = 0; i < Math.min(text.length, 2000); i++) {
    hash = ((hash << 5) + hash) ^ text.charCodeAt(i);
    hash = hash & 0xffffffff; // keep 32-bit signed
  }
  return 'reveliocache_v1_' + Math.abs(hash).toString(36);
}

// ─── Cache Write ──────────────────────────────────────────────────────────────

/**
 * Persists an analysis result to chrome.storage.local, keyed by email hash.
 * Also updates the pointer key for the most-recently cached result.
 *
 * @param {string} emailText  Raw email text.
 * @param {object} result     Full analysis result object.
 */
export async function cacheAnalysisResult(emailText, result) {
  try {
    const key = hashEmail(emailText);
    await chrome.storage.local.set({
      [key]: { result, cachedAt: Date.now(), emailPreview: emailText.slice(0, 80) },
      revelio_last_cache_key: key, // pointer for quick lookup of the latest result
    });
  } catch {
    // Non-fatal — the analysis result is still returned to the caller.
  }
}

// ─── Cache Read ───────────────────────────────────────────────────────────────

/**
 * Retrieves a cached analysis result for the given email text.
 * Returns null if no entry exists or the entry has expired.
 *
 * @param {string} emailText  Raw email text.
 * @returns {Promise<object|null>}
 */
export async function getCachedResult(emailText) {
  try {
    const key = hashEmail(emailText);
    const data = await chrome.storage.local.get(key);
    if (data[key]) {
      const ageMs = Date.now() - (data[key].cachedAt || 0);
      if (ageMs < CACHE_TTL_MS) return data[key].result;
    }
  } catch {
    // Fall through to return null.
  }
  return null;
}

// ─── Cache Invalidation ───────────────────────────────────────────────────────

/**
 * Removes the cache entry for the given email text and clears the pointer key.
 * Call this when the user explicitly requests a fresh re-analysis.
 *
 * @param {string} [emailText='']  Raw email text (optional).
 */
export async function clearCachedResult(emailText = '') {
  try {
    const keys = ['revelio_last_cache_key'];
    if (emailText) keys.push(hashEmail(emailText));

    // Also remove whichever key was cached most recently
    const data = await chrome.storage.local.get('revelio_last_cache_key');
    const lastKey = data.revelio_last_cache_key;
    if (lastKey) keys.push(lastKey);

    await chrome.storage.local.remove([...new Set(keys)]);
  } catch {
    // Non-fatal.
  }
}
