// Revelio — External URL Safety Checks
// Layer 2: Google Safe Browsing (heuristic) and Layer 3: VirusTotal (deep scan).
// Both are optional — they require user-supplied API keys in Settings.
// URLs are stripped of query params/fragments before submission to protect privacy.


/**
 * Strips query parameters and fragments from a URL for privacy before external submission.
 */
export function stripPII(urlStr) {
  try {
    const url = new URL(urlStr);
    url.search = '';
    url.hash = '';
    url.username = '';
    url.password = '';
    return url.toString();
  } catch {
    return urlStr;
  }
}

/**
 * Layer 2: Google Safe Browsing Lookup API (v4)
 * (v4 is used here for simplicity as v5 hash-prefix computation is extremely complex in raw JS without libraries,
 * and we only do on-demand lookup anyway).
 * We only send stripped URLs.
 */
export async function checkSafeBrowsing(url, apiKey) {
  if (!apiKey) return null;
  const safeUrl = stripPII(url);
  
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
  const payload = {
    client: {
      clientId: 'revelio',
      clientVersion: chrome.runtime.getManifest().version,
    },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url: safeUrl }]
    }
  };

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) return { error: `HTTP ${response.status}` };

    const data = await response.json();
    if (data && data.matches && data.matches.length > 0) {
      return { 
        isSafe: false,
        threatType: data.matches[0].threatType
      };
    }
    return { isSafe: true };
  } catch (err) {
    return { error: err.message };
  }
}

/**
 * Layer 3: VirusTotal URL Scan (v3 API)
 */
export async function checkVirusTotal(url, apiKey) {
  if (!apiKey) return null;
  const safeUrl = stripPII(url);
  
  // Base64 encode URL for the ID
  // VT requires unpadded base64url encoding
  let urlId = btoa(safeUrl).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  
  const endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
  
  try {
    const response = await fetch(endpoint, {
      method: 'GET',
      headers: { 
        'x-apikey': apiKey,
        'Accept': 'application/json'
      }
    });

    if (response.status === 404) {
      // URL not found in VT database, so let's submit it for scanning
      try {
        const submitParams = new URLSearchParams();
        submitParams.append('url', safeUrl);
        const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
          method: 'POST',
          headers: {
            'x-apikey': apiKey,
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: submitParams.toString()
        });
        
        if (submitRes.ok) {
          return { status: 'submitted', message: 'Submitted for scanning. Check back in 1-2 minutes.' };
        }
      } catch (submitErr) {
        console.error('VT Submit error:', submitErr);
      }
      return { status: 'not_found', message: 'Not found on VirusTotal. Auto-scan failed.' };
    }

    if (!response.ok) return { error: `HTTP ${response.status}` };

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;
    const results = data.data.attributes.last_analysis_results;
    
    // Get a few top engines that detected it
    const detectingEngines = [];
    for (const [engine, result] of Object.entries(results)) {
      if (result.category === 'malicious' || result.category === 'suspicious') {
        detectingEngines.push(`${engine}: ${result.result}`);
      }
    }

    return {
      stats: stats,
      totalDetected: stats.malicious + stats.suspicious,
      totalEngines: stats.malicious + stats.suspicious + stats.harmless + stats.undetected,
      detectingEngines: detectingEngines.slice(0, 3) // Top 3
    };

  } catch (err) {
    return { error: err.message };
  }
}
