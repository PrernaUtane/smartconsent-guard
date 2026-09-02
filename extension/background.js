/**
 * background.js — SmartConsent Guard Service Worker
 * 
 * Features:
 * - Navigation interception with heuristic + Google Safe Browsing + VirusTotal checks
 * - Popup reads storage directly
 * - Allowed/blocked domains persisted across sessions
 * - Multi-layered security: Heuristic → Google Safe Browsing → VirusTotal
 */

// ✅ FIXED: Use 127.0.0.1 instead of localhost
const BACKEND_URL = "http://127.0.0.1:8000";
const RISK_THRESHOLD = 60;

// ─────────────────────────────────────────────────────────────────────────────
// Navigation Interception — Checks URL before page loads
// ─────────────────────────────────────────────────────────────────────────────

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only handle main-frame navigations
  if (details.frameId !== 0) return;

  const { tabId, url } = details;

  // Skip non-HTTP urls, extension pages, and local server
  if (
    !url.startsWith("http") ||
    url.startsWith("chrome") ||
    url.includes("chrome-extension") ||
    url.includes("localhost") ||
    url.includes("127.0.0.1")
  ) return;

  // 1. Get hostname for domain matching
  let hostname;
  try {
    hostname = new URL(url).hostname;
  } catch { return; }

  // 2. Check if user already allowed or blocked this domain
  const storage = await chrome.storage.local.get(["allowed_sites", "blocked_sites"]);
  const allowed_sites = new Set(storage.allowed_sites || []);
  const blocked_sites = new Set(storage.blocked_sites || []);

  if (allowed_sites.has(hostname)) return; // Site is allowed, skip analysis

  if (blocked_sites.has(hostname)) {
    chrome.tabs.remove(tabId).catch(() => {});
    return;
  }

  // Clear stale data for this tab
  await chrome.storage.local.remove([`analysis_${tabId}`, `phishing_${tabId}`]);

  try {
    // ─── STEP 1: Check with heuristic engine ───
    const result = await checkUrl(url);
    let isPhishing = result.is_phishing;
    let riskScore = result.risk_score;
    let reasons = result.reasons || [];

    // ─── STEP 2: If heuristic score is > 30, check Google Safe Browsing ───
    if (riskScore > 30) {
      try {
        const gsbResult = await checkGoogleSafeBrowsing(url);
        if (gsbResult.is_malicious) {
          // Google flagged it – override heuristic result
          isPhishing = true;
          riskScore = Math.max(riskScore, 80);
          reasons.push(`Google Safe Browsing: ${gsbResult.message}`);
          console.log(`[SmartConsent] Google Safe Browsing flagged: ${url} - ${gsbResult.threat_type}`);
        } else {
          console.log(`[SmartConsent] Google Safe Browsing: ${url} is clean`);
        }
      } catch (gsbError) {
        console.warn('[SmartConsent] Google Safe Browsing check failed:', gsbError.message);
        // Continue with heuristic result – fail open
      }
    }

    // ─── STEP 3: If heuristic score is > 30, check VirusTotal ───
    if (riskScore > 30) {
      try {
        const vtResult = await checkVirusTotal(url);
        if (vtResult.is_malicious) {
          // VirusTotal flagged it – override heuristic result
          isPhishing = true;
          riskScore = Math.max(riskScore, 85);
          reasons.push(`VirusTotal: ${vtResult.message}`);
          console.log(`[SmartConsent] VirusTotal flagged: ${url} - ${vtResult.malicious_vendors} vendors`);
        } else {
          console.log(`[SmartConsent] VirusTotal: ${url} is clean (${vtResult.total_vendors} vendors checked)`);
        }
      } catch (vtError) {
        console.warn('[SmartConsent] VirusTotal check failed:', vtError.message);
        // Continue with heuristic result – fail open
      }
    }

    // ─── STEP 4: Store result so popup can display it ───
    await chrome.storage.local.set({
      [`phishing_${tabId}`]: {
        url,
        is_phishing: isPhishing,
        risk_score: riskScore,
        reasons: reasons,
        timestamp: Date.now(),
      },
    });

    // ─── STEP 5: Block if phishing ───
    if (isPhishing || riskScore > RISK_THRESHOLD) {
      // Store the blocked URL for "Enter Anyway" recovery
      await chrome.storage.session.set({ [`blockedUrl_${tabId}`]: url });

      const warningUrl =
        chrome.runtime.getURL("warning.html") +
        `?url=${encodeURIComponent(url)}` +
        `&score=${riskScore}` +
        `&reasons=${encodeURIComponent(JSON.stringify(reasons))}` +
        `&tabId=${tabId}`;

      // Small delay so navigation completes before redirect
      setTimeout(() => {
        chrome.tabs.update(tabId, { url: warningUrl });
      }, 100);

      updateBadge(tabId, riskScore);
    }
  } catch (err) {
    console.warn("[SmartConsent] Backend unreachable for URL check:", err.message);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Message Listener
// ─────────────────────────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id;

  // content.js asks for its own tabId
  if (message.type === "GET_TAB_ID" && tabId !== undefined) {
    sendResponse({ tabId });
    return true;
  }

  // content.js sends policy analysis result
  if (message.type === "POLICY_ANALYSIS_RESULT" && tabId !== undefined) {
    chrome.storage.local.set({
      [`analysis_${tabId}`]: {
        ...message.data,
        url: sender.tab.url,
        timestamp: Date.now(),
      },
    });
    updateBadge(tabId, message.data.risk_score);
    sendResponse({ ok: true });
    return true;
  }

  // warning.html or popup.js signals user clicked "Enter Anyway" or "Allow Site"
  if (message.type === "ALLOW_TAB" && message.url !== undefined) {
    let hostname;
    try { hostname = new URL(message.url).hostname; } catch { return; }

    chrome.storage.local.get("allowed_sites").then((storage) => {
      const allowed_sites = new Set(storage.allowed_sites || []);
      allowed_sites.add(hostname);
      chrome.storage.local.set({ allowed_sites: [...allowed_sites] });
      sendResponse({ ok: true });
    });
    return true;
  }

  // Popup requests tab data
  if (message.type === "GET_TAB_DATA") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTabId = tabs[0]?.id;
      if (!activeTabId) { sendResponse({}); return; }
      const keys = [`analysis_${activeTabId}`, `phishing_${activeTabId}`];
      chrome.storage.local.get(keys, (data) => {
        sendResponse({
          analysis: data[`analysis_${activeTabId}`] || null,
          phishing: data[`phishing_${activeTabId}`] || null,
          tabId: activeTabId,
          tabUrl: tabs[0]?.url,
        });
      });
    });
    return true;
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// API Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Check URL against heuristic engine
 */
async function checkUrl(url) {
  const response = await fetch(`${BACKEND_URL}/check-url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

/**
 * Check URL against Google Safe Browsing API via backend proxy
 */
async function checkGoogleSafeBrowsing(url) {
  const response = await fetch(`${BACKEND_URL}/check-google-safebrowsing`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(8000),
  });
  if (!response.ok) throw new Error(`Google Safe Browsing API HTTP ${response.status}`);
  return response.json();
}

/**
 * Check URL against VirusTotal API via backend proxy
 * Checks 70+ security vendors for comprehensive threat detection
 */
async function checkVirusTotal(url) {
  const response = await fetch(`${BACKEND_URL}/check-virustotal`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(12000), // VirusTotal is slower
  });
  if (!response.ok) throw new Error(`VirusTotal API HTTP ${response.status}`);
  return response.json();
}

// ─────────────────────────────────────────────────────────────────────────────
// Badge Helper
// ─────────────────────────────────────────────────────────────────────────────

function updateBadge(tabId, riskScore) {
  let color, text;
  if (riskScore > 60)      { color = "#ff4757"; text = "HIGH"; }
  else if (riskScore > 30) { color = "#ffa502"; text = "MED";  }
  else                     { color = "#2ed573"; text = "LOW";  }

  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text, tabId });
}