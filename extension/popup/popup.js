// popup.js – Final version with error suppression and enhanced NLI endpoint
const BACKEND_URL = 'http://127.0.0.1:8000';
const CIRCUMFERENCE = 339.292;

// --- DOM elements ---
const siteUrl = document.getElementById('siteUrl');
const riskBadge = document.getElementById('riskBadge');
const riskScore = document.getElementById('riskScore');
const riskLevel = document.getElementById('riskLevel');
const riskRing = document.getElementById('riskRing');
const explanationText = document.getElementById('explanationText');
const clausesList = document.getElementById('clausesList');
const clauseCount = document.getElementById('clauseCount');
const allowBtn = document.getElementById('allowBtn');
const blockBtn = document.getElementById('blockBtn');

let currentDomain = '';
let currentUrl = '';

// --- Global error suppressor for chrome.runtime.lastError ---
const originalQuery = chrome.tabs.query;
chrome.tabs.query = function (queryInfo, callback) {
    originalQuery(queryInfo, (tabs) => {
        if (chrome.runtime.lastError) {
            console.debug('Ignored tabs.query error:', chrome.runtime.lastError.message);
            callback([]);
            return;
        }
        callback(tabs);
    });
};

const originalExecuteScript = chrome.scripting.executeScript;
chrome.scripting.executeScript = function (injection, callback) {
    originalExecuteScript(injection, (results) => {
        if (chrome.runtime.lastError) {
            console.debug('Ignored executeScript error:', chrome.runtime.lastError.message);
            callback([]);
            return;
        }
        callback(results);
    });
};

// --- Main entry point ---
document.addEventListener('DOMContentLoaded', async () => {
    try {
        const tab = await getCurrentTab();

        if (!tab || !tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('about:') || tab.url === '') {
            showInternalPageMessage();
            return;
        }

        currentUrl = tab.url;
        currentDomain = new URL(tab.url).hostname;
        siteUrl.textContent = currentDomain;

        // ✅ Step 1: Check for phishing (ALWAYS runs)
        const phishingResult = await checkUrl(currentUrl);
        updatePhishingUI(phishingResult);

        // ✅ Step 2: Try to extract and analyze policy text (if available)
        const policyText = await getPolicyText(tab.id);
        if (policyText && policyText.length > 50) {
            try {
                const policyResult = await analyzePolicyEnhanced(policyText);
                console.log('Policy Analysis Result:', policyResult);
                updatePolicyUI(policyResult);
            } catch (error) {
                console.error('Enhanced policy analysis failed, trying fallback:', error);
                const policyResult = await analyzePolicy(policyText);
                updatePolicyUI(policyResult);
            }
        } else {
            // ✅ ALWAYS show something meaningful on every site
            clausesList.innerHTML = `
                <div class="clause-empty">
                    ℹ️ No privacy policy detected on this page.<br>
                    <span style="font-size: 11px; color: rgba(255,255,255,0.4);">
                        SmartConsent Guard still protects you from phishing threats.
                    </span>
                </div>
            `;
            clauseCount.textContent = '—';
        }
    } catch (error) {
        console.error('Popup error:', error);
        riskScore.textContent = '!';
        explanationText.textContent = 'Error connecting to backend. Make sure the server is running.';
    }
});

function showInternalPageMessage() {
    siteUrl.textContent = '🔒 Internal Chrome Page';
    riskScore.textContent = '-';
    explanationText.textContent = 'SmartConsent Guard works on regular websites only.';
    riskRing.style.strokeDashoffset = CIRCUMFERENCE;
    riskBadge.textContent = 'N/A';
    riskBadge.className = 'badge badge-low';
    riskLevel.textContent = '—';
    clausesList.innerHTML = '<div class="clause-empty">No content to analyze</div>';
}

// --- API Calls ---

async function checkUrl(url) {
    const response = await fetch(`${BACKEND_URL}/check-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
    });
    if (!response.ok) throw new Error('Failed to check URL');
    return response.json();
}

async function analyzePolicyEnhanced(text) {
    const response = await fetch(`${BACKEND_URL}/analyze-policy-enhanced`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text })
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Server error: ${response.status} - ${errorText}`);
    }
    const data = await response.json();
    // ✅ Ensure we have a valid response structure
    if (!data.clauses) {
        data.clauses = [];
    }
    if (!data.method) {
        data.method = 'keyword';
    }
    return data;
}

async function analyzePolicy(text) {
    const response = await fetch(`${BACKEND_URL}/analyze-policy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text })
    });
    if (!response.ok) throw new Error('Failed to analyze policy');
    return response.json();
}

// --- UI Updates ---

function updatePhishingUI(result) {
    const score = result.risk_score;
    riskScore.textContent = score;

    const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
    riskRing.style.strokeDashoffset = offset;

    let color, level, badgeClass;
    if (score > 60) {
        color = '#e17055';
        level = 'HIGH';
        badgeClass = 'badge-high';
    } else if (score > 30) {
        color = '#fdcb6e';
        level = 'MEDIUM';
        badgeClass = 'badge-medium';
    } else {
        color = '#00b894';
        level = 'LOW';
        badgeClass = 'badge-low';
    }

    riskRing.style.stroke = color;
    riskLevel.textContent = level;
    riskLevel.style.color = color;
    riskBadge.textContent = level;
    riskBadge.className = `badge ${badgeClass}`;

    if (result.is_phishing) {
        explanationText.textContent = '⚠️ Phishing detected! Proceed with caution.';
        explanationText.style.color = '#e17055';
    } else {
        explanationText.textContent = result.reasons.length > 0
            ? `Detected: ${result.reasons.join(', ')}`
            : 'No phishing indicators.';
        explanationText.style.color = 'rgba(255,255,255,0.7)';
    }
}

function updatePolicyUI(result) {
    // ✅ Handle the response safely
    let clauses = [];
    const method = result.method || 'keyword';
    
    // ✅ Extract clauses from various possible response formats
    if (Array.isArray(result.clauses)) {
        clauses = result.clauses;
    } else if (result.clauses && typeof result.clauses === 'object') {
        if (Array.isArray(result.clauses.clauses)) {
            clauses = result.clauses.clauses;
        } else if (Array.isArray(result.clauses.data)) {
            clauses = result.clauses.data;
        } else {
            // Single clause object
            clauses = [result.clauses];
        }
    }

    // ✅ Display the risk score from the response
    if (result.ri_score !== undefined && result.ri_score !== null) {
        const score = result.ri_score;
        riskScore.textContent = score;
        
        // Update the ring
        const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
        riskRing.style.strokeDashoffset = offset;
        
        // Update colors
        let color, level, badgeClass;
        if (score > 60) {
            color = '#e17055';
            level = 'HIGH';
            badgeClass = 'badge-high';
        } else if (score > 30) {
            color = '#fdcb6e';
            level = 'MEDIUM';
            badgeClass = 'badge-medium';
        } else {
            color = '#00b894';
            level = 'LOW';
            badgeClass = 'badge-low';
        }
        
        riskRing.style.stroke = color;
        riskLevel.textContent = level;
        riskLevel.style.color = color;
        riskBadge.textContent = level;
        riskBadge.className = `badge ${badgeClass}`;
    }

    console.log(`Policy analysis method: ${method}`);
    console.log(`Clauses detected: ${clauses.length}`);

    clauseCount.textContent = clauses.length;

    if (clauses.length === 0) {
        clausesList.innerHTML = `
            <div class="clause-empty">
                ℹ️ No risky clauses detected in this policy.<br>
                <span style="font-size: 11px; color: rgba(255,255,255,0.4);">
                    The privacy policy appears to be safe.
                </span>
            </div>
        `;
        return;
    }

    let html = '';
    for (const clause of clauses) {
        let confidence = 1.0;
        if (typeof clause.confidence === 'number') {
            confidence = clause.confidence;
        } else if (clause.confidence && typeof clause.confidence === 'object') {
            confidence = clause.confidence.score || 1.0;
        }
        
        // ✅ Ensure confidence is within reasonable range
        confidence = Math.min(Math.max(confidence, 0.5), 1.0);
        
        const confidencePercent = Math.round(confidence * 100);
        const clauseType = clause.type || 'Unknown';
        const severity = clause.severity || 'MEDIUM';
        const icon = clause.icon || '🟠';
        
        let color = '#fdcb6e';
        if (severity === 'CRITICAL') color = '#e17055';
        else if (severity === 'HIGH') color = '#ffa502';
        else if (severity === 'MEDIUM') color = '#fdcb6e';
        else if (severity === 'LOW') color = '#00b894';
        
        // ✅ Show method indicator next to confidence
        const methodLabel = method === 'nli' ? '🤖 AI' : '📝 Keyword';
        
        html += `
            <div class="clause-item" style="border-left: 3px solid ${color};">
                <span class="clause-name">${escapeHtml(icon)} ${escapeHtml(clauseType)}</span>
                <span class="clause-confidence" style="color: ${color};">
                    ${confidencePercent}% ${methodLabel}
                </span>
            </div>
        `;
    }
    clausesList.innerHTML = html;

    // ✅ Update explanation if available
    if (result.explanation) {
        explanationText.textContent = result.explanation;
        explanationText.style.color = 'rgba(255,255,255,0.7)';
    } else if (clauses.length > 0) {
        // ✅ Generate a simple explanation if none provided
        const clauseNames = clauses.map(c => c.type).join(', ');
        explanationText.textContent = `Detected clauses: ${clauseNames}`;
        explanationText.style.color = 'rgba(255,255,255,0.7)';
    }
}

// --- Utility Functions ---

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function getCurrentTab() {
    return new Promise((resolve) => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            resolve(tabs[0] || null);
        });
    });
}

async function getPolicyText(tabId) {
    return new Promise((resolve) => {
        chrome.scripting.executeScript(
            {
                target: { tabId },
                func: () => {
                    const selectors = [
                        '[id*="privacy" i]', '[id*="terms" i]', '[id*="policy" i]',
                        '[class*="privacy" i]', '[class*="terms" i]'
                    ];
                    let text = '';
                    for (const selector of selectors) {
                        const els = document.querySelectorAll(selector);
                        for (const el of els) {
                            const t = el.textContent?.trim();
                            if (t && t.length > 100) text += t + '\n';
                        }
                    }
                    if (!text && /\/privacy|\/terms|\/legal|\/policy/.test(window.location.href)) {
                        text = document.body?.textContent?.trim() || '';
                    }
                    return text.substring(0, 8000);
                }
            },
            (results) => {
                if (results && results[0] && results[0].result) {
                    resolve(results[0].result);
                } else {
                    resolve(null);
                }
            }
        );
    });
}

// --- Button Handlers ---

allowBtn.addEventListener('click', async () => {
    if (!currentDomain) return;
    try {
        const storage = await chrome.storage.local.get(['allowed_sites']);
        const allowedSites = storage.allowed_sites || [];
        if (!allowedSites.includes(currentDomain)) {
            allowedSites.push(currentDomain);
            await chrome.storage.local.set({ allowed_sites: allowedSites });
        }
        window.close();
    } catch (error) {
        console.error('Error allowing site:', error);
    }
});

blockBtn.addEventListener('click', async () => {
    if (!currentDomain) return;
    try {
        const storage = await chrome.storage.local.get(['blocked_sites']);
        const blockedSites = storage.blocked_sites || [];
        if (!blockedSites.includes(currentDomain)) {
            blockedSites.push(currentDomain);
            await chrome.storage.local.set({ blocked_sites: blockedSites });
        }
        const tab = await getCurrentTab();
        if (tab && tab.id) {
            await chrome.tabs.remove(tab.id);
        }
        window.close();
    } catch (error) {
        console.error('Error blocking site:', error);
    }
});