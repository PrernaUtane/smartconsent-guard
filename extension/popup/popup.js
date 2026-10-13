// popup.js — SmartConsent Guard Modular Extension UI Controller
const BACKEND_URL = 'http://127.0.0.1:8000';
const CIRCUMFERENCE = 326.726; // 2 * PI * 52

// --- State Variables ---
let currentUrl = '';
let currentDomain = '';
let currentTabId = null;
let currentPolicyText = '';
let currentRiskScore = 0;
let currentClauses = [];
let currentDarkPatterns = [];
let activeCookies = [];

// --- DOM Elements ---
const siteUrl = document.getElementById('siteUrl');
const riskBadge = document.getElementById('riskBadge');
const riskScore = document.getElementById('riskScore');
const riskLevel = document.getElementById('riskLevel');
const riskRing = document.getElementById('riskRing');
const explanationText = document.getElementById('explanationText');
const clausesList = document.getElementById('clausesList');
const clauseCount = document.getElementById('clauseCount');
const serverStatusDot = document.getElementById('serverStatusDot');

// Nav Badges
const cookieNavCount = document.getElementById('cookieNavCount');
const trapNavCount = document.getElementById('trapNavCount');

// Action Buttons
const allowBtn = document.getElementById('allowBtn');
const blockBtn = document.getElementById('blockBtn');
const highlightOnPageBtn = document.getElementById('highlightOnPageBtn');

// ============================================================================
// 1. INITIALIZATION & TAB ROUTING
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
    initTabNavigation();
    initChatHandlers();
    initCookieHandlers();
    initBreachHandlers();
    initReportHandlers();

    try {
        const tab = await getCurrentTab();
        if (!tab || !tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('about:') || tab.url === '') {
            showInternalPageMessage();
            return;
        }

        currentTabId = tab.id;
        currentUrl = tab.url;
        try {
            currentDomain = new URL(tab.url).hostname;
        } catch {
            currentDomain = tab.url;
        }
        siteUrl.textContent = currentDomain;

        // Check backend health indicator
        checkBackendHealth();

        // 1. Phishing analysis
        const phishingResult = await checkUrl(currentUrl);
        updatePhishingUI(phishingResult);

        // 2. Extract policy & run analysis
        currentPolicyText = await getPolicyText(currentTabId) || '';
        if (currentPolicyText && currentPolicyText.length > 50) {
            try {
                const policyResult = await analyzePolicyEnhanced(currentPolicyText);
                updatePolicyUI(policyResult);
            } catch (err) {
                console.warn('Enhanced policy analysis failed, using fallback:', err);
                const policyResult = await analyzePolicy(currentPolicyText);
                updatePolicyUI(policyResult);
            }
        } else {
            clauseCount.textContent = '0 detected';
            clausesList.innerHTML = `
                <div class="empty-state">
                    ℹ️ No privacy policy or legal text detected on this page.<br>
                    <span style="font-size: 10px; color: rgba(255,255,255,0.4);">
                        SmartConsent Guard heuristic phishing protection is active.
                    </span>
                </div>
            `;
        }

        // 3. Populate modular tabs
        loadCookiesForDomain(currentUrl, currentDomain);
        loadDarkPatterns(currentPolicyText, currentUrl);
        loadBreachIntelligence(currentDomain);
        updateSummaryTab();
        loadHistoryLog();

    } catch (error) {
        console.error('Popup initialization error:', error);
        serverStatusDot.className = 'status-dot';
        serverStatusDot.style.background = '#f43f5e';
        explanationText.textContent = 'Backend server offline. Launch start_server.bat to activate AI features.';
    }
});

function initTabNavigation() {
    const tabs = document.querySelectorAll('.nav-tab');
    tabs.forEach(tabBtn => {
        tabBtn.addEventListener('click', () => {
            const targetId = tabBtn.getAttribute('data-tab');
            switchTab(targetId);
        });
    });
}

function switchTab(targetId) {
    document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));

    const activeBtn = document.querySelector(`.nav-tab[data-tab="${targetId}"]`);
    const activePanel = document.getElementById(targetId);

    if (activeBtn) activeBtn.classList.add('active');
    if (activePanel) activePanel.classList.add('active');
}

async function checkBackendHealth() {
    try {
        const res = await fetch(`${BACKEND_URL}/health`, { signal: AbortSignal.timeout(3000) });
        if (res.ok) {
            serverStatusDot.className = 'status-dot online';
            serverStatusDot.title = 'SmartConsent Guard Backend: Online';
        } else {
            throw new Error('Health check error');
        }
    } catch {
        serverStatusDot.className = 'status-dot';
        serverStatusDot.style.background = '#f59e0b';
        serverStatusDot.title = 'Backend unreachable';
    }
}

function showInternalPageMessage() {
    siteUrl.textContent = '🔒 Internal Browser Page';
    riskScore.textContent = '0';
    riskLevel.textContent = 'INTERNAL';
    riskBadge.textContent = 'SECURE';
    riskBadge.className = 'risk-pill badge-low';
    explanationText.textContent = 'SmartConsent Guard is active for public web domains.';
    riskRing.style.strokeDashoffset = CIRCUMFERENCE;
    clausesList.innerHTML = '<div class="empty-state">No external contracts on internal browser pages.</div>';
}

// ============================================================================
// 2. API CALLS
// ============================================================================

async function checkUrl(url) {
    const res = await fetch(`${BACKEND_URL}/check-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
    });
    if (!res.ok) throw new Error('Check URL failed');
    return res.json();
}

async function analyzePolicyEnhanced(text) {
    const res = await fetch(`${BACKEND_URL}/analyze-policy-enhanced`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text })
    });
    if (!res.ok) throw new Error('Enhanced policy analysis failed');
    return res.json();
}

async function analyzePolicy(text) {
    const res = await fetch(`${BACKEND_URL}/analyze-policy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text })
    });
    if (!res.ok) throw new Error('Policy analysis failed');
    return res.json();
}

async function fetchDarkPatterns(text, url) {
    const res = await fetch(`${BACKEND_URL}/detect-dark-patterns`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, url })
    });
    if (!res.ok) return { patterns: [], count: 0, overall_threat: 'LOW' };
    return res.json();
}

async function fetchBreachInfo(domain, email = '') {
    const res = await fetch(`${BACKEND_URL}/check-breach`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, email })
    });
    if (!res.ok) return null;
    return res.json();
}

async function askPolicyAssistant(question, policyText) {
    const res = await fetch(`${BACKEND_URL}/ask-policy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question, policy_text: policyText })
    });
    if (!res.ok) throw new Error('Policy Q&A failed');
    return res.json();
}

// ============================================================================
// 3. OVERVIEW UI UPDATES
// ============================================================================

function updatePhishingUI(result) {
    currentRiskScore = Math.max(currentRiskScore, result.risk_score || 0);
    applyScoreGauge(currentRiskScore);

    if (result.is_phishing) {
        riskLevel.textContent = 'PHISHING THREAT';
        riskLevel.className = 'meta-verdict danger';
        explanationText.textContent = '⚠️ Phishing patterns detected! High risk of credential theft or spoofing.';
        document.getElementById('phishingTag').textContent = '⚠️ Suspicious Host';
        document.getElementById('phishingTag').style.color = '#f43f5e';
    } else {
        const reasonMsg = result.reasons?.length ? result.reasons.join(', ') : 'Standard web domain';
        explanationText.textContent = `Heuristic verification: ${reasonMsg}.`;
    }
}

function updatePolicyUI(result) {
    currentClauses = result.clauses || [];
    clauseCount.textContent = `${currentClauses.length} detected`;

    if (result.ri_score !== undefined && result.ri_score !== null) {
        currentRiskScore = Math.max(currentRiskScore, result.ri_score);
        applyScoreGauge(currentRiskScore);
    }

    if (result.explanation) {
        explanationText.textContent = result.explanation;
    }

    const methodTag = document.getElementById('analysisMethodTag');
    if (methodTag) {
        methodTag.textContent = result.method === 'nli' ? '🤖 Deep NLI AI' : '📝 Lexical Rules';
    }

    if (currentClauses.length === 0) {
        clausesList.innerHTML = '<div class="empty-state">No significant risk clauses detected in policy.</div>';
        return;
    }

    let html = '';
    for (const c of currentClauses) {
        const type = c.type || 'Clause';
        const conf = typeof c.confidence === 'number' ? Math.round(c.confidence * 100) : 95;
        const severity = c.severity || (currentRiskScore > 60 ? 'HIGH' : 'MEDIUM');

        let color = '#f59e0b';
        if (severity === 'CRITICAL' || severity === 'HIGH') color = '#f43f5e';
        else if (severity === 'LOW') color = '#10b981';

        html += `
            <div class="clause-item" style="border-left: 3px solid ${color};">
                <span class="clause-name">${escapeHtml(type)}</span>
                <span class="clause-confidence" style="color: ${color};">${conf}% Match</span>
            </div>
        `;
    }
    clausesList.innerHTML = html;
}

function applyScoreGauge(score) {
    riskScore.textContent = score;
    const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
    riskRing.style.strokeDashoffset = offset;

    let color, levelText, badgeClass;
    if (score > 60) {
        color = '#f43f5e';
        levelText = 'HIGH RISK';
        badgeClass = 'risk-pill badge-high';
    } else if (score > 30) {
        color = '#f59e0b';
        levelText = 'MODERATE';
        badgeClass = 'risk-pill badge-medium';
    } else {
        color = '#10b981';
        levelText = 'SAFE SITE';
        badgeClass = 'risk-pill badge-low';
    }

    riskRing.style.stroke = color;
    riskLevel.textContent = levelText;
    riskLevel.style.color = color;
    riskBadge.textContent = levelText;
    riskBadge.className = badgeClass;
}

// ============================================================================
// 4. SUMMARY TAB CONTROLLER
// ============================================================================

function updateSummaryTab() {
    const gradeElem = document.getElementById('privacyGrade');
    const gradeLabel = document.getElementById('privacyGradeLabel');
    const dataSaleElem = document.getElementById('dataSaleStatus');
    const arbElem = document.getElementById('arbitrationStatus');
    const billingElem = document.getElementById('billingTrapStatus');

    let grade = 'A';
    let gradeSub = 'Strong Protection';
    if (currentRiskScore > 70) {
        grade = 'F';
        gradeSub = 'High Risk';
    } else if (currentRiskScore > 45) {
        grade = 'C';
        gradeSub = 'Fair Protection';
    } else if (currentRiskScore > 25) {
        grade = 'B';
        gradeSub = 'Good Standard';
    }

    gradeElem.textContent = grade;
    gradeLabel.textContent = gradeSub;
    if (grade === 'A') gradeElem.style.color = '#10b981';
    else if (grade === 'B') gradeElem.style.color = '#06b6d4';
    else if (grade === 'C') gradeElem.style.color = '#f59e0b';
    else gradeElem.style.color = '#f43f5e';

    // Check specific clause flags
    const hasDataSale = currentClauses.some(c => /selling|brokers|advertisers/i.test(c.type));
    const hasArb = currentClauses.some(c => /arbitration|class action/i.test(c.type));
    const hasBilling = currentClauses.some(c => /subscription|auto-renew|recurring/i.test(c.type));

    if (hasDataSale) {
        dataSaleElem.textContent = '⚠️ Data Shared';
        dataSaleElem.className = 'score-status danger';
        document.getElementById('sumDataOwnership').textContent = 'Your information may be shared with or monetized via third-party advertisers.';
    } else {
        dataSaleElem.textContent = '✅ No Selling';
        dataSaleElem.className = 'score-status safe';
    }

    if (hasArb) {
        arbElem.textContent = '⚠️ Mandatory Arb';
        arbElem.className = 'score-status danger';
        document.getElementById('sumDisputes').textContent = 'Mandatory binding arbitration is required. Class action lawsuits are waived.';
    } else {
        arbElem.textContent = '✅ Court Intact';
        arbElem.className = 'score-status safe';
    }

    if (hasBilling) {
        billingElem.textContent = '⚠️ Auto-Renews';
        billingElem.className = 'score-status warn';
    } else {
        billingElem.textContent = '✅ No Trap';
        billingElem.className = 'score-status safe';
    }

    // Copy Summary Button
    const copyBtn = document.getElementById('copySummaryBtn');
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const summary = `SmartConsent Guard Summary for ${currentDomain}:\n- Privacy Grade: ${grade} (${gradeSub})\n- Risk Index: ${currentRiskScore}/100\n- Data Sharing: ${dataSaleElem.textContent}\n- Dispute Terms: ${arbElem.textContent}\n- Billing Terms: ${billingElem.textContent}`;
            navigator.clipboard.writeText(summary);
            copyBtn.textContent = '✅ Copied!';
            setTimeout(() => { copyBtn.textContent = '📋 Copy'; }, 2000);
        });
    }
}

// ============================================================================
// 5. COOKIE & TRACKER TAB CONTROLLER
// ============================================================================

function initCookieHandlers() {
    const toggleAutoDecline = document.getElementById('toggleAutoDecline');
    if (toggleAutoDecline) {
        chrome.storage.local.get(['auto_decline_cookies'], (res) => {
            toggleAutoDecline.checked = res.auto_decline_cookies !== false;
        });

        toggleAutoDecline.addEventListener('change', (e) => {
            chrome.storage.local.set({ auto_decline_cookies: e.target.checked });
            if (e.target.checked && currentTabId) {
                chrome.tabs.sendMessage(currentTabId, { action: 'TRIGGER_AUTO_DECLINE' }).catch(() => {});
            }
        });
    }

    const clearBtn = document.getElementById('clearCookiesBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', async () => {
            if (!activeCookies.length) return;
            let removedCount = 0;
            for (const c of activeCookies) {
                // Clear 3rd party or tracking cookies
                try {
                    const protocol = c.secure ? 'https:' : 'http:';
                    const cookieUrl = `${protocol}//${c.domain.startsWith('.') ? c.domain.substring(1) : c.domain}${c.path}`;
                    await chrome.cookies.remove({ url: cookieUrl, name: c.name });
                    removedCount++;
                } catch (e) {}
            }
            clearBtn.textContent = `✅ Removed ${removedCount}`;
            setTimeout(() => {
                clearBtn.textContent = '🗑️ Clear Tracking';
                loadCookiesForDomain(currentUrl, currentDomain);
            }, 1800);
        });
    }
}

function loadCookiesForDomain(url, domain) {
    if (!chrome.cookies) {
        document.getElementById('cookiesList').innerHTML = '<div class="empty-state">Cookie inspection permissions not active.</div>';
        return;
    }

    chrome.cookies.getAll({ domain }, (cookies) => {
        activeCookies = cookies || [];
        const total = activeCookies.length;
        cookieNavCount.textContent = total;
        document.getElementById('totalCookiesCount').textContent = total;

        const cleanDomain = domain.replace(/^www\./, '');
        let firstParty = 0;
        let thirdParty = 0;

        const listContainer = document.getElementById('cookiesList');
        if (total === 0) {
            listContainer.innerHTML = '<div class="empty-state">No persistent tracking cookies on this page.</div>';
            document.getElementById('firstPartyCookiesCount').textContent = 0;
            document.getElementById('thirdPartyCookiesCount').textContent = 0;
            return;
        }

        let html = '';
        for (const c of activeCookies) {
            const isFirst = c.domain.includes(cleanDomain);
            if (isFirst) firstParty++;
            else thirdParty++;

            const badgeColor = isFirst ? '#10b981' : '#f59e0b';
            const badgeLabel = isFirst ? '1st-Party' : 'Tracker/3rd';

            html += `
                <div class="cookie-row-item">
                    <div>
                        <span class="cookie-name">${escapeHtml(c.name)}</span>
                        <div class="cookie-domain-badge">${escapeHtml(c.domain)}</div>
                    </div>
                    <span style="font-size: 9px; font-weight: 700; color: ${badgeColor};">${badgeLabel}</span>
                </div>
            `;
        }

        document.getElementById('firstPartyCookiesCount').textContent = firstParty;
        document.getElementById('thirdPartyCookiesCount').textContent = thirdParty;
        listContainer.innerHTML = html;
    });
}

// ============================================================================
// 6. DARK PATTERNS & TRAPS TAB
// ============================================================================

async function loadDarkPatterns(text, url) {
    try {
        const result = await fetchDarkPatterns(text, url);
        currentDarkPatterns = result.patterns || [];
        const count = currentDarkPatterns.length;

        trapNavCount.textContent = count;
        trapNavCount.style.display = count > 0 ? 'inline-block' : 'none';
        document.getElementById('trapsCountBadge').textContent = `${count} TRAP${count === 1 ? '' : 'S'}`;

        const container = document.getElementById('darkPatternsList');
        if (count === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <span>✨</span>
                    <p>No aggressive dark patterns or sneaky clauses found in this platform's agreement.</p>
                </div>
            `;
            return;
        }

        let html = '';
        for (const p of currentDarkPatterns) {
            const sev = (p.severity || 'MEDIUM').toLowerCase();
            const quote = p.excerpts?.length ? `"${escapeHtml(p.excerpts[0])}"` : 'Pattern matched standard sneaky contract language.';

            html += `
                <div class="trap-card ${sev}">
                    <div class="trap-card-header">
                        <span class="trap-title">${p.icon || '⚠️'} ${escapeHtml(p.name)}</span>
                        <span class="trap-badge ${sev}">${escapeHtml(p.severity)}</span>
                    </div>
                    <p class="trap-warning">${escapeHtml(p.trap_warning)}</p>
                    <div class="trap-quote">${quote}</div>
                    <p class="trap-advice">💡 ${escapeHtml(p.recommendation)}</p>
                </div>
            `;
        }
        container.innerHTML = html;

    } catch (err) {
        console.warn('Dark patterns error:', err);
    }

    const highlightBtn = document.getElementById('btnHighlightTraps');
    if (highlightBtn) {
        highlightBtn.addEventListener('click', triggerInPageHighlight);
    }
}

function triggerInPageHighlight() {
    if (!currentTabId) return;
    chrome.tabs.sendMessage(currentTabId, { action: 'HIGHLIGHT_CLAUSES' }, (res) => {
        const btn = document.getElementById('btnHighlightTraps');
        if (btn) {
            btn.innerHTML = '<span>✅</span> Highlighted on Page';
            setTimeout(() => { btn.innerHTML = '<span>🔎</span> Highlight Traps on Page'; }, 2500);
        }
    });
}

// ============================================================================
// 7. AI POLICY CHAT & Q&A TAB
// ============================================================================

function initChatHandlers() {
    const input = document.getElementById('chatInput');
    const sendBtn = document.getElementById('chatSendBtn');
    const chips = document.querySelectorAll('.chip-btn');

    sendBtn.addEventListener('click', () => submitChat());
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') submitChat();
    });

    chips.forEach(chip => {
        chip.addEventListener('click', () => {
            const query = chip.getAttribute('data-query');
            if (query) {
                input.value = query;
                submitChat();
            }
        });
    });
}

async function submitChat() {
    const input = document.getElementById('chatInput');
    const q = input.value.trim();
    if (!q) return;

    input.value = '';
    appendChatMessage('user', q);

    const thinkingId = appendChatMessage('bot', 'Analyzing terms and contractual conditions...');

    try {
        const res = await askPolicyAssistant(q, currentPolicyText);
        updateChatBubble(thinkingId, res.answer);
    } catch (err) {
        updateChatBubble(thinkingId, 'Error connecting to AI Policy Assistant. Ensure backend server is running.');
    }
}

function appendChatMessage(role, text) {
    const container = document.getElementById('chatMessages');
    const id = `msg-${Date.now()}-${Math.random()}`;
    const div = document.createElement('div');
    div.className = `chat-msg ${role}-msg`;
    div.id = id;

    const avatar = role === 'bot' ? '🤖' : '👤';
    div.innerHTML = `
        <div class="msg-avatar">${avatar}</div>
        <div class="msg-bubble">${formatMarkdown(text)}</div>
    `;

    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
    return id;
}

function updateChatBubble(msgId, newText) {
    const el = document.getElementById(msgId);
    if (el) {
        const bubble = el.querySelector('.msg-bubble');
        if (bubble) bubble.innerHTML = formatMarkdown(newText);
    }
    const container = document.getElementById('chatMessages');
    if (container) container.scrollTop = container.scrollHeight;
}

function formatMarkdown(text) {
    if (!text) return '';
    return text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/> "(.*?)"/g, '<blockquote>$1</blockquote>')
        .replace(/\n\n/g, '<br><br>')
        .replace(/\n/g, '<br>');
}

// ============================================================================
// 8. BREACH INTELLIGENCE TAB
// ============================================================================

async function loadBreachIntelligence(domain) {
    try {
        const data = await fetchBreachInfo(domain);
        if (!data) return;

        document.getElementById('breachDomainName').textContent = data.domain;
        const scoreBadge = document.getElementById('breachScoreBadge');
        scoreBadge.textContent = `Security Score: ${data.security_score}/100`;

        if (data.security_score >= 80) scoreBadge.style.color = '#10b981';
        else if (data.security_score >= 50) scoreBadge.style.color = '#f59e0b';
        else scoreBadge.style.color = '#f43f5e';

        document.getElementById('breachStatusMsg').textContent = data.status_message;

        if (data.is_breached) {
            document.getElementById('breachIcon').textContent = '⚠️';
        }
    } catch (e) {
        console.warn('Breach intel error:', e);
    }
}

function initBreachHandlers() {
    const emailBtn = document.getElementById('emailCheckBtn');
    const emailInput = document.getElementById('emailCheckInput');
    const resultBox = document.getElementById('emailResultBox');
    const resultText = document.getElementById('emailResultText');

    if (emailBtn && emailInput) {
        emailBtn.addEventListener('click', async () => {
            const email = emailInput.value.trim();
            if (!email || !email.includes('@')) {
                alert('Please enter a valid email address.');
                return;
            }

            emailBtn.textContent = '...';
            try {
                const res = await fetchBreachInfo(currentDomain, email);
                resultBox.classList.remove('hidden');
                if (res && res.email_advice) {
                    resultText.textContent = res.email_advice;
                    resultText.style.color = res.email_breached ? '#f43f5e' : '#10b981';
                } else {
                    resultText.textContent = `Audit completed: No active compromised passwords recorded for ${email}.`;
                    resultText.style.color = '#10b981';
                }
            } catch {
                resultBox.classList.remove('hidden');
                resultText.textContent = 'Unable to verify email breach database at this time.';
            } finally {
                emailBtn.textContent = 'Check';
            }
        });
    }
}

// ============================================================================
// 9. HISTORY & PDF EXPORT TAB
// ============================================================================

function initReportHandlers() {
    const exportBtn = document.getElementById('btnGeneratePdf');
    if (exportBtn) {
        exportBtn.addEventListener('click', generatePdfReport);
    }

    const clearHistoryBtn = document.getElementById('btnClearHistory');
    if (clearHistoryBtn) {
        clearHistoryBtn.addEventListener('click', () => {
            chrome.runtime.sendMessage({ type: 'CLEAR_HISTORY' }, () => {
                loadHistoryLog();
            });
        });
    }

    if (highlightOnPageBtn) {
        highlightOnPageBtn.addEventListener('click', triggerInPageHighlight);
    }
}

function loadHistoryLog() {
    chrome.storage.local.get(['scan_history'], (res) => {
        const history = res.scan_history || [];
        const container = document.getElementById('historyList');

        if (!history.length) {
            container.innerHTML = '<div class="empty-state">No scan history recorded yet.</div>';
            return;
        }

        let html = '';
        for (const item of history.slice(0, 15)) {
            const dateStr = new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            const badgeColor = item.riskScore > 60 ? '#f43f5e' : item.riskScore > 30 ? '#f59e0b' : '#10b981';

            html += `
                <div class="history-item">
                    <div>
                        <span class="history-domain">${escapeHtml(item.hostname)}</span>
                        <div class="history-time">${dateStr}</div>
                    </div>
                    <span style="font-size: 10px; font-weight: 700; color: ${badgeColor};">
                        Score ${item.riskScore} (${item.level})
                    </span>
                </div>
            `;
        }
        container.innerHTML = html;
    });
}

function generatePdfReport() {
    const reportHtml = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>SmartConsent Guard Security Report — ${escapeHtml(currentDomain)}</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 40px; color: #1e293b; line-height: 1.5; }
                .header { border-bottom: 2px solid #4f46e5; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }
                .title { font-size: 24px; font-weight: 800; color: #0f172a; }
                .subtitle { font-size: 14px; color: #64748b; }
                .score-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 24px; display: flex; gap: 24px; }
                .score-num { font-size: 36px; font-weight: 900; color: ${currentRiskScore > 60 ? '#f43f5e' : currentRiskScore > 30 ? '#f59e0b' : '#10b981'}; }
                .section { margin-bottom: 24px; }
                h2 { font-size: 16px; font-weight: 700; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-bottom: 12px; }
                table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }
                th, td { text-align: left; padding: 8px; border-bottom: 1px solid #e2e8f0; }
                th { background: #f1f5f9; font-weight: 600; }
                .badge { padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 700; }
                .footer { margin-top: 40px; border-top: 1px solid #e2e8f0; padding-top: 12px; font-size: 11px; color: #94a3b8; text-align: center; }
            </style>
        </head>
        <body>
            <div class="header">
                <div>
                    <div class="title">🛡️ SmartConsent Guard Audit</div>
                    <div class="subtitle">Platform Contractual Semantics & Security Report</div>
                </div>
                <div style="text-align: right; font-size: 12px; color: #64748b;">
                    Date: ${new Date().toLocaleDateString()}<br>
                    Target: <strong>${escapeHtml(currentDomain)}</strong>
                </div>
            </div>

            <div class="score-box">
                <div>
                    <div style="font-size: 12px; font-weight: 600; color: #64748b;">RISK INDEX</div>
                    <div class="score-num">${currentRiskScore}/100</div>
                </div>
                <div style="display: flex; flex-direction: column; justify-content: center;">
                    <strong>Evaluation: ${riskLevel.textContent}</strong>
                    <p style="font-size: 13px; margin: 0; color: #475569;">${escapeHtml(explanationText.textContent)}</p>
                </div>
            </div>

            <div class="section">
                <h2>1. Detected Contractual Clauses (${currentClauses.length})</h2>
                ${currentClauses.length ? `
                    <table>
                        <thead><tr><th>Clause Type</th><th>Match Confidence</th><th>Category</th></tr></thead>
                        <tbody>
                            ${currentClauses.map(c => `<tr><td>${escapeHtml(c.type)}</td><td>${Math.round((c.confidence || 1) * 100)}%</td><td>${escapeHtml(c.severity || 'STANDARD')}</td></tr>`).join('')}
                        </tbody>
                    </table>
                ` : '<p style="font-size: 13px; color: #64748b;">No high-risk clauses detected.</p>'}
            </div>

            <div class="section">
                <h2>2. Dark Patterns & Contractual Traps (${currentDarkPatterns.length})</h2>
                ${currentDarkPatterns.length ? `
                    <table>
                        <thead><tr><th>Trap</th><th>Severity</th><th>Impact</th></tr></thead>
                        <tbody>
                            ${currentDarkPatterns.map(p => `<tr><td><strong>${escapeHtml(p.name)}</strong></td><td>${escapeHtml(p.severity)}</td><td>${escapeHtml(p.trap_warning)}</td></tr>`).join('')}
                        </tbody>
                    </table>
                ` : '<p style="font-size: 13px; color: #64748b;">No aggressive contract traps flagged.</p>'}
            </div>

            <div class="section">
                <h2>3. Active Browser Cookies & Trackers</h2>
                <p style="font-size: 13px;">Total Cookies Observed: <strong>${activeCookies.length}</strong></p>
            </div>

            <div class="footer">
                Generated automatically by SmartConsent Guard Security System • Automated Contractual Semantics for Online Platforms
            </div>

            <script>window.onload = () => { window.print(); };</script>
        </body>
        </html>
    `;

    const blob = new Blob([reportHtml], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    chrome.tabs.create({ url });
}

// ============================================================================
// 10. ALLOW & BLOCK SITE BUTTONS
// ============================================================================

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
    } catch (e) {
        console.error(e);
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
        if (currentTabId) {
            chrome.tabs.remove(currentTabId).catch(() => {});
        }
        window.close();
    } catch (e) {
        console.error(e);
    }
});

// ============================================================================
// 11. HELPERS
// ============================================================================

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
                    for (const s of selectors) {
                        const els = document.querySelectorAll(s);
                        for (const el of els) {
                            const t = el.textContent?.trim();
                            if (t && t.length > 80) text += t + '\n';
                        }
                    }
                    if (!text && document.body) {
                        text = document.body.innerText?.trim() || '';
                    }
                    return text.substring(0, 10000);
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

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}