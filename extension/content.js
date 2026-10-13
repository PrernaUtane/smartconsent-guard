// content.js
// SmartConsent Guard — Terms & Conditions Extractor & Auto-Decline Engine

const POLICY_KEYWORDS = [
    'privacy', 'policy', 'terms', 'conditions', 'tos', 'legal',
    'consent', 'data', 'cookie', 'gdpr', 'ccpa', 'rights',
    'agreement', 'accept', 'notice', 'disclosure'
];

const SECTION_SELECTORS = [
    '[id*="terms" i]', '[class*="terms" i]',
    '[id*="privacy" i]', '[class*="privacy" i]',
    '[id*="policy" i]', '[class*="policy" i]',
    '[id*="legal" i]', '[class*="legal" i]',
    '[id*="tos" i]', '[class*="tos" i]',
    '[id*="consent" i]', '[class*="consent" i]'
];

const HEADING_RE = /privacy|terms|conditions|legal|tos|cookie|consent|gdpr|ccpa/i;

const DELAYS = [1000, 3000, 6000];
let scanned = false;
let cookieBannerHandled = false;

// ─────────────────────────────────────────────────────────────────────────────
// 1. AUTO-DECLINE COOKIE BANNERS
// ─────────────────────────────────────────────────────────────────────────────

const REJECT_BUTTON_SELECTORS = [
    '#onetrust-reject-all-handler',
    '#CybotCookiebotDialogBodyButtonDecline',
    '#didomi-notice-disagree-button',
    '.qc-cmp2-footer .qc-cmp2-buttons-desktop button:first-child',
    '[data-testid*="reject" i]',
    '[aria-label*="reject all" i]',
    '[aria-label*="decline" i]',
    'button[id*="reject" i]',
    'button[class*="reject" i]',
    'button[id*="decline" i]',
    'button[class*="decline" i]',
    '.cm__btn--reject',
    '.klaro .cn-decline'
];

async function autoDeclineCookieBanner() {
    if (cookieBannerHandled) return;

    // Check if auto-decline is enabled in storage (default: true)
    try {
        const settings = await chrome.storage.local.get(['auto_decline_cookies']);
        if (settings.auto_decline_cookies === false) return;
    } catch (e) {
        // Continue if storage query fails
    }

    // Check specific known selector buttons
    for (const selector of REJECT_BUTTON_SELECTORS) {
        const btn = document.querySelector(selector);
        if (btn && btn.offsetParent !== null && !btn.disabled) {
            console.log('🛡️ [SmartConsent] Auto-declining cookies via selector:', selector);
            btn.click();
            cookieBannerHandled = true;
            notifyDeclineSuccess('Non-essential cookies auto-declined.');
            recordDeclineEvent();
            return;
        }
    }

    // Generic heuristic search across visible buttons in banner/dialog containers
    const bannerContainers = document.querySelectorAll(
        '[id*="cookie" i], [class*="cookie" i], [id*="consent" i], [class*="consent" i], [role="dialog"], [aria-modal="true"]'
    );

    for (const container of bannerContainers) {
        if (container.offsetParent === null) continue; // skip hidden
        const buttons = container.querySelectorAll('button, a[role="button"], input[type="button"]');
        for (const btn of buttons) {
            const label = (btn.textContent || btn.value || '').trim().toLowerCase();
            if (
                label.includes('reject all') ||
                label.includes('decline all') ||
                label.includes('reject non-essential') ||
                label.includes('only necessary') ||
                label.includes('necessary only') ||
                label.includes('refuse all') ||
                (label === 'decline' || label === 'reject' || label === 'deny')
            ) {
                console.log('🛡️ [SmartConsent] Auto-declining cookies via text match:', label);
                btn.click();
                cookieBannerHandled = true;
                notifyDeclineSuccess(`Auto-declined cookies (${label})`);
                recordDeclineEvent();
                return;
            }
        }
    }
}

function notifyDeclineSuccess(text) {
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed;
        bottom: 24px;
        right: 24px;
        background: rgba(15, 23, 42, 0.95);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.4);
        border-radius: 10px;
        padding: 10px 16px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 13px;
        font-weight: 500;
        box-shadow: 0 10px 25px rgba(0,0,0,0.4);
        z-index: 2147483647;
        display: flex;
        align-items: center;
        gap: 8px;
        transition: all 0.3s ease;
    `;
    toast.innerHTML = `<span>🛡️</span><span><strong>SmartConsent:</strong> ${text}</span>`;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

function recordDeclineEvent() {
    chrome.runtime.sendMessage({
        type: 'COOKIE_BANNER_DECLINED',
        url: window.location.href,
        hostname: window.location.hostname,
        timestamp: Date.now()
    }).catch(() => {});
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. IN-PAGE SNEAKY CLAUSE HIGHLIGHTER
// ─────────────────────────────────────────────────────────────────────────────

function highlightSneakyClauses() {
    const riskyTerms = [
        { term: /binding\s+arbitration|waive\s+right\s+to\s+sue/gi, label: 'Forced Arbitration', color: '#f43f5e' },
        { term: /auto-renew|recurring\s+charge|automatically\s+renew/gi, label: 'Auto-Renewal Trap', color: '#f59e0b' },
        { term: /sell\s+(?:your\s+)?personal|data\s+brokers/gi, label: 'Data Resale', color: '#f43f5e' },
        { term: /disclaim\s+all\s+warranties|as[\s-]is\s+and\s+as[\s-]available/gi, label: 'Total Liability Disclaimer', color: '#8b5cf6' }
    ];

    let count = 0;
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const nodesToReplace = [];

    while (walker.nextNode()) {
        const node = walker.currentNode;
        if (!node.nodeValue || node.parentElement.tagName === 'SCRIPT' || node.parentElement.tagName === 'STYLE') continue;
        for (const item of riskyTerms) {
            if (item.term.test(node.nodeValue)) {
                nodesToReplace.push({ node, item });
                break;
            }
        }
    }

    for (const { node, item } of nodesToReplace) {
        if (!node.parentElement) continue;
        const span = document.createElement('span');
        span.style.backgroundColor = `${item.color}33`;
        span.style.borderBottom = `2px solid ${item.color}`;
        span.style.borderRadius = '3px';
        span.style.padding = '1px 3px';
        span.title = `SmartConsent Guard: ${item.label}`;
        span.textContent = node.nodeValue;
        node.parentElement.replaceChild(span, node);
        count++;
    }

    notifyDeclineSuccess(`Highlighted ${count} risky clause passage(s) on this page.`);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. TERMS & POLICY EXTRACTION
// ─────────────────────────────────────────────────────────────────────────────

function extractPolicyText() {
    if (scanned) return;
    scanned = true;

    // Check dedicated sections
    let text = '';
    for (const selector of SECTION_SELECTORS) {
        const elements = document.querySelectorAll(selector);
        for (const el of elements) {
            const elText = el.textContent?.trim();
            if (elText && elText.length > 100) {
                text += elText + '\n\n';
            }
        }
    }

    // Check headings
    if (text.length < 200) {
        const headings = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
        for (const heading of headings) {
            if (HEADING_RE.test(heading.textContent)) {
                let parent = heading.parentElement;
                let parentText = parent?.textContent?.trim() || '';
                if (parentText && parentText.length > 100) {
                    text += parentText + '\n\n';
                }
            }
        }
    }

    // URL fallback or whole body fallback
    if (text.length < 100 && document.body) {
        const bodyText = document.body.innerText?.trim() || '';
        if (bodyText.length > 150) {
            text = bodyText;
        }
    }

    if (text.length > 80) {
        const cleanText = text.replace(/\s+/g, ' ').trim().substring(0, 15000);
        chrome.runtime.sendMessage({
            type: 'POLICY_ANALYSIS_RESULT',
            data: { 
                text: cleanText, 
                url: window.location.href 
            }
        }).catch(() => {});
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. SCHEDULE TASKS & LISTENERS
// ─────────────────────────────────────────────────────────────────────────────

let attempt = 0;
function scheduleScan() {
    if (attempt < DELAYS.length) {
        setTimeout(() => {
            autoDeclineCookieBanner();
            extractPolicyText();
            attempt++;
            scheduleScan();
        }, DELAYS[attempt]);
    }
}
scheduleScan();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'getPolicyText') {
        scanned = false;
        extractPolicyText();
        sendResponse({ success: true });
        return true;
    }
    if (message.action === 'HIGHLIGHT_CLAUSES') {
        highlightSneakyClauses();
        sendResponse({ success: true });
        return true;
    }
    if (message.action === 'TRIGGER_AUTO_DECLINE') {
        cookieBannerHandled = false;
        autoDeclineCookieBanner();
        sendResponse({ success: true });
        return true;
    }
    return true;
});