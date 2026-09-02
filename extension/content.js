// content.js
// SmartConsent Guard - Terms & Conditions Extractor

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

function extractPolicyText() {
    if (scanned) return;
    scanned = true;

    let text = '';

    // Strategy 1: Find dedicated sections
    for (const selector of SECTION_SELECTORS) {
        const elements = document.querySelectorAll(selector);
        for (const el of elements) {
            const elText = el.textContent?.trim();
            if (elText && elText.length > 100) {
                text += elText + '\n\n';
            }
        }
    }

    // Strategy 2: Find headings with legal terms
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

    // Strategy 3: URL fallback
    if (text.length < 100) {
        const url = window.location.href.toLowerCase();
        if (/\/privacy|\/terms|\/legal|\/policy|\/tos|\/cookie|\/agreement/.test(url)) {
            const bodyText = document.body?.textContent?.trim() || '';
            if (bodyText.length > 500) {
                text = bodyText;
            }
        }
    }

    // Validate and send
    if (text.length > 100 && looksLegal(text)) {
        text = text.replace(/\s+/g, ' ').trim();
        // Send to background script
        chrome.runtime.sendMessage({
            type: 'POLICY_ANALYSIS_RESULT',
            data: { text: text, url: window.location.href }
        });
    }
}

function looksLegal(text) {
    let keywordCount = 0;
    const lowerText = text.toLowerCase();
    for (const keyword of POLICY_KEYWORDS) {
        if (lowerText.includes(keyword)) {
            keywordCount++;
        }
    }
    return keywordCount >= 2;
}

// Start scanning with delays
let attempt = 0;
function scheduleScan() {
    if (attempt < DELAYS.length) {
        setTimeout(() => {
            extractPolicyText();
            attempt++;
            scheduleScan();
        }, DELAYS[attempt]);
    }
}
scheduleScan();

// Listen for popup requests
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'getPolicyText') {
        scanned = false;
        extractPolicyText();
        sendResponse({ success: true });
    }
    return true;
});