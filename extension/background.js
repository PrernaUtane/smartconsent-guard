// background.js
// Service worker for SmartConsent Guard

const BACKEND_URL = 'http://127.0.0.1:8000';

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return;
    if (details.url.startsWith('chrome://')) return;
    if (details.url.startsWith('chrome-extension://')) return;
    if (details.url.startsWith('http://localhost')) return;
    if (details.url.startsWith('http://127.0.0.1')) return;

    const tabId = details.tabId;
    const url = details.url;

    try {
        const domain = new URL(url).hostname;
        const storage = await chrome.storage.local.get(['allowed_sites', 'blocked_sites']);
        const allowedSites = storage.allowed_sites || [];
        const blockedSites = storage.blocked_sites || [];

        if (blockedSites.includes(domain)) {
            await chrome.tabs.remove(tabId);
            return;
        }
        if (allowedSites.includes(domain)) return;

        const response = await fetch(`${BACKEND_URL}/check-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        if (!response.ok) return;
        const data = await response.json();

        if (data.is_phishing) {
            await chrome.storage.session.set({ [`blockedUrl_${tabId}`]: url });
            const warningUrl = chrome.runtime.getURL('warning/warning.html') +
                `?url=${encodeURIComponent(url)}` +
                `&score=${data.risk_score}` +
                `&reasons=${encodeURIComponent(data.reasons.join('||'))}`;
            await chrome.tabs.update(tabId, { url: warningUrl });
        }
    } catch (error) {
        console.error(error);
    }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'allowDomain') {
        handleAllowDomain(message.domain, sender.tab?.id);
        sendResponse({ success: true });
    } else if (message.action === 'blockDomain') {
        handleBlockDomain(message.domain, sender.tab?.id);
        sendResponse({ success: true });
    } else if (message.action === 'getBlockedUrl') {
        const tabId = sender.tab?.id;
        if (tabId) {
            chrome.storage.session.get([`blockedUrl_${tabId}`], (result) => {
                sendResponse({ url: result[`blockedUrl_${tabId}`] || null });
            });
            return true;
        }
    }
    return true;
});

async function handleAllowDomain(domain, tabId) {
    try {
        const storage = await chrome.storage.local.get(['allowed_sites']);
        const allowedSites = storage.allowed_sites || [];
        if (!allowedSites.includes(domain)) {
            allowedSites.push(domain);
            await chrome.storage.local.set({ allowed_sites: allowedSites });
        }
        if (tabId) {
            const result = await chrome.storage.session.get([`blockedUrl_${tabId}`]);
            const originalUrl = result[`blockedUrl_${tabId}`];
            if (originalUrl) await chrome.tabs.update(tabId, { url: originalUrl });
        }
    } catch (error) { console.error(error); }
}

async function handleBlockDomain(domain, tabId) {
    try {
        const storage = await chrome.storage.local.get(['blocked_sites']);
        const blockedSites = storage.blocked_sites || [];
        if (!blockedSites.includes(domain)) {
            blockedSites.push(domain);
            await chrome.storage.local.set({ blocked_sites: blockedSites });
        }
        if (tabId) await chrome.tabs.remove(tabId);
    } catch (error) { console.error(error); }
}