// warning.js
const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get('url') || '';
const score = parseInt(params.get('score')) || 0;
const reasonsRaw = params.get('reasons') || '';
const reasons = reasonsRaw ? reasonsRaw.split('||') : [];

document.getElementById('scoreDisplay').textContent = score;
document.getElementById('urlDisplay').textContent = blockedUrl;
const reasonsList = document.getElementById('reasonsList');
if (reasons.length > 0) {
    reasonsList.innerHTML = reasons.map(r => `<div class="reason-item">• ${escapeHtml(r)}</div>`).join('');
} else {
    reasonsList.innerHTML = '<div class="reason-item">• Suspicious activity detected</div>';
}

document.getElementById('goBackBtn').addEventListener('click', async () => {
    try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tabs.length > 0) {
            chrome.tabs.goBack(tabs[0].id, () => {
                if (chrome.runtime.lastError) chrome.tabs.remove(tabs[0].id);
            });
        }
    } catch (e) { console.error(e); }
});

document.getElementById('enterAnywayBtn').addEventListener('click', async () => {
    try {
        const domain = new URL(blockedUrl).hostname;
        const storage = await chrome.storage.local.get(['allowed_sites']);
        const allowedSites = storage.allowed_sites || [];
        if (!allowedSites.includes(domain)) { allowedSites.push(domain); await chrome.storage.local.set({ allowed_sites: allowedSites }); }
        const tab = await getCurrentTab();
        if (tab && tab.id) await chrome.tabs.update(tab.id, { url: blockedUrl });
    } catch (e) { window.location.href = blockedUrl; }
});

function escapeHtml(text) { const d=document.createElement('div'); d.textContent=text; return d.innerHTML; }
function getCurrentTab() { return new Promise(r => chrome.tabs.query({ active:true, currentWindow:true }, tabs => r(tabs[0]))); }