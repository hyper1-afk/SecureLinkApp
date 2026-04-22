const params     = new URLSearchParams(window.location.search);
const blockedUrl = params.get('url') || 'Unknown URL';
const riskScore  = parseInt(params.get('score') || '0', 10);
let threats = [];
try { threats = JSON.parse(params.get('threats') || '[]'); } catch (e) { threats = []; }

// SVG icons
const SVG_DANGER = `<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
const SVG_WARN   = `<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
const SVG_SAFE   = `<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`;

// Elements
const card       = document.getElementById('card');
const accent     = document.getElementById('card-accent');
const badge      = document.getElementById('risk-badge');
const flagIcon   = document.getElementById('flag-icon');
const heading    = document.getElementById('heading');
const subtitle   = document.getElementById('subtitle');
const proceedBtn = document.getElementById('btn-proceed');
const scoreLine  = document.getElementById('score-line');

// Adapt appearance to risk level
if (riskScore < 30) {
    flagIcon.innerHTML  = SVG_SAFE;
    flagIcon.className  = 'flag-icon safe-icon';
    heading.textContent = 'This site looks safe';
    heading.className   = 'safe';
    subtitle.textContent = 'No significant threats were detected.';
    badge.textContent   = 'SAFE';
    badge.className     = 'risk-badge safe';
    accent.className    = 'card-accent safe';
    card.classList.add('safe-card');
    proceedBtn.classList.add('hidden');
    if (threats.length === 0) threats = ['No threats detected'];
} else if (riskScore < 50) {
    flagIcon.innerHTML  = SVG_WARN;
    flagIcon.className  = 'flag-icon medium';
    heading.textContent = 'This site has risk indicators';
    heading.className   = 'warn';
    subtitle.textContent = 'Proceed with caution and avoid entering personal information.';
    badge.textContent   = 'MEDIUM RISK';
    badge.className     = 'risk-badge medium';
    accent.className    = 'card-accent medium';
    card.classList.add('medium-card');
    if (threats.length === 0) threats = ['Some risk indicators detected'];
} else {
    flagIcon.innerHTML  = SVG_DANGER;
    if (threats.length === 0) threats = ['This site has been flagged as potentially dangerous'];
}

// URL and score
document.getElementById('blocked-url').textContent = blockedUrl;
scoreLine.textContent = `Risk score: ${riskScore} / 100`;

// Threat list
const list = document.getElementById('threats-list');
threats.forEach(threat => {
    const item = document.createElement('div');
    item.className = riskScore < 30 ? 'threat-item safe-item' : 'threat-item';
    const icon = document.createElement('span');
    icon.className = 'icon';
    const text = document.createTextNode(threat);
    item.appendChild(icon);
    item.appendChild(text);
    list.appendChild(item);
});

// Go back
document.getElementById('btn-back').addEventListener('click', () => {
    chrome.tabs.getCurrent(tab => {
        chrome.tabs.update(tab.id, { url: 'chrome://newtab' });
    });
});

// Proceed anyway
proceedBtn.addEventListener('click', () => {
    chrome.storage.local.set({ [`bypass_${blockedUrl}`]: Date.now() }, () => {
        chrome.tabs.getCurrent(tab => {
            chrome.tabs.update(tab.id, { url: blockedUrl });
        });
    });
});
