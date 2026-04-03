const params     = new URLSearchParams(window.location.search);
const blockedUrl = params.get('url') || 'Unknown URL';
const riskScore  = parseInt(params.get('score') || '0', 10);
let threats = [];
try { threats = JSON.parse(params.get('threats') || '[]'); } catch (e) { threats = []; }

// Elements
const badge      = document.getElementById('risk-badge');
const flagIcon   = document.getElementById('flag-icon');
const heading    = document.getElementById('heading');
const proceedBtn = document.getElementById('btn-proceed');
const scoreLine  = document.getElementById('score-line');

// Adapt appearance to risk level
if (riskScore < 30) {
    flagIcon.textContent  = '✅';
    heading.textContent   = 'This site looks safe';
    heading.className     = 'safe';
    badge.textContent     = 'SAFE';
    badge.className       = 'risk-badge safe';
    proceedBtn.classList.add('hidden');
    if (threats.length === 0) threats = ['No threats detected'];
} else if (riskScore < 50) {
    flagIcon.textContent = '⚠️';
    heading.textContent  = 'This site has some risk indicators';
    heading.className    = 'warn';
    badge.textContent    = 'MEDIUM RISK';
    badge.className      = 'risk-badge medium';
    if (threats.length === 0) threats = ['Some risk indicators detected'];
} else {
    flagIcon.textContent = '🛑';
    if (threats.length === 0) threats = ['This site has been flagged as potentially dangerous'];
}

// URL and score
document.getElementById('blocked-url').textContent = blockedUrl;
scoreLine.textContent = `Risk score: ${riskScore} / 100`;

// Threat list
const list = document.getElementById('threats-list');
threats.forEach(threat => {
    const item = document.createElement('div');
    item.className = 'threat-item';
    const icon = document.createElement('span');
    icon.className   = 'icon';
    icon.textContent = riskScore < 30 ? '✓' : '·';
    const text = document.createTextNode(threat);
    item.appendChild(icon);
    item.appendChild(text);
    list.appendChild(item);
});

// Go back
document.getElementById('btn-back').addEventListener('click', () => {
    chrome.tabs.create({ url: 'chrome://newtab' });
    window.close();
});

// Proceed anyway — two-click confirm
let confirmPending = false;
proceedBtn.addEventListener('click', function () {
    if (!confirmPending) {
        confirmPending = true;
        this.textContent = 'Click again to confirm';
        this.classList.add('confirming');
        return;
    }
    chrome.storage.local.set({ [`bypass_${blockedUrl}`]: Date.now() }, () => {
        chrome.tabs.getCurrent(tab => {
            chrome.tabs.update(tab.id, { url: blockedUrl });
        });
    });
});
