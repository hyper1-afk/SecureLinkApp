// Parse URL parameters
const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get('url') || 'Unknown URL';
const riskScore = parseInt(params.get('score') || '0', 10);
let threats = [];

try {
    threats = JSON.parse(params.get('threats') || '[]');
} catch (e) {
    threats = [];
}

// Adapt page appearance based on risk score
const container = document.querySelector('.warning-container');
const icon = document.querySelector('.warning-icon');
const heading = document.querySelector('h1');
const subtitle = document.querySelector('.subtitle');
const proceedBtn = document.getElementById('btn-proceed');

if (riskScore < 30) {
    icon.textContent = '✅';
    heading.textContent = 'Link Looks Safe';
    heading.className = 'heading-safe';
    subtitle.textContent = 'SecureLink found no threats with this link';
    proceedBtn.classList.add('hidden');
    if (threats.length === 0) threats = ['No threats detected'];
} else if (riskScore < 50) {
    icon.textContent = '⚠️';
    heading.textContent = 'Suspicious Link';
    heading.className = 'heading-warning';
    subtitle.textContent = 'Proceed with caution — this link has some risk indicators';
    if (threats.length === 0) threats = ['Some risk indicators detected'];
} else {
    if (threats.length === 0) threats = ['This site has been flagged as potentially dangerous'];
}

// Display blocked URL
document.getElementById('blocked-url').textContent = blockedUrl;

// Display risk score
document.getElementById('risk-score').textContent = `Risk Score: ${riskScore}/100`;

// Display threats/findings
const threatsList = document.getElementById('threats-list');
const threatsHeading = document.querySelector('.threats h3');
if (riskScore < 30) {
    threatsHeading.textContent = '✅ Scan Results:';
} else if (riskScore < 50) {
    threatsHeading.textContent = '⚠️ Risk Indicators:';
}

threats.forEach(threat => {
    const item = document.createElement('div');
    item.className = 'threat-item';
    const iconEl = document.createElement('span');
    iconEl.textContent = riskScore < 30 ? '✅' : '⚠️';
    const text = document.createTextNode(' ' + threat);
    item.appendChild(iconEl);
    item.appendChild(text);
    threatsList.appendChild(item);
});

// Go back to safety — open new tab instead of history.back() to avoid looping back to the blocked site
document.getElementById('btn-back').addEventListener('click', function() {
    chrome.tabs.create({ url: 'chrome://newtab' });
    window.close();
});

// Proceed anyway — chrome extension pages block confirm(), so use inline confirmation
let proceedConfirmPending = false;
document.getElementById('btn-proceed').addEventListener('click', function() {
    if (!proceedConfirmPending) {
        proceedConfirmPending = true;
        this.textContent = 'Click again to confirm — this site may be dangerous';
        this.style.background = '#dc2626';
        return;
    }
    // Store bypass for this URL temporarily
    chrome.storage.local.set({
        [`bypass_${blockedUrl}`]: Date.now()
    }, () => {
        window.location.href = blockedUrl;
    });
});
