// Parse URL parameters
const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get('url') || 'Unknown URL';
const riskScore = params.get('score') || '?';
let threats = [];

try {
    threats = JSON.parse(params.get('threats') || '[]');
} catch (e) {
    threats = ['Suspicious activity detected'];
}

// Display blocked URL
document.getElementById('blocked-url').textContent = blockedUrl;

// Display risk score
document.getElementById('risk-score').textContent = `Risk Score: ${riskScore}/100`;

// Display threats
const threatsList = document.getElementById('threats-list');
if (threats.length === 0) {
    threats = ['This site has been flagged as potentially dangerous'];
}
threats.forEach(threat => {
    const item = document.createElement('div');
    item.className = 'threat-item';
    const icon = document.createElement('span');
    icon.textContent = '⚠️';
    const text = document.createTextNode(' ' + threat);
    item.appendChild(icon);
    item.appendChild(text);
    threatsList.appendChild(item);
});

// Go back to safety
document.getElementById('btn-back').addEventListener('click', function() {
    if (window.history.length > 1) {
        window.history.back();
    } else {
        window.location.href = 'https://google.com';
    }
});

// Proceed anyway (at user's risk)
document.getElementById('btn-proceed').addEventListener('click', function() {
    if (confirm('Are you sure you want to proceed? This site may be dangerous and could harm your computer or steal your information.')) {
        // Store bypass for this URL temporarily
        chrome.storage.local.set({ 
            [`bypass_${blockedUrl}`]: Date.now() 
        }, () => {
            window.location.href = blockedUrl;
        });
    }
});
