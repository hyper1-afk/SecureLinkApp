// SecureLink Browser Extension - Popup Script

const API_BASE = 'http://localhost:5000'; // Change to your production URL

// DOM Elements
const urlInput = document.getElementById('urlInput');
const verifyBtn = document.getElementById('verifyBtn');
const loading = document.getElementById('loading');
const result = document.getElementById('result');
const resultIcon = document.getElementById('resultIcon');
const resultTitle = document.getElementById('resultTitle');
const resultSubtitle = document.getElementById('resultSubtitle');
const riskFill = document.getElementById('riskFill');
const riskScore = document.getElementById('riskScore');
const threatTags = document.getElementById('threatTags');
const aiExplanation = document.getElementById('aiExplanation');
const recentList = document.getElementById('recentList');

// Load recent checks on popup open
document.addEventListener('DOMContentLoaded', async () => {
    loadRecentChecks();
    
    // Auto-paste clipboard content if it's a URL
    try {
        const text = await navigator.clipboard.readText();
        if (isValidUrl(text)) {
            urlInput.value = text;
        }
    } catch (e) {
        // Clipboard access denied
    }
});

// Verify button click
verifyBtn.addEventListener('click', () => {
    const url = urlInput.value.trim();
    if (url) {
        verifyUrl(url);
    }
});

// Enter key to verify
urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        const url = urlInput.value.trim();
        if (url) {
            verifyUrl(url);
        }
    }
});

// Check current page
document.getElementById('checkCurrentPage').addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
        urlInput.value = tab.url;
        verifyUrl(tab.url);
    }
});

// Scan page links
document.getElementById('scanPageLinks').addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.id) {
        chrome.tabs.sendMessage(tab.id, { action: 'scanLinks' });
        window.close();
    }
});

// Report link
document.getElementById('reportLink').addEventListener('click', () => {
    const url = urlInput.value.trim();
    if (url) {
        chrome.tabs.create({ url: `${API_BASE}/community?report=${encodeURIComponent(url)}` });
    } else {
        chrome.tabs.create({ url: `${API_BASE}/community` });
    }
});

// Breach checker
document.getElementById('breachChecker').addEventListener('click', () => {
    chrome.tabs.create({ url: `${API_BASE}/breach-checker` });
});

// Settings
document.getElementById('settingsBtn').addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
});

// Verify URL function
async function verifyUrl(url) {
    if (!isValidUrl(url)) {
        showError('Please enter a valid URL');
        return;
    }

    // Show loading
    loading.style.display = 'block';
    result.style.display = 'none';
    verifyBtn.disabled = true;

    try {
        const response = await fetch(`${API_BASE}/api/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();
        
        // Save to recent checks
        saveRecentCheck(url, data);
        
        // Display result
        displayResult(url, data);

    } catch (error) {
        console.error('Error verifying URL:', error);
        showError('Unable to connect to SecureLink. Please check your internet connection.');
    } finally {
        loading.style.display = 'none';
        verifyBtn.disabled = false;
    }
}

// Display verification result
function displayResult(url, data) {
    result.style.display = 'block';
    
    const riskScoreValue = data.risk_score || 0;
    const isSafe = riskScoreValue < 30;
    const isWarning = riskScoreValue >= 30 && riskScoreValue < 70;
    const isDanger = riskScoreValue >= 70;

    // Update classes
    result.className = 'result';
    if (isSafe) {
        result.classList.add('safe');
        resultIcon.textContent = '✓';
        resultTitle.textContent = 'Safe';
        resultSubtitle.textContent = 'This link appears to be safe';
    } else if (isWarning) {
        result.classList.add('warning');
        resultIcon.textContent = '⚠';
        resultTitle.textContent = 'Caution';
        resultSubtitle.textContent = 'This link has some risk indicators';
    } else {
        result.classList.add('danger');
        resultIcon.textContent = '✕';
        resultTitle.textContent = 'Dangerous';
        resultSubtitle.textContent = 'This link is potentially harmful';
    }

    // Update risk meter
    riskFill.style.width = `${riskScoreValue}%`;
    riskScore.textContent = `Risk Score: ${riskScoreValue}/100`;

    // Update threat tags
    threatTags.innerHTML = '';
    if (data.threat_types && data.threat_types.length > 0) {
        data.threat_types.forEach(threat => {
            const tag = document.createElement('span');
            tag.className = 'threat-tag';
            tag.textContent = threat;
            threatTags.appendChild(tag);
        });
    }

    // Show AI explanation if available
    if (data.ai_explanation) {
        aiExplanation.style.display = 'block';
        aiExplanation.textContent = data.ai_explanation;
    } else {
        aiExplanation.style.display = 'none';
    }

    // Send notification for dangerous links
    if (isDanger) {
        chrome.runtime.sendMessage({
            action: 'showNotification',
            title: '⚠️ Dangerous Link Detected',
            message: `Risk Score: ${riskScoreValue}/100 - ${url}`
        });
    }
}

// Show error message
function showError(message) {
    result.style.display = 'block';
    result.className = 'result danger';
    resultIcon.textContent = '!';
    resultTitle.textContent = 'Error';
    resultSubtitle.textContent = message;
    riskFill.style.width = '0%';
    riskScore.textContent = '';
    threatTags.innerHTML = '';
    aiExplanation.style.display = 'none';
}

// Save recent check to storage
function saveRecentCheck(url, data) {
    chrome.storage.local.get(['recentChecks'], (result) => {
        let checks = result.recentChecks || [];
        
        // Add new check at the beginning
        checks.unshift({
            url: url,
            riskScore: data.risk_score || 0,
            timestamp: Date.now()
        });

        // Keep only last 10 checks
        checks = checks.slice(0, 10);

        chrome.storage.local.set({ recentChecks: checks });
        loadRecentChecks();
    });
}

// Load recent checks from storage
function loadRecentChecks() {
    chrome.storage.local.get(['recentChecks'], (result) => {
        const checks = result.recentChecks || [];
        
        if (checks.length === 0) {
            recentList.innerHTML = '<p style="font-size: 12px; opacity: 0.5; text-align: center;">No recent checks</p>';
            return;
        }

        recentList.innerHTML = checks.map(check => {
            const statusClass = check.riskScore < 30 ? 'safe' : check.riskScore < 70 ? 'warning' : 'danger';
            const domain = new URL(check.url).hostname;
            
            return `
                <div class="recent-item" data-url="${escapeHtml(check.url)}">
                    <div class="recent-status ${statusClass}"></div>
                    <div class="recent-url">${escapeHtml(domain)}</div>
                    <div class="recent-score">${check.riskScore}</div>
                </div>
            `;
        }).join('');

        // Add click handlers
        recentList.querySelectorAll('.recent-item').forEach(item => {
            item.addEventListener('click', () => {
                urlInput.value = item.dataset.url;
                verifyUrl(item.dataset.url);
            });
        });
    });
}

// Utility: Check if string is valid URL
function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

// Utility: Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
