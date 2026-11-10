// SecureLink Browser Extension - Content Script

const MAX_PAGE_LINK_SCANS = 25;

// Listen for messages from popup and background
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'scanLinks') {
        scanPageLinks();
    } else if (message.action === 'showResult') {
        showInlineResult(message.url, message.data);
    } else if (message.action === 'showScanToast') {
        showToast(message.message, message.type || 'info');
    }
});

// Scan all links on the page
async function scanPageLinks() {
    const links = document.querySelectorAll('a[href]');
    const uniqueUrls = new Set();

    // Collect unique external links
    links.forEach(link => {
        const href = link.href;
        if (href && href.startsWith('http') && !href.startsWith(window.location.origin)) {
            uniqueUrls.add(href);
        }
    });

    if (uniqueUrls.size === 0) {
        showToast('No external links found on this page');
        return;
    }

    const urlsToScan = [...uniqueUrls].slice(0, MAX_PAGE_LINK_SCANS);
    const skippedCount = uniqueUrls.size - urlsToScan.length;
    showToast(skippedCount > 0
        ? `Scanning ${urlsToScan.length} links. ${skippedCount} more were left unscanned.`
        : `Scanning ${urlsToScan.length} links...`);

    // Check each link
    let dangerous = 0;
    let suspicious = 0;
    let completed = 0;
    let failed = 0;
    let limited = false;

    for (const url of urlsToScan) {
        try {
            const data = await requestBackgroundScan(url);

            if (data.limitReached) {
                limited = true;
                break;
            }
            completed += 1;
            
            // Mark links on the page
            markLinks(url, data.risk_score);

            if (data.risk_score >= 70) dangerous++;
            else if (data.risk_score >= 30) suspicious++;

        } catch (_) {
            // Do not write the URL or other page data to the console.
            failed += 1;
        }
    }

    // Show summary
    const unverified = skippedCount + failed + (limited ? urlsToScan.length - completed - failed : 0);
    if (unverified > 0) {
        showToast(`Found ${dangerous} high-risk and ${suspicious} suspicious links; ${unverified} were not checked.`, 'warning');
    } else if (dangerous > 0 || suspicious > 0) {
        showToast(`⚠️ Found ${dangerous} dangerous and ${suspicious} suspicious links!`, 'warning');
    } else {
        showToast(`No risk indicators found in ${completed} checks. This is not a safety guarantee.`, 'success');
    }
}

function requestBackgroundScan(url) {
    return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({ action: 'checkUrl', url }, (response) => {
            if (chrome.runtime.lastError) {
                reject(new Error('SecureLink could not reach its scanner.'));
                return;
            }
            if (!response || response.error) {
                reject(new Error(response?.message || 'SecureLink could not review this link.'));
                return;
            }
            resolve({
                risk_score: Number(response.riskScore) || 0,
                threats_detected: Array.isArray(response.threats) ? response.threats : [],
                warnings: Array.isArray(response.warnings) ? response.warnings : [],
                limitReached: response.limitReached === true,
                message: typeof response.message === 'string' ? response.message : '',
            });
        });
    });
}

// Mark links on the page with indicators
function markLinks(url, riskScore) {
    const links = [...document.querySelectorAll('a[href]')].filter(link => link.href === url);
    
    links.forEach(link => {
        // Remove existing indicator if any
        const existing = link.querySelector('.securelink-indicator');
        if (existing) existing.remove();

        // Create indicator
        const indicator = document.createElement('span');
        indicator.className = 'securelink-indicator';
        
        if (riskScore < 30) {
            indicator.innerHTML = '✅';
            indicator.title = `SecureLink: No risk indicator found (Risk: ${riskScore}/100). This is not a safety guarantee.`;
            indicator.classList.add('securelink-safe');
        } else if (riskScore < 70) {
            indicator.innerHTML = '⚠️';
            indicator.title = `SecureLink: Suspicious (Risk: ${riskScore}/100)`;
            indicator.classList.add('securelink-warning');
        } else {
            indicator.innerHTML = '🚨';
            indicator.title = `SecureLink: Dangerous (Risk: ${riskScore}/100)`;
            indicator.classList.add('securelink-danger');
        }

        link.style.position = 'relative';
        link.appendChild(indicator);
    });
}

// Show inline result near hovered link
function showInlineResult(url, data) {
    // Find the link element
    const links = [...document.querySelectorAll('a[href]')].filter(link => link.href === url);
    if (links.length === 0) return;

    const link = links[0];
    const rect = link.getBoundingClientRect();

    // Create result popup using DOM (no innerHTML — prevents XSS)
    const popup = document.createElement('div');
    popup.className = 'securelink-popup';

    const header = document.createElement('div');
    header.className = 'securelink-popup-header';
    const iconEl = document.createElement('span');
    iconEl.className = 'securelink-popup-icon';
    iconEl.textContent = data.risk_score < 30 ? '✅' : data.risk_score < 70 ? '⚠️' : '🚨';
    const titleEl = document.createElement('span');
    titleEl.className = 'securelink-popup-title';
    titleEl.textContent = data.risk_score < 30 ? 'No indicator flagged' : data.risk_score < 70 ? 'Suspicious' : 'High risk';
    header.appendChild(iconEl);
    header.appendChild(titleEl);

    const scoreEl = document.createElement('div');
    scoreEl.className = 'securelink-popup-score';
    scoreEl.textContent = 'Risk Score: ' + data.risk_score + '/100';

    const closeEl = document.createElement('div');
    closeEl.className = 'securelink-popup-close';
    closeEl.textContent = 'Click anywhere to close';

    popup.appendChild(header);
    popup.appendChild(scoreEl);

    if (data.threat_types && data.threat_types.length > 0) {
        const threatsEl = document.createElement('div');
        threatsEl.className = 'securelink-popup-threats';
        data.threat_types.forEach(t => {
            const tag = document.createElement('span');
            tag.className = 'securelink-threat-tag';
            tag.textContent = t;
            threatsEl.appendChild(tag);
        });
        popup.appendChild(threatsEl);
    }

    popup.appendChild(closeEl);

    // Position popup using CSS classes instead of inline styles
    popup.style.setProperty('top', (rect.bottom + window.scrollY + 10) + 'px');
    popup.style.setProperty('left', (rect.left + window.scrollX) + 'px');

    document.body.appendChild(popup);

    // Close on click
    setTimeout(() => {
        document.addEventListener('click', function closePopup() {
            popup.remove();
            document.removeEventListener('click', closePopup);
        }, { once: true });
    }, 100);
}

// Show toast notification
function showToast(message, type = 'info') {
    // Remove existing toast
    const existing = document.querySelector('.securelink-toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = `securelink-toast securelink-toast-${type}`;
    toast.textContent = message;
    
    document.body.appendChild(toast);

    // Animate in
    setTimeout(() => toast.classList.add('securelink-toast-visible'), 10);

    // Remove after 3 seconds
    setTimeout(() => {
        toast.classList.remove('securelink-toast-visible');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Add hover listener for link checking
document.addEventListener('mouseover', async (e) => {
    const link = e.target.closest('a[href]');
    if (!link || !link.href.startsWith('http')) return;

    // Check if already processed
    if (link.dataset.securelinkChecked) return;

    // Get user settings
    chrome.storage.sync.get(['hoverCheck'], async (settings) => {
        if (!settings.hoverCheck) return;

        link.dataset.securelinkChecked = 'pending';

        try {
            const data = await requestBackgroundScan(link.href);

            if (data.limitReached) {
                link.dataset.securelinkChecked = 'unavailable';
                return;
            }
            
            link.dataset.securelinkChecked = 'done';
            markLinks(link.href, data.risk_score);

        } catch (error) {
            link.dataset.securelinkChecked = '';
        }
    });
});

console.log('SecureLink content script loaded');
