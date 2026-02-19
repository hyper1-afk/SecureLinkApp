// SecureLink Browser Extension - Content Script

const API_BASE = 'http://localhost:5000'; // Change to your production URL

// Listen for messages from popup and background
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'scanLinks') {
        scanPageLinks();
    } else if (message.action === 'showResult') {
        showInlineResult(message.url, message.data);
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

    showToast(`Scanning ${uniqueUrls.size} links...`);

    // Check each link
    let dangerous = 0;
    let suspicious = 0;

    for (const url of uniqueUrls) {
        try {
            const response = await fetch(`${API_BASE}/api/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            const data = await response.json();
            
            // Mark links on the page
            markLinks(url, data.risk_score);

            if (data.risk_score >= 70) dangerous++;
            else if (data.risk_score >= 30) suspicious++;

        } catch (error) {
            console.error('Error checking link:', url, error);
        }
    }

    // Show summary
    if (dangerous > 0 || suspicious > 0) {
        showToast(`⚠️ Found ${dangerous} dangerous and ${suspicious} suspicious links!`, 'warning');
    } else {
        showToast('✅ All links appear safe!', 'success');
    }
}

// Mark links on the page with indicators
function markLinks(url, riskScore) {
    const links = document.querySelectorAll(`a[href="${url}"]`);
    
    links.forEach(link => {
        // Remove existing indicator if any
        const existing = link.querySelector('.securelink-indicator');
        if (existing) existing.remove();

        // Create indicator
        const indicator = document.createElement('span');
        indicator.className = 'securelink-indicator';
        
        if (riskScore < 30) {
            indicator.innerHTML = '✅';
            indicator.title = `SecureLink: Safe (Risk: ${riskScore}/100)`;
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
    const links = document.querySelectorAll(`a[href="${url}"]`);
    if (links.length === 0) return;

    const link = links[0];
    const rect = link.getBoundingClientRect();

    // Create result popup
    const popup = document.createElement('div');
    popup.className = 'securelink-popup';
    popup.innerHTML = `
        <div class="securelink-popup-header">
            <span class="securelink-popup-icon">${data.risk_score < 30 ? '✅' : data.risk_score < 70 ? '⚠️' : '🚨'}</span>
            <span class="securelink-popup-title">${data.risk_score < 30 ? 'Safe' : data.risk_score < 70 ? 'Suspicious' : 'Dangerous'}</span>
        </div>
        <div class="securelink-popup-score">Risk Score: ${data.risk_score}/100</div>
        ${data.threat_types && data.threat_types.length > 0 ? `
            <div class="securelink-popup-threats">
                ${data.threat_types.map(t => `<span class="securelink-threat-tag">${t}</span>`).join('')}
            </div>
        ` : ''}
        <div class="securelink-popup-close">Click anywhere to close</div>
    `;

    // Position popup
    popup.style.top = `${rect.bottom + window.scrollY + 10}px`;
    popup.style.left = `${rect.left + window.scrollX}px`;

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
            const response = await fetch(`${API_BASE}/api/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: link.href })
            });
            const data = await response.json();
            
            link.dataset.securelinkChecked = 'done';
            markLinks(link.href, data.risk_score);

        } catch (error) {
            link.dataset.securelinkChecked = '';
        }
    });
});

console.log('SecureLink content script loaded');
