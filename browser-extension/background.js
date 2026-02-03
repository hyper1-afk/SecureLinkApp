// SecureLink Browser Extension - Background Service Worker

const API_BASE = 'http://localhost:5000'; // Change to your production URL

// Install context menu
chrome.runtime.onInstalled.addListener(() => {
    // Context menu for links
    chrome.contextMenus.create({
        id: 'verifyLink',
        title: 'Check link with SecureLink',
        contexts: ['link']
    });

    // Context menu for selection
    chrome.contextMenus.create({
        id: 'verifySelection',
        title: 'Check selected URL with SecureLink',
        contexts: ['selection']
    });

    // Context menu for page
    chrome.contextMenus.create({
        id: 'verifyPage',
        title: 'Check this page with SecureLink',
        contexts: ['page']
    });

    console.log('SecureLink extension installed');
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
    let urlToCheck = null;

    if (info.menuItemId === 'verifyLink') {
        urlToCheck = info.linkUrl;
    } else if (info.menuItemId === 'verifySelection') {
        urlToCheck = info.selectionText.trim();
    } else if (info.menuItemId === 'verifyPage') {
        urlToCheck = info.pageUrl;
    }

    if (urlToCheck) {
        verifyUrl(urlToCheck, tab);
    }
});

// Verify URL and show result
async function verifyUrl(url, tab) {
    // Validate URL
    try {
        new URL(url);
    } catch (e) {
        showNotification('Invalid URL', 'The selected text is not a valid URL');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();
        
        // Show notification with result
        const riskScore = data.risk_score || 0;
        if (riskScore < 30) {
            showNotification(
                '✅ Safe Link',
                `Risk Score: ${riskScore}/100\n${truncate(url, 50)}`
            );
        } else if (riskScore < 70) {
            showNotification(
                '⚠️ Suspicious Link',
                `Risk Score: ${riskScore}/100\n${truncate(url, 50)}\nProceed with caution.`
            );
        } else {
            showNotification(
                '🚨 Dangerous Link!',
                `Risk Score: ${riskScore}/100\n${truncate(url, 50)}\nDo not visit this link!`
            );
        }

        // Send result to content script to show inline
        if (tab && tab.id) {
            chrome.tabs.sendMessage(tab.id, {
                action: 'showResult',
                url: url,
                data: data
            });
        }

    } catch (error) {
        console.error('Error verifying URL:', error);
        showNotification('Error', 'Could not verify the link. Please try again.');
    }
}

// Handle messages from popup and content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'showNotification') {
        showNotification(message.title, message.message);
    } else if (message.action === 'verifyUrl') {
        verifyUrl(message.url, sender.tab);
    }
});

// Show notification
function showNotification(title, message) {
    chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: title,
        message: message,
        priority: 2
    });
}

// Utility: Truncate string
function truncate(str, maxLength) {
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength - 3) + '...';
}

// Listen for tab updates to check URLs
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only check when navigation completes
    if (changeInfo.status === 'complete' && tab.url) {
        // Get user settings
        chrome.storage.sync.get(['autoCheck', 'blockedDomains'], async (settings) => {
            if (!settings.autoCheck) return;

            // Check if URL matches blocked domains
            try {
                const url = new URL(tab.url);
                const blockedDomains = settings.blockedDomains || [];
                
                if (blockedDomains.includes(url.hostname)) {
                    // Show warning page
                    chrome.tabs.update(tabId, {
                        url: chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(tab.url)}`)
                    });
                }
            } catch (e) {
                // Invalid URL, ignore
            }
        });
    }
});
