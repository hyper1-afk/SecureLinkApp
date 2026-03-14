// SecureLink Browser Extension - Background Service Worker
// Automatically scans URLs when you navigate and warns about malicious sites

const API_BASE = 'https://securelinkapp.com'; // Production API

// Track checked URLs to avoid re-checking
const checkedUrls = new Map();
const CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours - saves scans on revisited sites
const pendingChecks = new Set(); // URLs currently being checked

// User session
let userSession = null;

// Load saved session on startup
chrome.storage.local.get(['userSession'], (result) => {
    if (result.userSession) {
        userSession = result.userSession;
    }
});

// Skip these URL patterns (internal browser pages, local addresses)
const SKIP_PATTERNS = [
    /^chrome/,
    /^about:/,
    /^edge:/,
    /^file:/,
    /^moz-extension:/,
    /^chrome-extension:/,
    /localhost/,
    /127\.0\.0\.1/,
    /192\.168\./,
    /^10\./,
];

// Known safe domains that don't need checking (saves scans)
const SAFE_DOMAINS = [
    // Search engines
    'google.com', 'www.google.com', 'google.co.uk', 'google.ca', 'google.com.au',
    'bing.com', 'www.bing.com',
    'duckduckgo.com', 'www.duckduckgo.com',
    'yahoo.com', 'www.yahoo.com', 'search.yahoo.com',
    
    // Social media
    'youtube.com', 'www.youtube.com', 'youtu.be',
    'facebook.com', 'www.facebook.com', 'm.facebook.com',
    'instagram.com', 'www.instagram.com',
    'twitter.com', 'www.twitter.com', 'x.com', 'www.x.com',
    'linkedin.com', 'www.linkedin.com',
    'reddit.com', 'www.reddit.com', 'old.reddit.com',
    'tiktok.com', 'www.tiktok.com',
    'pinterest.com', 'www.pinterest.com',
    'snapchat.com', 'www.snapchat.com',
    'discord.com', 'www.discord.com', 'discord.gg',
    'twitch.tv', 'www.twitch.tv',
    
    // Shopping
    'amazon.com', 'www.amazon.com', 'amazon.co.uk', 'amazon.ca',
    'ebay.com', 'www.ebay.com',
    'walmart.com', 'www.walmart.com',
    'target.com', 'www.target.com',
    'bestbuy.com', 'www.bestbuy.com',
    'etsy.com', 'www.etsy.com',
    'shopify.com', 'www.shopify.com',
    
    // Tech giants
    'microsoft.com', 'www.microsoft.com', 'office.com', 'live.com', 'outlook.com',
    'apple.com', 'www.apple.com', 'icloud.com',
    'google.com', 'accounts.google.com', 'mail.google.com', 'drive.google.com', 'docs.google.com',
    
    // Development
    'github.com', 'www.github.com', 'gist.github.com',
    'gitlab.com', 'www.gitlab.com',
    'stackoverflow.com', 'www.stackoverflow.com', 'stackexchange.com',
    'npmjs.com', 'www.npmjs.com',
    'pypi.org', 'www.pypi.org',
    
    // News & Reference
    'wikipedia.org', 'en.wikipedia.org', 'www.wikipedia.org',
    'cnn.com', 'www.cnn.com',
    'bbc.com', 'www.bbc.com', 'bbc.co.uk',
    'nytimes.com', 'www.nytimes.com',
    'reuters.com', 'www.reuters.com',
    
    // Streaming
    'netflix.com', 'www.netflix.com',
    'hulu.com', 'www.hulu.com',
    'disneyplus.com', 'www.disneyplus.com',
    'spotify.com', 'www.spotify.com', 'open.spotify.com',
    'hbomax.com', 'www.hbomax.com', 'max.com',
    
    // Financial (major banks)
    'paypal.com', 'www.paypal.com',
    'chase.com', 'www.chase.com',
    'bankofamerica.com', 'www.bankofamerica.com',
    'wellsfargo.com', 'www.wellsfargo.com',
    'stripe.com', 'www.stripe.com',
    
    // Cloud services
    'aws.amazon.com', 'console.aws.amazon.com',
    'azure.microsoft.com', 'portal.azure.com',
    'cloud.google.com', 'console.cloud.google.com',
    'digitalocean.com', 'www.digitalocean.com',
    'cloudflare.com', 'www.cloudflare.com', 'dash.cloudflare.com',
    'vercel.com', 'www.vercel.com',
    'heroku.com', 'www.heroku.com',
    'netlify.com', 'www.netlify.com',
    
    // Communication
    'zoom.us', 'www.zoom.us',
    'slack.com', 'www.slack.com',
    'teams.microsoft.com',
    'meet.google.com',
    
    // Other common
    'dropbox.com', 'www.dropbox.com',
    'notion.so', 'www.notion.so',
    'trello.com', 'www.trello.com',
    'canva.com', 'www.canva.com',
    'figma.com', 'www.figma.com',
    'godaddy.com', 'www.godaddy.com',
    'squarespace.com', 'www.squarespace.com',
    'wix.com', 'www.wix.com',
    'wordpress.com', 'www.wordpress.com',
    
    // SecureLink
    'securelinkapp.com', 'www.securelinkapp.com'
];

// Persistent counters — survive service worker restarts
let badgeBlockedCount = 0;
let totalScannedCount = 0;
chrome.storage.local.get(['badgeBlockedCount', 'totalScannedCount'], (result) => {
    badgeBlockedCount  = result.badgeBlockedCount  || 0;
    totalScannedCount  = result.totalScannedCount  || 0;
    updateBadge();
});

function updateBadge() {
    if (badgeBlockedCount > 0) {
        chrome.action.setBadgeText({ text: badgeBlockedCount > 99 ? '99+' : String(badgeBlockedCount) });
        chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
    } else {
        chrome.action.setBadgeText({ text: '' });
    }
}

function incrementBadge() {
    badgeBlockedCount++;
    chrome.storage.local.set({ badgeBlockedCount });
    updateBadge();
}

function incrementScanned() {
    totalScannedCount++;
    chrome.storage.local.set({ totalScannedCount });
}

// Right-click context menu for scanning links
chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: 'securelink-scan',
        title: 'Scan link with SecureLink',
        contexts: ['link']
    });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId !== 'securelink-scan') return;

    const url = info.linkUrl;
    if (!url) return;

    // Store scanning state and open popup immediately
    chrome.storage.local.set({ lastScanResult: { status: 'scanning', url, timestamp: Date.now() } });

    // Open popup so user can see the scan happening
    chrome.windows.getCurrent({ populate: false }, (win) => {
        if (win && win.focused && chrome.action.openPopup) {
            chrome.action.openPopup().catch(() => {});
        }
    });

    const result = await checkUrl(url);

    if (result.limitReached) {
        chrome.storage.local.set({ lastScanResult: { status: 'limit', url, message: result.message, timestamp: Date.now() } });
        return;
    }

    const score = result.riskScore || 0;
    const threats = [...(result.threats || []), ...(result.warnings || [])];

    incrementScanned();
    if (score >= 50) incrementBadge();

    // Store final result — popup listening for this change will update automatically
    chrome.storage.local.set({ lastScanResult: { status: 'done', url, score, threats, timestamp: Date.now() } });
});

// Use webNavigation.onBeforeNavigate to intercept BEFORE page loads
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only check main frame navigation
    if (details.frameId !== 0) return;
    
    const url = details.url;
    const tabId = details.tabId;

    // Skip internal/local URLs
    for (const pattern of SKIP_PATTERNS) {
        if (pattern.test(url)) return;
    }
    
    // Skip extension pages
    if (url.includes('warning.html') || url.includes('upgrade.html')) return;
    
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname.replace(/^www\./, '');
        
        // Skip known safe domains
        if (SAFE_DOMAINS.some(d => d === urlObj.hostname || d === hostname)) return;

        // Check if already pending
        if (pendingChecks.has(url)) return;

        // Check cache first
        const cached = checkedUrls.get(url);
        if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
            if (cached.dangerous) showWarning(tabId, url, cached.data);
            return;
        }

        // Mark as pending
        pendingChecks.add(url);

        const result = await checkUrl(url);
        pendingChecks.delete(url);

        // Handle rate limit
        if (result.limitReached) {
            showUpgradePrompt(tabId, result.message);
            return;
        }
        
        // Cache the result
        checkedUrls.set(url, {
            timestamp: Date.now(),
            dangerous: result.riskScore >= 50,
            data: result
        });

        incrementScanned();

        if (result.riskScore >= 50) {
            incrementBadge();
            showWarning(tabId, url, result);
        }
        
    } catch (_) {
        // Silently skip — do not block navigation on scan errors
    }
});

// Check URL against our API
async function checkUrl(url) {
    try {
        const headers = { 'Content-Type': 'application/json' };
        
        // Add auth token if logged in
        if (userSession?.token) {
            headers['Authorization'] = `Bearer ${userSession.token}`;
        }
        
        const response = await fetch(`${API_BASE}/api/extension/verify`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ url })
        });
        
        // Handle rate limit
        if (response.status === 429) {
            const data = await response.json();
            return {
                riskScore: 0,
                limitReached: true,
                message: data.message || 'Daily scan limit reached',
                upgradeUrl: data.upgrade_url
            };
        }
        
        if (!response.ok) {
            return { riskScore: 0, threats: [], message: 'API error' };
        }
        
        const data = await response.json();
        
        // API returns 0-1 scale, convert to 0-100
        let riskScore = data.risk_score || 0;
        if (riskScore <= 1) {
            riskScore = Math.round(riskScore * 100);
        }
        
        return {
            riskScore: riskScore,
            threats: data.threats_detected || data.threats || [],
            warnings: data.warnings || [],
            isSafe: data.is_safe,
            scansRemaining: data.scans_remaining,
            subscriptionTier: data.subscription_tier,
            message: data.message || ''
        };
    } catch (_) {
        return { riskScore: 0, threats: [], message: 'Could not verify' };
    }
}

// Show warning page
function showWarning(tabId, url, result) {
    // Combine threats and warnings
    const allThreats = [...(result.threats || []), ...(result.warnings || [])];
    
    const warningUrl = chrome.runtime.getURL('warning.html') + 
        `?url=${encodeURIComponent(url)}` +
        `&score=${result.riskScore}` +
        `&threats=${encodeURIComponent(JSON.stringify(allThreats))}`;
    
    // Redirect to warning page
    chrome.tabs.update(tabId, { url: warningUrl });
}

// Show upgrade prompt when rate limited
function showUpgradePrompt(tabId, message) {
    const upgradeUrl = chrome.runtime.getURL('upgrade.html') + 
        `?message=${encodeURIComponent(message)}`;
    
    // Show upgrade prompt in new tab (don't block navigation)
    chrome.tabs.create({ url: upgradeUrl, active: false });
}

// Login function
async function login(email, password) {
    try {
        const response = await fetch(`${API_BASE}/api/extension/auth`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email_or_username: email, password: password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            userSession = {
                token: data.token,
                user: data.user,
                scanLimit: data.scan_limit
            };
            
            // Save session
            chrome.storage.local.set({ userSession: userSession });
            
            return { success: true, user: data.user };
        }
        
        return { success: false, error: data.error || 'Login failed' };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Logout function
function logout() {
    userSession = null;
    chrome.storage.local.remove(['userSession']);
    return { success: true };
}

// Get current status
async function getStatus() {
    try {
        const headers = { 'Content-Type': 'application/json' };
        
        if (userSession?.token) {
            headers['Authorization'] = `Bearer ${userSession.token}`;
        }
        
        const response = await fetch(`${API_BASE}/api/extension/status`, {
            method: 'GET',
            headers: headers
        });
        
        return await response.json();
    } catch (error) {
        return { error: error.message };
    }
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'checkUrl') {
        checkUrl(message.url).then(result => {
            sendResponse(result);
        });
        return true;
    }
    
    if (message.action === 'login') {
        login(message.email, message.password).then(result => {
            sendResponse(result);
        });
        return true;
    }
    
    if (message.action === 'logout') {
        sendResponse(logout());
    }
    
    if (message.action === 'getStatus') {
        getStatus().then(result => {
            sendResponse(result);
        });
        return true;
    }
    
    if (message.action === 'getSession') {
        sendResponse({ session: userSession });
    }
    
    if (message.action === 'getStats') {
        sendResponse({
            checkedCount: totalScannedCount,
            blockedCount: badgeBlockedCount
        });
    }

    if (message.action === 'clearBadge') {
        badgeBlockedCount = 0;
        totalScannedCount = 0;
        chrome.storage.local.set({ badgeBlockedCount: 0, totalScannedCount: 0 });
        updateBadge();
        sendResponse({ success: true });
    }
});
