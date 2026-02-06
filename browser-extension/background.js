// SecureLink Browser Extension - Background Service Worker
// Automatically scans URLs when you navigate and warns about malicious sites

const API_BASE = 'https://securelinkapp.com'; // Production API

// Track checked URLs to avoid re-checking
const checkedUrls = new Map();
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// User session
let userSession = null;

// Load saved session on startup
chrome.storage.local.get(['userSession'], (result) => {
    if (result.userSession) {
        userSession = result.userSession;
        console.log('SecureLink: Loaded saved session for', userSession.user?.email);
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

// Known safe domains that don't need checking
const SAFE_DOMAINS = [
    'google.com', 'www.google.com', 'google.co.uk',
    'youtube.com', 'www.youtube.com',
    'facebook.com', 'www.facebook.com',
    'amazon.com', 'www.amazon.com',
    'microsoft.com', 'www.microsoft.com',
    'apple.com', 'www.apple.com',
    'github.com', 'www.github.com',
    'stackoverflow.com', 'www.stackoverflow.com',
    'wikipedia.org', 'en.wikipedia.org',
    'reddit.com', 'www.reddit.com',
    'twitter.com', 'x.com',
    'linkedin.com', 'www.linkedin.com',
    'netflix.com', 'www.netflix.com',
    'securelinkapp.com', 'www.securelinkapp.com'
];

console.log('SecureLink: Extension loaded and ready');

// Listen for tab URL changes - this catches address bar navigation
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    // Only check when URL changes and we have a URL
    if (!changeInfo.url) return;
    
    const url = changeInfo.url;
    console.log('SecureLink: Detected navigation to:', url);
    
    // Skip internal/local URLs
    for (const pattern of SKIP_PATTERNS) {
        if (pattern.test(url)) {
            console.log('SecureLink: Skipping internal URL');
            return;
        }
    }
    
    // Skip extension warning page
    if (url.includes('warning.html')) return;
    
    try {
        const urlObj = new URL(url);
        
        // Skip known safe domains
        const hostname = urlObj.hostname.replace(/^www\./, '');
        if (SAFE_DOMAINS.some(d => d === urlObj.hostname || d === hostname)) {
            console.log('SecureLink: Known safe domain, skipping');
            return;
        }
        
        // Check cache first
        const cached = checkedUrls.get(url);
        if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
            console.log('SecureLink: Using cached result, dangerous:', cached.dangerous);
            if (cached.dangerous) {
                showWarning(tabId, url, cached.data);
            }
            return;
        }
        
        // Check the URL with our API
        console.log('SecureLink: Checking URL with API...');
        const result = await checkUrl(url);
        console.log('SecureLink: API result - Risk Score:', result.riskScore);
        
        // Handle rate limit
        if (result.limitReached) {
            console.log('SecureLink: Rate limit reached');
            showUpgradePrompt(tabId, result.message);
            return;
        }
        
        // Cache the result
        checkedUrls.set(url, {
            timestamp: Date.now(),
            dangerous: result.riskScore >= 50,
            data: result
        });
        
        // Show warning for risky URLs (50+ risk score)
        if (result.riskScore >= 50) {
            console.log('SecureLink: DANGEROUS URL DETECTED! Showing warning...');
            showWarning(tabId, url, result);
        }
        
    } catch (error) {
        console.error('SecureLink: Error checking URL', error);
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
            console.error('SecureLink: API returned status', response.status);
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
    } catch (error) {
        console.error('SecureLink: API fetch error', error);
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
            checkedCount: checkedUrls.size,
            blockedCount: [...checkedUrls.values()].filter(v => v.dangerous).length
        });
    }
});
