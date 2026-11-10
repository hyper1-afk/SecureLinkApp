// SecureLink Browser Extension - Background Service Worker
// Automatically scans URLs when you navigate and warns about malicious sites

import {
    buildAuthorizationUrl,
    createPkcePair,
    randomBase64Url,
    readAuthorizationCallback,
} from './v2-oauth.js';
import { configuredApiOrigin, validateApiOrigin } from './api-origin.js';
import { legacyScanFailure, normalizeLegacyScan } from './legacy-scan.js';
import { redactUrlForSubmission } from './url-privacy.js';
import {
    createWarningPageUrl,
    matchesTabBypass,
    warningBypassKey,
    warningIncidentKey
} from './warning-state.js';

const DEFAULT_API_BASE = 'https://securelinkapp.com';
const PUBLISHED_EXTENSION_ID = 'dpegeipjmofhdikcbniodhohpckoeole';
const IS_PUBLISHED_EXTENSION = chrome.runtime.id === PUBLISHED_EXTENSION_ID;
let API_BASE = IS_PUBLISHED_EXTENSION ? DEFAULT_API_BASE : '';

// Load custom API URL (set via extension settings panel)
chrome.storage.local.get(['customApiUrl'], (result) => {
    API_BASE = configuredApiOrigin(
        result.customApiUrl,
        IS_PUBLISHED_EXTENSION ? DEFAULT_API_BASE : ''
    );
});

// Update API_BASE whenever user changes it in the settings panel
chrome.storage.onChanged.addListener((changes) => {
    if (changes.customApiUrl !== undefined) {
        API_BASE = configuredApiOrigin(
            changes.customApiUrl.newValue,
            IS_PUBLISHED_EXTENSION ? DEFAULT_API_BASE : ''
        );
    }
});

// Track checked URLs to avoid re-checking
const checkedUrls = new Map();
const CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours - saves scans on revisited sites
const MAX_CACHED_URLS = 500;
const pendingChecks = new Set(); // URLs currently being checked

// Remove raw warning-bypass keys and context-menu results created by older versions.
chrome.storage.local.get(null, (stored) => {
    const staleKeys = Object.keys(stored || {}).filter((key) => key.startsWith('bypass_'));
    if (stored?.lastScanResult) staleKeys.push('lastScanResult');
    if (staleKeys.length) chrome.storage.local.remove(staleKeys);
});

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
    'microsoft.com', 'www.microsoft.com', 'office.com', 'www.office.com',
    'outlook.office.com', 'outlook.office365.com', 'outlook.com', 'www.outlook.com',
    'live.com', 'login.microsoftonline.com', 'login.live.com',
    'teams.microsoft.com', 'sharepoint.com', 'onedrive.live.com',
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

function cacheScan(url, result) {
    checkedUrls.delete(url);
    checkedUrls.set(url, {
        timestamp: Date.now(),
        dangerous: result.riskScore >= 50,
        data: result
    });
    if (checkedUrls.size > MAX_CACHED_URLS) {
        checkedUrls.delete(checkedUrls.keys().next().value);
    }
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
    chrome.storage.session.set({ lastScanResult: { status: 'scanning', url, timestamp: Date.now() } });

    // Open popup so user can see the scan happening
    chrome.windows.getCurrent({ populate: false }, (win) => {
        if (win && win.focused && chrome.action.openPopup) {
            chrome.action.openPopup().catch(() => {});
        }
    });

    const result = await checkUrl(url);

    if (result.error) {
        chrome.storage.session.set({ lastScanResult: { status: 'error', url, message: result.message, timestamp: Date.now() } });
        return;
    }

    if (result.limitReached) {
        chrome.storage.session.set({ lastScanResult: { status: 'limit', url, message: result.message, timestamp: Date.now() } });
        return;
    }

    const score = result.riskScore || 0;
    const threats = [...(result.threats || []), ...(result.warnings || [])];

    incrementScanned();
    if (score >= 50) incrementBadge();

    // Store final result — popup listening for this change will update automatically
    chrome.storage.session.set({ lastScanResult: { status: 'done', url, score, threats, timestamp: Date.now() } });
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

    // Consume a short-lived, tab-scoped exception once, only for its exact destination.
    const bypassKey = warningBypassKey(tabId);
    const bypassEntry = await chrome.storage.session.get(bypassKey);
    const bypass = bypassEntry[bypassKey];
    if (bypass) {
        await chrome.storage.session.remove(bypassKey);
        if (matchesTabBypass(bypass, url)) return;
    }

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
            if (cached.dangerous) await showWarning(tabId, url, cached.data);
            return;
        }

        // Mark as pending
        pendingChecks.add(url);

        const result = await checkUrl(url);
        pendingChecks.delete(url);

        if (result.error) return;

        // Handle rate limit
        if (result.limitReached) {
            showUpgradePrompt(tabId, result.message);
            return;
        }
        
        // Cache the result
        cacheScan(url, result);

        incrementScanned();

        if (result.riskScore >= 50) {
            incrementBadge();
            await showWarning(tabId, url, result);
        }
        
    } catch (_) {
        // Silently skip — do not block navigation on scan errors
    }
});

// Check URL against our API
async function checkUrl(url) {
    try {
        if (!API_BASE) return legacyScanFailure('Legacy API is not configured in this unpacked build.');
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
            return legacyScanFailure('Legacy scanner could not reach its API.');
        }
        
        const data = await response.json();
        return normalizeLegacyScan(data);
    } catch (_) {
        return legacyScanFailure('Legacy scanner could not verify this link.');
    }
}

// Show warning page
async function showWarning(tabId, url, result) {
    const incidentId = crypto.randomUUID();
    const storageKey = warningIncidentKey(incidentId);
    const allThreats = [...(result.threats || []), ...(result.warnings || [])]
        .filter((item) => typeof item === 'string')
        .slice(0, 20)
        .map((item) => item.slice(0, 240));
    await chrome.storage.session.set({
        [storageKey]: {
            url,
            score: Math.max(0, Math.min(100, Number(result.riskScore) || 0)),
            threats: allThreats,
            expiresAt: Date.now() + 5 * 60 * 1000
        }
    });
    try {
        await chrome.tabs.update(tabId, {
            url: createWarningPageUrl(chrome.runtime.getURL(''), incidentId)
        });
    } catch (error) {
        await chrome.storage.session.remove(storageKey);
        throw error;
    }
}

// Show upgrade prompt when rate limited — only open one tab
function showUpgradePrompt(tabId, message) {
    const upgradeBase = chrome.runtime.getURL('upgrade.html');

    // If an upgrade tab is already open, just focus it instead of opening another
    chrome.tabs.query({}, (tabs) => {
        const existing = tabs.find(t => t.url && t.url.startsWith(upgradeBase));
        if (existing) {
            chrome.tabs.update(existing.id, { active: true });
            chrome.windows.update(existing.windowId, { focused: true });
        } else {
            const upgradeUrl = upgradeBase + `?message=${encodeURIComponent(message)}`;
            chrome.tabs.create({ url: upgradeUrl, active: false });
        }
    });
}

// Login function
async function login(email, password) {
    try {
        if (!API_BASE) return { success: false, error: 'Configure the legacy API URL before using legacy sign-in.' };
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
        if (!API_BASE) return { error: 'Legacy API is not configured in this unpacked build.' };
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

const V2_TOKEN_KEY = 'v2ExtensionAccessToken';
const V2_ORIGIN_KEY = 'v2ApiOrigin';
const V2_ORG_KEY = 'v2OrganizationId';
const V2_EXPIRY_KEY = 'v2TokenExpiresAt';

function extensionPageSender(sender) {
    return sender.id === chrome.runtime.id
        && typeof sender.url === 'string'
        && sender.url.startsWith(chrome.runtime.getURL(''))
        && !sender.tab;
}

async function getV2ApiOrigin() {
    const { v2ApiBase } = await chrome.storage.local.get('v2ApiBase');
    if (!v2ApiBase) throw new Error('Set the V2 API origin in extension Settings first.');
    return validateApiOrigin(v2ApiBase).origin;
}

async function connectV2() {
    const apiOrigin = await getV2ApiOrigin();
    const redirectUri = chrome.identity.getRedirectURL();
    const state = randomBase64Url(32);
    const { verifier, challenge } = await createPkcePair();
    const authorizationUrl = buildAuthorizationUrl(apiOrigin, redirectUri, state, challenge);
    const callbackUrl = await chrome.identity.launchWebAuthFlow({ url: authorizationUrl, interactive: true });
    if (!callbackUrl) throw new Error('Authorization was cancelled.');
    const code = readAuthorizationCallback(callbackUrl, redirectUri, state);
    const response = await fetch(new URL('/extension/oauth/token', apiOrigin), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            grant_type: 'authorization_code',
            client_id: 'securelink-chrome-extension',
            code,
            redirect_uri: redirectUri,
            code_verifier: verifier
        }),
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer'
    });
    if (!response.ok) throw new Error('SecureLink V2 could not complete authorization.');
    const token = await response.json();
    if (token.token_type !== 'Bearer' || token.scope !== 'url_scan'
        || !Number.isInteger(token.expires_in) || token.expires_in <= 0
        || typeof token.access_token !== 'string' || token.access_token.length < 32) {
        throw new Error('SecureLink V2 returned an invalid session.');
    }
    await chrome.storage.session.set({
        [V2_TOKEN_KEY]: token.access_token,
        [V2_ORIGIN_KEY]: apiOrigin,
        [V2_ORG_KEY]: token.organization_id,
        [V2_EXPIRY_KEY]: Date.now() + token.expires_in * 1000
    });
    return { connected: true, expiresAt: Date.now() + token.expires_in * 1000 };
}

async function v2Session() {
    const values = await chrome.storage.session.get([
        V2_TOKEN_KEY, V2_ORIGIN_KEY, V2_ORG_KEY, V2_EXPIRY_KEY
    ]);
    if (!values[V2_TOKEN_KEY] || !values[V2_ORIGIN_KEY]
        || !values[V2_EXPIRY_KEY] || values[V2_EXPIRY_KEY] <= Date.now()) {
        await chrome.storage.session.remove([V2_TOKEN_KEY, V2_ORIGIN_KEY, V2_ORG_KEY, V2_EXPIRY_KEY]);
        return null;
    }
    const configuredOrigin = await getV2ApiOrigin();
    if (configuredOrigin !== values[V2_ORIGIN_KEY]) {
        throw new Error('The V2 API origin changed. Disconnect the old session before reconnecting.');
    }
    return values;
}

async function v2Status() {
    const values = await chrome.storage.session.get([
        V2_TOKEN_KEY, V2_ORIGIN_KEY, V2_EXPIRY_KEY, V2_ORG_KEY
    ]);
    if (!values[V2_TOKEN_KEY] || !values[V2_ORIGIN_KEY]
        || !values[V2_EXPIRY_KEY] || values[V2_EXPIRY_KEY] <= Date.now()) {
        await chrome.storage.session.remove([V2_TOKEN_KEY, V2_ORIGIN_KEY, V2_ORG_KEY, V2_EXPIRY_KEY]);
        return { connected: false };
    }
    if (await getV2ApiOrigin() !== values[V2_ORIGIN_KEY]) {
        return { connected: false, error: 'The configured API differs from the saved session.' };
    }
    const response = await fetch(new URL('/extension/oauth/session', values[V2_ORIGIN_KEY]), {
        headers: { Authorization: `Bearer ${values[V2_TOKEN_KEY]}` },
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer'
    });
    if (response.status === 401 || response.status === 403) {
        await chrome.storage.session.remove([V2_TOKEN_KEY, V2_ORIGIN_KEY, V2_ORG_KEY, V2_EXPIRY_KEY]);
        return { connected: false };
    }
    if (!response.ok) throw new Error('Could not verify the V2 session with the API.');
    const currentSession = await response.json();
    return {
        connected: true,
        organizationId: currentSession.organization_id,
        expiresAt: new Date(currentSession.expires_at).getTime()
    };
}

async function disconnectV2() {
    const values = await chrome.storage.session.get([V2_TOKEN_KEY, V2_ORIGIN_KEY]);
    let serverRevoked = false;
    if (values[V2_TOKEN_KEY] && values[V2_ORIGIN_KEY]) {
        try {
            const response = await fetch(new URL('/extension/oauth/revoke', values[V2_ORIGIN_KEY]), {
                method: 'POST',
                headers: { Authorization: `Bearer ${values[V2_TOKEN_KEY]}` },
                cache: 'no-store',
                credentials: 'omit',
                referrerPolicy: 'no-referrer'
            });
            serverRevoked = response.ok;
        } catch (_) {
            serverRevoked = false;
        } finally {
            await chrome.storage.session.remove([V2_TOKEN_KEY, V2_ORIGIN_KEY, V2_ORG_KEY, V2_EXPIRY_KEY]);
        }
    }
    return { connected: false, serverRevoked };
}

async function scanWithV2(url) {
    const values = await v2Session();
    if (!values) throw new Error('Connect a V2 workspace before submitting a manual review.');
    const sanitized = redactUrlForSubmission(url);
    const response = await fetch(new URL('/extension/v1/scans', values[V2_ORIGIN_KEY]), {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${values[V2_TOKEN_KEY]}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: sanitized.url, redactions: sanitized.redactions }),
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer'
    });
    if (response.status === 401 || response.status === 403) {
        await chrome.storage.session.remove([V2_TOKEN_KEY, V2_ORIGIN_KEY, V2_ORG_KEY, V2_EXPIRY_KEY]);
        throw new Error('V2 access expired or was revoked. Connect again to continue.');
    }
    if (!response.ok) throw new Error('SecureLink V2 could not review this link.');
    return response.json();
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (['v2Connect', 'v2Disconnect', 'v2Status', 'v2Scan'].includes(message.action)) {
        if (!extensionPageSender(sender)) {
            sendResponse({ error: 'V2 actions are available only from the SecureLink extension popup.' });
            return false;
        }
        const operation = message.action === 'v2Connect' ? connectV2()
            : message.action === 'v2Disconnect' ? disconnectV2()
                : message.action === 'v2Status' ? v2Status()
                    : scanWithV2(message.url);
        operation.then(
            result => sendResponse({ success: true, result }),
            error => sendResponse({ error: error instanceof Error ? error.message : 'V2 request failed.' })
        );
        return true;
    }

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

    if (message.action === 'getLegacyApiState') {
        sendResponse({ configured: Boolean(API_BASE), publishedDefault: IS_PUBLISHED_EXTENSION });
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
