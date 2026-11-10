// SecureLink Browser Extension - Background Service Worker
// Automatically scans URLs when you navigate and warns about malicious sites

import {
    buildAuthorizationUrl,
    createPkcePair,
    randomBase64Url,
    readAuthorizationCallback,
} from './v2-oauth.js';
import { configuredApiOrigin, validateApiOrigin } from './api-origin.js';
import { legacyScanFailure, normalizeLegacyScan, shouldSkipCloudScan } from './legacy-scan.js';
import { redactUrlForAutomaticScan, redactUrlForSubmission } from './url-privacy.js';
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

    // Never send browser-internal or local/private destinations to the cloud API.
    if (shouldSkipCloudScan(url)) return;

    // Consume a short-lived, tab-scoped exception once, only for its exact destination.
    const bypassKey = warningBypassKey(tabId);
    const bypassEntry = await chrome.storage.session.get(bypassKey);
    const bypass = bypassEntry[bypassKey];
    if (bypass) {
        await chrome.storage.session.remove(bypassKey);
        if (matchesTabBypass(bypass, url)) return;
    }

    try {
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
        if (shouldSkipCloudScan(url)) {
            return legacyScanFailure('This local or unsupported address was not sent to the cloud scanner.');
        }
        const submittedUrl = redactUrlForAutomaticScan(url);
        const headers = { 'Content-Type': 'application/json' };
        
        // Add auth token if logged in
        if (userSession?.token) {
            headers['Authorization'] = `Bearer ${userSession.token}`;
        }
        
        const response = await fetch(`${API_BASE}/api/extension/verify`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ url: submittedUrl })
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
        && sender.url === chrome.runtime.getURL('popup.html')
        && !sender.tab;
}

function extensionContentScriptSender(sender) {
    if (sender.id !== chrome.runtime.id || !sender.tab || typeof sender.url !== 'string') return false;
    try {
        const senderUrl = new URL(sender.url);
        return senderUrl.protocol === 'http:' || senderUrl.protocol === 'https:';
    } catch (_) {
        return false;
    }
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

async function scanCurrentPage() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id || !/^https?:\/\//i.test(tab.url || '')) {
        throw new Error('Page scanning is available on regular HTTP or HTTPS pages.');
    }
    await chrome.scripting.insertCSS({ target: { tabId: tab.id }, files: ['content.css'] });
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content.js'] });
    await chrome.tabs.sendMessage(tab.id, { action: 'scanLinks' });
    return { started: true, message: 'Up to 25 external links are being reviewed on the current page.' };
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'scanCurrentPage') {
        if (!extensionPageSender(sender)) {
            sendResponse({ error: 'Page scanning must be started from the SecureLink popup.' });
            return false;
        }
        scanCurrentPage().then(
            result => sendResponse(result),
            error => sendResponse({ error: error instanceof Error ? error.message : 'Could not scan this page.' })
        );
        return true;
    }

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
        if (!extensionPageSender(sender) && !extensionContentScriptSender(sender)) {
            sendResponse({ error: 'URL review requests must come from the SecureLink extension.' });
            return false;
        }
        if (typeof message.url !== 'string' || message.url.length > 4096) {
            sendResponse({ error: 'The URL is invalid or too long.' });
            return false;
        }
        checkUrl(message.url).then(result => {
            sendResponse(result);
        });
        return true;
    }

    if (['login', 'logout', 'getStatus', 'getSession', 'getLegacyApiState', 'getStats', 'clearBadge'].includes(message.action)
        && !extensionPageSender(sender)) {
        sendResponse({ error: 'This action is available only from the SecureLink extension popup.' });
        return false;
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
