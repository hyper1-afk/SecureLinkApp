import {
    createTabBypass,
    warningBypassKey,
    warningIncidentKey
} from './warning-state.js';

const incidentId = new URLSearchParams(window.location.search).get('incident');
const incidentKey = (() => {
    try {
        return warningIncidentKey(incidentId);
    } catch (_) {
        return null;
    }
})();

const SVG_DANGER = `<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
const SVG_WARN = `<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;

const card = document.getElementById('card');
const accent = document.getElementById('card-accent');
const badge = document.getElementById('risk-badge');
const flagIcon = document.getElementById('flag-icon');
const heading = document.getElementById('heading');
const subtitle = document.getElementById('subtitle');
const proceedBtn = document.getElementById('btn-proceed');
const scoreLine = document.getElementById('score-line');
const list = document.getElementById('threats-list');
const backBtn = document.getElementById('btn-back');

function showUnavailable() {
    flagIcon.innerHTML = SVG_WARN;
    flagIcon.className = 'flag-icon medium';
    heading.textContent = 'Warning details unavailable';
    heading.className = 'warn';
    subtitle.textContent = 'SecureLink could not load this warning. Do not treat the link as safe.';
    badge.textContent = 'UNKNOWN';
    badge.className = 'risk-badge medium';
    accent.className = 'card-accent medium';
    card.classList.add('medium-card');
    document.getElementById('blocked-url').textContent = 'Link details expired or unavailable';
    list.replaceChildren();
    scoreLine.textContent = '';
    proceedBtn.classList.add('hidden');
}

function renderIncident(incident) {
    if (!incident || typeof incident.url !== 'string'
        || !Number.isInteger(incident.score) || incident.score < 50 || incident.score > 100
        || !Number.isFinite(incident.expiresAt) || incident.expiresAt <= Date.now()
        || !Array.isArray(incident.threats)) {
        showUnavailable();
        return;
    }
    flagIcon.innerHTML = SVG_DANGER;
    badge.textContent = 'HIGH RISK';
    heading.textContent = 'This site may be dangerous';
    subtitle.textContent = 'SecureLink detected risk indicators. Do not enter personal or account information.';
    document.getElementById('blocked-url').textContent = incident.url;
    scoreLine.textContent = `Risk score: ${incident.score} / 100`;
    list.replaceChildren();
    for (const threat of incident.threats.slice(0, 20)) {
        if (typeof threat !== 'string') continue;
        const item = document.createElement('div');
        item.className = 'threat-item';
        const icon = document.createElement('span');
        icon.className = 'icon';
        item.append(icon, document.createTextNode(threat.slice(0, 240)));
        list.append(item);
    }
    proceedBtn.disabled = false;
    setTimeout(async () => {
        if (!incidentKey) return;
        const current = await chrome.storage.session.get(incidentKey);
        const saved = current[incidentKey];
        if (saved?.expiresAt === incident.expiresAt && saved.expiresAt <= Date.now()) {
            await chrome.storage.session.remove(incidentKey);
            showUnavailable();
        }
    }, Math.max(0, incident.expiresAt - Date.now()));
}

async function loadIncident() {
    if (!incidentKey) {
        showUnavailable();
        return;
    }
    try {
        const stored = await chrome.storage.session.get(incidentKey);
        const incident = stored[incidentKey];
        if (!incident || !Number.isFinite(incident.expiresAt) || incident.expiresAt <= Date.now()) {
            await chrome.storage.session.remove(incidentKey);
            showUnavailable();
            return;
        }
        renderIncident(incident);
    } catch (_) {
        showUnavailable();
    }
}

backBtn.addEventListener('click', () => {
    if (incidentKey) chrome.storage.session.remove(incidentKey);
    chrome.tabs.getCurrent((tab) => {
        if (tab?.id !== undefined) chrome.tabs.update(tab.id, { url: 'chrome://newtab' });
    });
});

proceedBtn.addEventListener('click', async () => {
    if (!incidentKey || proceedBtn.disabled) return;
    proceedBtn.disabled = true;
    try {
        const stored = await chrome.storage.session.get(incidentKey);
        const incident = stored[incidentKey];
        if (!incident || incident.expiresAt <= Date.now()) {
            showUnavailable();
            return;
        }
        const tab = await new Promise((resolve) => chrome.tabs.getCurrent(resolve));
        if (!tab || !Number.isSafeInteger(tab.id)) throw new Error('Warning tab is unavailable.');
        const bypassKey = warningBypassKey(tab.id);
        await chrome.storage.session.set({ [bypassKey]: createTabBypass(incident.url) });
        try {
            await chrome.tabs.update(tab.id, { url: incident.url });
            await chrome.storage.session.remove(incidentKey);
        } catch (error) {
            await chrome.storage.session.remove(bypassKey);
            throw error;
        }
    } catch (_) {
        subtitle.textContent = 'SecureLink could not continue to the link. Use Go back to leave this page.';
        proceedBtn.disabled = false;
    }
});

void loadIncident();
