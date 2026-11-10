const INCIDENT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function warningIncidentKey(id) {
  if (typeof id !== "string" || !INCIDENT_ID.test(id)) {
    throw new Error("Invalid warning incident identifier.");
  }
  return `warningIncident_${id}`;
}

export function warningBypassKey(tabId) {
  if (!Number.isSafeInteger(tabId) || tabId < 0) {
    throw new Error("Invalid warning tab identifier.");
  }
  return `warningBypass_${tabId}`;
}

export function createWarningPageUrl(extensionBase, incidentId) {
  const base = new URL(extensionBase);
  if (base.protocol !== "chrome-extension:" || !base.pathname.endsWith("/")) {
    throw new Error("Invalid extension page origin.");
  }
  const url = new URL("warning.html", base);
  url.searchParams.set("incident", warningIncidentKey(incidentId).slice("warningIncident_".length));
  return url.href;
}

export function createTabBypass(url, now = Date.now()) {
  const destination = new URL(url);
  if (destination.protocol !== "https:" && destination.protocol !== "http:") {
    throw new Error("Only web links can be opened from a warning.");
  }
  if (!Number.isFinite(now)) throw new Error("Invalid bypass timestamp.");
  return { url, expiresAt: now + 10_000 };
}

export function matchesTabBypass(record, url, now = Date.now()) {
  if (!record || typeof record !== "object" || typeof record.url !== "string"
      || !Number.isFinite(record.expiresAt) || !Number.isFinite(now)) return false;
  return record.url === url && record.expiresAt > now;
}
