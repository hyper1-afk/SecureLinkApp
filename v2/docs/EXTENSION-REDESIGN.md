# Browser extension redesign

The legacy extension lives in `browser-extension/` at the repository root. It is separate from V2 and currently calls legacy endpoints such as `/api/extension/verify` and `/api/extension/auth`. Do not point it at V2 until a versioned extension API and auth flow exist.

## Target structure

Move toward a small, typed MV3 extension package with clear boundaries:

- `manifest.json`: minimum required permissions and the SecureLink API host only.
- `src/background/service_worker.ts`: navigation events, API calls, bounded cache, token lifecycle, rate-limit responses.
- `src/popup/`: UI only; it sends typed messages and never receives raw access/refresh tokens.
- `src/warning/`: warning UI backed by a short-lived incident record, not URL/query-string payloads.
- `src/shared/protocol.ts`: request/response types shared by UI, worker, and API client.
- `tests/`: URL normalization/redaction, message authorization, cache expiry, warning bypass, and API error behavior.
- Build output under `dist/`; package and validate the built manifest before store upload.

Keep privileged network and storage operations in the service worker. Validate every message shape and sender, return only needed display data, and clear session data on logout or rejected credentials.

## Security and privacy changes

1. Replace `http://*/*` and `https://*/*` host permissions with the production API origin. Request narrowly scoped optional host permission only for local development. Remove `tabs` if the final implementation does not need tab metadata.
2. Remove the large hard-coded `SAFE_DOMAINS` bypass list. It creates blind spots for compromised or lookalike paths on otherwise popular domains. Only skip browser-internal schemes and the extension's own pages; let server policy decide reputation.
3. Do not put the visited URL or threat detail in `warning.html?url=...`. The current warning page carries them in browser history. Store a short-lived incident under a random ID in `chrome.storage.session` and pass only that ID to the extension page.
4. Redact credentials, fragments, and sensitive query keys (tokens, codes, sessions, email) before sending URLs. Make full-query scanning an explicit, explained opt-in because query values may contain private data.
5. Keep only bounded, expiring cache entries. Avoid storing full URLs or auth tokens in `chrome.storage.local`; expose only session status and account display fields to popup code.
6. Fix warning bypass. `warning.js` currently writes `bypass_<url>`, but `background.js` never reads it, so proceeding can trigger the warning again. Use a one-use, tab-scoped, short-expiry bypass and clear it on the next navigation.
7. Treat network errors as “could not verify,” not “safe.” Surface stale/unknown verdicts distinctly and keep the user in control.
8. The `onBeforeNavigate` fetch-and-redirect path is best-effort: the destination request can begin before the verdict returns. Do not promise pre-load blocking unless the replacement design proves it. Use local declarative rules for known blocked destinations and clearly label cloud checks as navigation-time checks.
9. Add privacy controls for scan history, opt-out/pause controls, and a clear explanation of which URL parts are sent and retained.

## V2 integration

The V2 API now implements the server side of a browser-mediated OAuth authorization-code flow with mandatory PKCE S256. It allowlists the exact Chrome Web Store redirect URI, binds a one-time three-minute authorization code to that redirect and challenge, stores only hashes of codes and opaque extension tokens, and issues a 12-hour extension session. Resetting a password, disabling an account, losing the required organization role, or revoking the session invalidates extension access. Extension tokens are accepted only by `/extension/v1/scans` and `/extension/oauth/revoke`; they cannot call dashboard APIs. The grant has the fixed `url_scan` scope and cannot manage members, assets, or cases. Users can list and revoke their extension sessions from the dashboard.

The V2 preview removes URL credentials and fragments and replaces values for sensitive query keys (including email, tokens, sessions, codes, and redirect parameters) before transmitting a URL. It preserves the corresponding parameter names so the server can detect structural indicators. The API stores only the sanitized URL's structural evidence plus client-reported redaction counts; it does not store the submitted URL. Other query values, host, and path are still sent to the first-party SecureLink API.

The consent page authenticates on the SecureLink origin. Account passwords are never entered into or sent by the extension. The extension must generate a cryptographically random verifier and state for each authorization request, use `chrome.identity.launchWebAuthFlow`, verify the returned state, exchange the code with the verifier, and keep the resulting token in `chrome.storage.session`. Do not add a refresh token. Ask the user to reconnect when the session expires.

Use PKCE for this same-browser extension flow. The OAuth device-code flow is intended for constrained/cross-device use; current cross-device security guidance says not to use cross-device flows for same-device scenarios and highlights user-code phishing risks. [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html), [RFC 10027](https://www.rfc-editor.org/rfc/rfc10027.html).

The legacy extension has not been switched to this API. The OAuth redirect is configured only for the published Chrome Web Store item; confirm the extension ID and staging host before testing the real extension. Edge support and the extension-side PKCE implementation remain to be completed and tested before publication.

Do not put a long-lived API secret in the extension package. The extension is a public client; all entitlements and scan quotas must be enforced by the server.

## Release checks

Test MV3 service-worker suspension/restart, Chrome and Edge behavior, permission prompts, extension-page XSS/message abuse, cache bounds, warning bypass, API timeout/rate limit/offline states, and URL redaction. Run a privacy review of the store listing and permission justification before publishing.
