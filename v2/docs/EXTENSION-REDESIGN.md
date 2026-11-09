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

Use the V2 API only after the browser auth protocol is designed. Prefer browser-mediated OAuth authorization code with PKCE and short-lived access tokens; keep refresh/session handling in the extension worker. Passwords should be entered on the SecureLink web origin, not sent from the extension popup to a new password-login endpoint. Add extension-specific audience/scope and revoke sessions when a user resets their password or account is disabled.

Do not put a long-lived API secret in the extension package. The extension is a public client; all entitlements and scan quotas must be enforced by the server.

## Release checks

Test MV3 service-worker suspension/restart, Chrome and Edge behavior, permission prompts, extension-page XSS/message abuse, cache bounds, warning bypass, API timeout/rate limit/offline states, and URL redaction. Run a privacy review of the store listing and permission justification before publishing.
