# SecureLink V2 extension preview

This is an unpacked development client for the V2 API. It is separate from the
published extension in `browser-extension/`; loading it does not update existing
users.

## Run locally

1. Start the V2 API stack using `v2/README.md` and create a verified test account.
   For local email verification, use the local Mailpit inbox.
2. In Chrome, open `chrome://extensions`, enable Developer mode, and choose
   **Load unpacked**. Select this `v2/extension` directory.
3. Copy the extension ID shown on the extension card. Chrome derives its OAuth
   callback from that ID: `https://<extension-id>.chromiumapp.org/`.
4. Add that exact callback URI to `EXTENSION_REDIRECT_URIS` in the untracked
   `v2/.env` file, for example:
   `EXTENSION_REDIRECT_URIS=https://<extension-id>.chromiumapp.org/`
5. Restart the API, open the extension, choose **Connect account**, grant the
   optional Chrome identity permission for the authorization attempt, sign in on
   the SecureLink page, choose an organization, and approve the scan-only access.
6. Submit an HTTPS URL using **Review link**. The result is a passive structural
   URL review; it does not query threat intelligence and does not certify a link
   as safe. Disconnect from the popup or revoke the session from the dashboard.

The preview uses `http://localhost:8000` and declares only that local API origin
in `manifest.json`. For staging, package a separate build with the staging API
origin in `service-worker.js` and `manifest.json`, and add the staging extension's
exact Chrome identity callback to `EXTENSION_REDIRECT_URIS`. Use HTTPS for every
non-local API. Do not use a wildcard host permission or callback URI.

The access token is held in the extension service worker and Chrome session
storage, expires after 12 hours, and grants only URL scan submission. The
extension never receives the account password or the web dashboard's JWT. This
preview is not the Chrome Web Store release and should not be uploaded as one.
