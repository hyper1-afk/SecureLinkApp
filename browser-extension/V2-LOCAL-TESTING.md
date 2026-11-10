# Test the V2 connector in the existing extension

This development-branch change adds an optional V2 connection while keeping the
legacy automatic scanner as a separate path. It has not been published to the
Chrome Web Store.

1. Start the V2 API and local Mailpit stack from `v2/README.md`. Create an account
   and verify its email through Mailpit.
2. In Chrome, open `chrome://extensions`, enable Developer mode, and choose
   **Load unpacked**. Select this `browser-extension` directory. The unpacked
   extension gets a different ID from the published extension.
3. Copy that local extension ID and add its exact identity callback to the
   untracked `v2/.env` file:
   `EXTENSION_REDIRECT_URIS=https://<local-extension-id>.chromiumapp.org/`
   Restart the V2 API after changing the setting.
4. Open the extension, open Settings, enter `http://localhost:8000` as the V2 API
   origin, and save it. Then choose **Connect** in the SecureLink V2 workspace
   panel. Grant the optional Chrome identity permission, sign in on the
   first-party SecureLink page, select an organization, and approve scan-only
   access.
5. Enter an HTTP or HTTPS URL in the existing scan field and choose
   **Submit link for V2 review**. The V2 finding list is structural only. It
   does not claim that the URL is malicious or safe. Disconnect from the panel
   or revoke the session from the V2 dashboard.

When loaded unpacked with a different ID, the legacy automatic scanner does not
send page URLs to the live legacy API by default. Its panel reports that the
legacy scanner is disabled. The published Chrome Web Store installation retains
its current default endpoint and behavior. The V2 API origin is stored as a
local extension setting; its short-lived token is stored in Chrome session
storage and never sent to a different configured origin.

Do not publish this package until the local flow and isolated staging flow pass
and the Chrome Web Store permission/privacy review is complete.
