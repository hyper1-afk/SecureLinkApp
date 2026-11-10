# SecureLink V2 local browser check

This checklist exercises the local V2 website, API, email queue, and unpacked extension without touching the published site or extension.

## Start the local stack

1. Follow the development setup in [the V2 README](../README.md), including `python scripts/init_local_env.py` and `docker compose --profile local-mail up --build` from `v2/`.
2. Open `http://localhost:8000/` for registration and account actions. The authenticated organization dashboard is at `http://localhost:8000/dashboard`; it is a separate page from the account form.
3. Open `http://localhost:8025/` for Mailpit. Use only test addresses and fake URL credentials.

## Website, scan, and alert flow

1. Register a test account and verify it through the message captured in Mailpit. Sign in and open the dashboard.
2. Submit `https://demo-user:demo-password@example.com/private?token=demo-value` in **Inspect a link**.
3. Confirm the result displays only `https://example.com/[path and query omitted]`, and that a high-priority case appears in **Cases** without manually opening it.
4. Confirm an alert email is captured in Mailpit. It should identify the organization, severity, hostname, case ID, and dashboard link. It must not contain `demo-user`, `demo-password`, `/private`, or `demo-value`.
   The dashboard's **Priority email alerts** panel should show zero pending and zero failed after Mailpit accepts the message.
5. Turn off **Email me about high-priority cases**, submit another URL with a fake credential or sensitive query indicator, and confirm no new alert arrives for that account. The preference change should be reflected after reloading the dashboard.
6. A viewer/analyst can change their own preference but should not receive organization priority alerts. Only verified, active owners/admins are eligible.

## Unpacked extension flow

1. In Chrome, open `chrome://extensions`, enable Developer mode, and load the unpacked `v2/extension` directory.
2. Copy the extension ID. Set `EXTENSION_REDIRECT_URIS` in the untracked `v2/.env` to exactly `https://<extension-id>.chromiumapp.org/`, then restart the API and worker.
3. From the extension popup, connect the verified test account, select its organization, and approve access.
4. Review an HTTPS link. Confirm it produces a scan and, for a high-priority indicator, the same dashboard case and email behavior as a website scan.
5. Disconnect from the extension, then confirm its scan request is rejected until it is connected again. The extension preview must not replace or be uploaded over the published extension.

The local analyzer is a passive URL-structure check. It makes no outbound URL requests and does not query Have I Been Pwned or another threat-intelligence provider, so results are indicators for review, not a malicious/safe verdict.

## Report a local issue

Include the page or extension action, expected behavior, actual behavior, browser console or API response, and relevant Mailpit message. Redact access tokens, passwords, real customer URLs, and SMTP values before sharing logs.
