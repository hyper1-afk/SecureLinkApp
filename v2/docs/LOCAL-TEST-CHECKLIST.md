# SecureLink V2 local browser check

This checklist exercises the local V2 website, API, email queue, and unpacked extension without touching the published site or extension.

## Start the local stack

1. Follow the development setup in [the V2 README](../README.md), including `python scripts/init_local_env.py` and `docker compose --profile local-mail up --build` from `v2/`.
2. Open `http://localhost:8000/` for registration and account actions. The authenticated organization dashboard is at `http://localhost:8000/dashboard`; it is a separate page from the account form.
3. Open `http://localhost:8025/` for Mailpit. Use only test addresses and fake URL credentials.

## Website, scan, and alert flow

1. Register a test account and verify it through the message captured in Mailpit. Sign in. The account page should show that the owner role requires MFA within seven days; enroll an authenticator and save the one-time recovery codes before continuing.
2. Submit `https://demo-user:demo-password@example.com/private?token=demo-value` in **Inspect a link**.
3. Confirm the result displays only `https://example.com/[path and query omitted]`, and that a high-priority case appears in **Cases** without manually opening it.
4. Confirm an alert email is captured in Mailpit. It should identify the organization, severity, hostname, case ID, and dashboard link. It must not contain `demo-user`, `demo-password`, `/private`, or `demo-value`.
   In the dashboard's **Priority email alerts** panel, select **Refresh delivery status**; it should show zero pending and zero failed after Mailpit accepts the message.
5. Turn off **Email me about high-priority cases**, submit another URL with a fake credential or sensitive query indicator, and confirm no new alert arrives for that account. The preference change should be reflected after reloading the dashboard.
6. A viewer/analyst can change their own preference but should not receive organization priority alerts. Only verified, active owners/admins are eligible.

## Unpacked extension flow

1. In Chrome, open `chrome://extensions`, enable Developer mode, and load the unpacked `v2/extension` directory.
2. Copy the extension ID. Set `EXTENSION_REDIRECT_URIS` in the untracked `v2/.env` to exactly `https://<extension-id>.chromiumapp.org/`, then restart the API and worker.
3. From the extension popup, connect the verified test account, select its organization, and approve access.
4. Review an HTTPS link. Confirm it produces a scan and, for a high-priority indicator, the same dashboard case and email behavior as a website scan.
5. Disconnect from the extension, then confirm its scan request is rejected until it is connected again. The extension preview must not replace or be uploaded over the published extension.

## Opt-in domain DNS monitoring

1. Add a test domain you control, publish its one-time TXT challenge, and verify ownership.
2. Confirm monitoring is initially paused. As an owner/admin, enable **SPF and DMARC DNS monitoring** for the verified domain; check the local worker logs for errors without including secrets.
3. Confirm DNS observations appear in **Security signals**, unchanged findings are not duplicated on each check, and high-priority findings create a case and Mailpit message.
4. Pause monitoring and confirm no later checks run for that domain. Do not enable it for a domain that does not send email unless missing SPF/DMARC records are expected findings.

The worker queries only the domain's SPF and `_dmarc` TXT records. It does not connect to discovered IP addresses, fetch web pages, or use paid Have I Been Pwned APIs.

The local analyzer is a passive URL-structure check. It makes no outbound URL requests and does not query Have I Been Pwned or another threat-intelligence provider, so results are indicators for review, not a malicious/safe verdict.

## Report a local issue

Include the page or extension action, expected behavior, actual behavior, browser console or API response, and relevant Mailpit message. Redact access tokens, passwords, real customer URLs, and SMTP values before sharing logs.
