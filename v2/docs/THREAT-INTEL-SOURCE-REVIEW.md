# Threat intelligence source review

Reviewed 2026-11-10. This review is a product and engineering gate, not legal advice.

## Decision

Use Spamhaus DROP as a narrow, locally cached network-range indicator. Spamhaus says DROP is free for use in any product with attribution and the copyright text/date retained with the data. It also requires automated updates, recommends daily refresh, and prohibits fetching more often than hourly. The V2 worker follows the stricter daily cadence, stores attribution and source dates, expires data at the feed's published 26-hour window, and performs matching locally. It checks only literal public IP URLs: it does not resolve submitted hostnames or disclose URLs to Spamhaus. A match is a high-priority review indicator, not proof about page content; the feed is a small subset of hostile IP ranges, not a phishing URL or domain feed. No Have I Been Pwned integration or paid HIBP key is used.

The V2 foundation also supports organization-managed exact-host indicators. Organization owners/admins control these entries, changes are audited, matches are tenant-scoped and exact (no implicit subdomain expansion), and a match creates a medium-severity review finding. It is evidence supplied by that organization, not a global reputation verdict.

The legacy verifier previously called Google Safe Browsing when `GOOGLE_SAFE_BROWSING_API_KEY` was configured. That integration and configuration have been removed from this development branch: Google's Safe Browsing API is restricted to non-commercial use unless a separate agreement is in place. Do not put a rotated key into SecureLink or re-enable that provider for the commercial service without written authorization. A future commercial provider must be evaluated separately for URL disclosure, retention, attribution, pricing, and hard spending limits. Google Web Risk's Lookup API advertises up to 100,000 free calls per month, with paid usage above that tier; it is not configured here and must not be enabled without a quota/billing cap.

The legacy verifier's VirusTotal integration has also been removed from this branch. VirusTotal documents that its public API may not be used in commercial products or services; reintroducing a paid/private API requires a valid agreement and review of URL submission and retention terms. The legacy AbuseIPDB and URLhaus feed integrations have also been removed; AbuseIPDB's terms prohibit commercial use of its Free/Individual plans, and URLhaus commercial ingestion/redistribution terms have not been confirmed. Reintroducing either source requires documented commercial rights and rate/cost controls.

## Sources checked

- [Spamhaus DROP usage FAQ](https://www.spamhaus.org/faqs/do-not-route-or-peer-drop/) says the data is open to download and use without a fee, requires product credit and preservation of the date/copy text, recommends automated daily updates, and prohibits downloads more often than once per hour. The scope is dangerous IP network ranges; DROP should enhance, not replace, broader protection.
- [Spamhaus DROP list](https://www.spamhaus.org/drop/) describes the list as highly malicious networks used for malware, trojans, botnet controllers, and related activity. This source does not provide full URL or phishing-domain reputation.
- [URLhaus Community API](https://urlhaus.abuse.ch/api) requires an auth key and says commercial or for-profit needs may require a paid enhanced API. This is not a safe assumed-free dependency for a commercial product.
- [URLhaus Terms of Use](https://abuse.ch/terms-of-use/) must be evaluated before commercial product use or redistribution.
- [PhishTank Terms of Use](https://phishtank.org/terms.php) states that its current governing terms are Cisco's EULA and presents older terms as archived. The archived text allows commercial use of defined Data, but it does not resolve whether current Cisco terms preserve that permission for SecureLink's feed ingestion, caching, and customer-facing matches.
- [PhishTank API documentation](https://phishtank.org/api_info.php) supports URL lookups, meaning a per-scan API integration would disclose submitted URLs. The documentation also points frequent users toward local data copies. A local feed can avoid disclosing submitted URLs but still needs a confirmed right to ingest and serve the data commercially.
- [Google Safe Browsing API usage restrictions](https://developers.google.com/safe-browsing/v4/usage-limits) limit use to non-commercial applications. [Google's terms](https://developers.google.com/safe-browsing/terms) prohibit commercial use absent a separate agreement. [Web Risk pricing](https://cloud.google.com/web-risk/pricing) documents the free Lookup API tier and paid overage.
- [VirusTotal Public API documentation](https://docs.virustotal.com/reference/getting-started) prohibits use in commercial products/services; its [public-versus-private API guidance](https://docs.virustotal.com/v2.0/reference/public-vs-private-api) says commercial use requires its private API arrangement.
- [AbuseIPDB Legal Information](https://www.abuseipdb.com/legal.html) states that Free/Individual plans are for non-commercial projects and that commercial use requires a Basic or higher paid plan.

## Operational limits

The Spamhaus integration is limited to IP-literal URL checks. Expired or unavailable data produces no match and never implies a URL is safe. Feed retrieval and validation are isolated in a worker, and the feed worker's database credential should have access only to the feed snapshot and sync-state tables. Monitor worker restarts and stale snapshots before staging acceptance. Before enabling another provider, separately confirm commercial rights, caching/retention, attribution, URL disclosure, and pricing/cost limits.

