# Threat intelligence source review

Reviewed 2026-11-10. This review is a product and engineering gate, not legal advice.

## Decision

Do not ship an external phishing feed integration until SecureLink has confirmed the current commercial-use, redistribution, attribution, and retention terms for the chosen source. No customer-submitted URL is sent to a feed provider in the current V2 scanner. No Have I Been Pwned integration or paid HIBP key is used.

The V2 foundation now supports organization-managed exact-host indicators. Organization owners/admins control these entries, changes are audited, matches are tenant-scoped and exact (no implicit subdomain expansion), and a match creates a medium-severity review finding. It is evidence supplied by that organization, not a global reputation verdict. This is useful for customer-provided reports and does not require an external intelligence license.

The legacy verifier previously called Google Safe Browsing when `GOOGLE_SAFE_BROWSING_API_KEY` was configured. That integration and configuration have been removed from this development branch: Google's Safe Browsing API is restricted to non-commercial use unless a separate agreement is in place. Do not put a rotated key into SecureLink or re-enable that provider for the commercial service without written authorization. A future commercial provider must be evaluated separately for URL disclosure, retention, attribution, pricing, and hard spending limits. Google Web Risk's Lookup API advertises up to 100,000 free calls per month, with paid usage above that tier; it is not configured here and must not be enabled without a quota/billing cap.

The legacy verifier's VirusTotal integration has also been removed from this branch. VirusTotal documents that its public API may not be used in commercial products or services; reintroducing a paid/private API requires a valid agreement and review of URL submission and retention terms. The legacy AbuseIPDB and URLhaus feed integrations have also been removed; AbuseIPDB's terms prohibit commercial use of its Free/Individual plans, and URLhaus commercial ingestion/redistribution terms have not been confirmed. Reintroducing either source requires documented commercial rights and rate/cost controls.

## Sources checked

- [URLhaus Community API](https://urlhaus.abuse.ch/api) requires an auth key and says commercial or for-profit needs may require a paid enhanced API. This is not a safe assumed-free dependency for a commercial product.
- [URLhaus Terms of Use](https://abuse.ch/terms-of-use/) must be evaluated before commercial product use or redistribution.
- [PhishTank Terms of Use](https://phishtank.org/terms.php) states that its current governing terms are Cisco's EULA and presents older terms as archived. The archived text allows commercial use of defined Data, but it does not resolve whether current Cisco terms preserve that permission for SecureLink's feed ingestion, caching, and customer-facing matches.
- [PhishTank API documentation](https://phishtank.org/api_info.php) supports URL lookups, meaning a per-scan API integration would disclose submitted URLs. The documentation also points frequent users toward local data copies. A local feed can avoid disclosing submitted URLs but still needs a confirmed right to ingest and serve the data commercially.
- [Google Safe Browsing API usage restrictions](https://developers.google.com/safe-browsing/v4/usage-limits) limit use to non-commercial applications. [Google's terms](https://developers.google.com/safe-browsing/terms) prohibit commercial use absent a separate agreement. [Web Risk pricing](https://cloud.google.com/web-risk/pricing) documents the free Lookup API tier and paid overage.
- [VirusTotal Public API documentation](https://docs.virustotal.com/reference/getting-started) prohibits use in commercial products/services; its [public-versus-private API guidance](https://docs.virustotal.com/v2.0/reference/public-vs-private-api) says commercial use requires its private API arrangement.
- [AbuseIPDB Legal Information](https://www.abuseipdb.com/legal.html) states that Free/Individual plans are for non-commercial projects and that commercial use requires a Basic or higher paid plan.

## Follow-up gate

Before enabling a feed adapter, obtain and record current written terms or counsel's approval for commercial service use, caching/retention, derivative indicators, attribution, and customer-facing results. Then add a bounded importer with freshness/expiry tracking, provenance, feed health monitoring, tenant-safe match behavior, and tests for stale or revoked indicators. A source becoming unavailable must never turn into a clean/safe verdict.
