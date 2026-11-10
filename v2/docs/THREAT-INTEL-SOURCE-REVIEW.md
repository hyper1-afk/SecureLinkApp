# Threat intelligence source review

Reviewed 2026-11-10. This review is a product and engineering gate, not legal advice.

## Decision

Do not ship an external phishing feed integration until SecureLink has confirmed the current commercial-use, redistribution, attribution, and retention terms for the chosen source. No customer-submitted URL is sent to a feed provider in the current V2 scanner. No Have I Been Pwned integration or paid HIBP key is used.

The V2 foundation now supports organization-managed exact-host indicators. Organization owners/admins control these entries, changes are audited, matches are tenant-scoped and exact (no implicit subdomain expansion), and a match creates a medium-severity review finding. It is evidence supplied by that organization, not a global reputation verdict. This is useful for customer-provided reports and does not require an external intelligence license.

## Sources checked

- [URLhaus Community API](https://urlhaus.abuse.ch/api) requires an auth key and says commercial or for-profit needs may require a paid enhanced API. This is not a safe assumed-free dependency for a commercial product.
- [URLhaus Terms of Use](https://abuse.ch/terms-of-use/) must be evaluated before commercial product use or redistribution.
- [PhishTank Terms of Use](https://phishtank.org/terms.php) states that its current governing terms are Cisco's EULA and presents older terms as archived. The archived text allows commercial use of defined Data, but it does not resolve whether current Cisco terms preserve that permission for SecureLink's feed ingestion, caching, and customer-facing matches.
- [PhishTank API documentation](https://phishtank.org/api_info.php) supports URL lookups, meaning a per-scan API integration would disclose submitted URLs. The documentation also points frequent users toward local data copies. A local feed can avoid disclosing submitted URLs but still needs a confirmed right to ingest and serve the data commercially.

## Follow-up gate

Before enabling a feed adapter, obtain and record current written terms or counsel's approval for commercial service use, caching/retention, derivative indicators, attribution, and customer-facing results. Then add a bounded importer with freshness/expiry tracking, provenance, feed health monitoring, tenant-safe match behavior, and tests for stale or revoked indicators. A source becoming unavailable must never turn into a clean/safe verdict.
