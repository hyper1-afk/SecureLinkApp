# Safe URL scan boundary

The scan API is deliberately passive: it parses and normalizes the submitted URL, creates tenant-scoped evidence, and emits deterministic URL hygiene findings. The API process does not resolve the URL, open a socket to its destination, follow redirects, fetch page content, or send the submitted URL to a reputation or AI provider. A separate worker downloads only Spamhaus's published DROP CIDR files from fixed HTTPS URLs. The API compares a literal public IP in a submitted URL against the current local snapshot; it never resolves a submitted hostname for this check.

The API stores only the normalized hostname, scheme, a display URL with path/query/fragment/credentials omitted, and structured booleans. It does not persist the submitted URL or query values. Evidence and findings have organization-scoped database constraints; PostgreSQL rejects scan-evidence updates and deletes.

## What the findings mean

Findings identify URL properties such as embedded credentials, unencrypted HTTP, local/non-global IP destinations, internationalized hostnames, sensitive parameter names, redirect-style parameters, and a current Spamhaus DROP match for a literal public IP. A redirect-style parameter is only a heuristic; it does not prove an open redirect. DROP covers a limited set of highly malicious IP networks; it is not a phishing URL or domain reputation service. Its source, date, CIDR, and SBL reference are retained as evidence. A stale or unavailable feed creates no match. An empty finding list is not a safety verdict.

## Requirements before active scanning

Do not add URL fetching to the API process. Any future page inspection or redirect resolution requires a separately isolated worker with enforced egress controls, destination-IP pinning, DNS rebinding defenses, redirect revalidation, response-size/time limits, content-type restrictions, resource quotas, and per-tenant authorization. Integrate reputation providers through fixed provider endpoints, never by fetching arbitrary submitted URLs. Add security review and SSRF tests before enabling active scanning.

