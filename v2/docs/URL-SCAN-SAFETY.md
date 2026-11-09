# Safe URL scan boundary

The current scan API is deliberately **passive**. It parses and normalizes the submitted URL, creates tenant-scoped evidence, and emits deterministic URL hygiene findings. It does not resolve DNS, open sockets, follow redirects, fetch page content, query third-party reputation providers, or send data to an AI provider. This removes user-controlled outbound requests from the API process for this milestone.

The API stores only the normalized hostname, scheme, a display URL with path/query/fragment/credentials omitted, and structured booleans. It does not persist the submitted URL or query values. Evidence and findings have organization-scoped database constraints; PostgreSQL rejects scan-evidence updates and deletes.

## What the findings mean

Findings identify URL properties such as embedded credentials, unencrypted HTTP, local/non-global IP destinations, internationalized hostnames, sensitive parameter names, and redirect-style parameters. A redirect-style parameter is only a heuristic; it does not prove an open redirect. The engine does not claim that a URL is clean, malicious, or reputation-checked. An empty finding list is not a safety verdict.

## Requirements before active scanning

Do not add URL fetching to the API process. Any future page inspection or redirect resolution requires a separately isolated worker with enforced egress controls, destination-IP pinning, DNS rebinding defenses, redirect revalidation, response-size/time limits, content-type restrictions, resource quotas, and per-tenant authorization. Integrate reputation providers through fixed provider endpoints, never by fetching arbitrary submitted URLs. Add security review and SSRF tests before enabling active scanning.
