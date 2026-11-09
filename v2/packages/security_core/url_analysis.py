from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

PARSER_VERSION = "url-hygiene-v1"
SENSITIVE_QUERY_KEYS = {
    "access_token", "auth", "authorization", "code", "key", "password",
    "secret", "session", "sessionid", "token",
}
REDIRECT_QUERY_KEYS = {"continue", "next", "redirect", "redirect_uri", "return", "returnto", "url"}
DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class InvalidScanURL(ValueError):
    pass


@dataclass(frozen=True)
class FindingDraft:
    detector_code: str
    severity: str
    title: str
    description: str


@dataclass(frozen=True)
class URLAnalysis:
    display_url: str
    hostname: str
    scheme: str
    evidence: dict[str, object]
    findings: tuple[FindingDraft, ...]


def analyze_url(raw_url: str) -> URLAnalysis:
    if len(raw_url) > 2048 or not raw_url:
        raise InvalidScanURL("URL must be between 1 and 2048 characters")
    if any(ord(char) < 0x20 or char.isspace() for char in raw_url):
        raise InvalidScanURL("URL contains whitespace or control characters")
    try:
        parsed = urlsplit(raw_url)
        scheme = parsed.scheme.casefold()
        hostname_input = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise InvalidScanURL("URL syntax is invalid") from exc
    if scheme not in {"http", "https"} or hostname_input is None or not parsed.netloc:
        raise InvalidScanURL("Only absolute HTTP and HTTPS URLs are supported")

    hostname_input = hostname_input.rstrip(".")
    if not hostname_input:
        raise InvalidScanURL("URL hostname is invalid")
    ip_address = None
    try:
        ip_address = ipaddress.ip_address(hostname_input)
        hostname = ip_address.compressed.lower()
    except ValueError:
        try:
            hostname = hostname_input.encode("idna").decode("ascii").casefold()
        except UnicodeError as exc:
            raise InvalidScanURL("URL hostname is invalid") from exc
        labels = hostname.split(".")
        if len(hostname) > 253 or any(not DNS_LABEL.fullmatch(label) for label in labels):
            raise InvalidScanURL("URL hostname is invalid")
    if port is not None and not 1 <= port <= 65535:
        raise InvalidScanURL("URL port is invalid")

    query_keys: set[str] = set()
    try:
        for key, _value in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=64):
            query_keys.add(key.casefold())
    except ValueError as exc:
        raise InvalidScanURL("URL has too many query parameters") from exc

    has_credentials = parsed.username is not None or parsed.password is not None
    is_idn = not hostname_input.isascii() or any(label.startswith("xn--") for label in hostname.split("."))
    is_non_global_ip = ip_address is not None and not ip_address.is_global
    is_local_hostname = hostname == "localhost" or hostname.endswith((".localhost", ".local", ".internal"))
    sensitive_query_present = bool(query_keys & SENSITIVE_QUERY_KEYS) or any(
        key.endswith(("_token", "_secret", "_password")) for key in query_keys
    )
    redirect_parameter_present = bool(query_keys & REDIRECT_QUERY_KEYS)

    display_host = f"[{hostname}]" if isinstance(ip_address, ipaddress.IPv6Address) else hostname
    default_port = 80 if scheme == "http" else 443
    port_suffix = f":{port}" if port is not None and port != default_port else ""
    display_url = f"{scheme}://{display_host}{port_suffix}/[path and query omitted]"
    evidence: dict[str, object] = {
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "credentials_present": has_credentials,
        "sensitive_query_present": sensitive_query_present,
        "redirect_parameter_present": redirect_parameter_present,
        "fragment_present": bool(parsed.fragment),
        "internationalized_hostname": is_idn,
        "non_global_ip_literal": is_non_global_ip,
        "local_hostname": is_local_hostname,
        "network_requests_made": False,
    }
    findings: list[FindingDraft] = []
    if has_credentials:
        findings.append(FindingDraft(
            "credentials_in_url", "high", "Credentials embedded in URL",
            "The submitted URL contains user information. Remove it and rotate any exposed credentials.",
        ))
    if scheme == "http":
        findings.append(FindingDraft(
            "plaintext_transport", "medium", "URL uses unencrypted HTTP",
            "The URL uses HTTP, so requests to it would not be protected by TLS.",
        ))
    if is_non_global_ip or is_local_hostname:
        findings.append(FindingDraft(
            "non_public_destination", "high", "URL points to a non-public destination",
            "The hostname is a local name or non-global IP literal. SecureLink did not connect to it.",
        ))
    if is_idn:
        findings.append(FindingDraft(
            "internationalized_hostname", "informational", "Internationalized hostname",
            "The hostname uses internationalized characters and should be checked for lookalike characters.",
        ))
    if sensitive_query_present:
        findings.append(FindingDraft(
            "sensitive_query_parameter", "informational", "Potentially sensitive query parameter",
            "A sensitive parameter name was detected. Query names and values were not retained.",
        ))
    if redirect_parameter_present:
        findings.append(FindingDraft(
            "redirect_parameter", "informational", "Redirect-style parameter present",
            "The URL contains a parameter commonly used for redirects. This alone does not establish an open redirect.",
        ))
    return URLAnalysis(display_url, hostname, scheme, evidence, tuple(findings))


def evidence_hash(evidence: dict[str, object]) -> str:
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
