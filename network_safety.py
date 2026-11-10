"""Small, pinned-network helpers for legacy user-supplied domain probes."""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass


class UnsafeTargetError(ValueError):
    """Raised when a target is not a public, routable host."""


@dataclass(frozen=True)
class PublicAddress:
    family: int
    socktype: int
    protocol: int
    sockaddr: tuple


@dataclass(frozen=True)
class PublicHTTPResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    text: str


def _normalize_host(host: str) -> str:
    host = host.strip().strip("[]").rstrip(".")
    if not host or any(char in host for char in ("%", "\x00", "\r", "\n", "/", "@")):
        raise UnsafeTargetError("Invalid target host")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        try:
            normalized = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise UnsafeTargetError("Invalid target hostname") from exc
        if len(normalized) > 253 or not re.fullmatch(r"[a-z0-9.-]+", normalized):
            raise UnsafeTargetError("Invalid target hostname")
        labels = normalized.split(".")
        if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
            raise UnsafeTargetError("Invalid target hostname")
        return normalized


def _require_global_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError as exc:
        raise UnsafeTargetError("Target resolved to an invalid IP address") from exc
    if not address.is_global:
        raise UnsafeTargetError("Target is not globally routable")
    return address


def resolve_public_addresses(host: str, port: int) -> list[PublicAddress]:
    """Resolve once, reject any non-public answer, and return pinned socket addresses."""
    normalized = _normalize_host(host)
    try:
        literal = ipaddress.ip_address(normalized)
    except ValueError:
        literal = None

    if literal is not None:
        address = _require_global_ip(str(literal))
        if address.version == 4:
            return [PublicAddress(socket.AF_INET, socket.SOCK_STREAM, 0, (str(address), port))]
        return [PublicAddress(socket.AF_INET6, socket.SOCK_STREAM, 0, (str(address), port, 0, 0))]

    try:
        resolved = socket.getaddrinfo(normalized, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise UnsafeTargetError("Target could not be resolved") from exc
    if not resolved or len(resolved) > 16:
        raise UnsafeTargetError("Target has no usable public addresses")

    addresses: list[PublicAddress] = []
    seen: set[tuple] = set()
    for family, socktype, protocol, _, sockaddr in resolved:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        address = _require_global_ip(sockaddr[0])
        if address.version != (4 if family == socket.AF_INET else 6):
            raise UnsafeTargetError("Target address family mismatch")
        key = (family, sockaddr)
        if key not in seen:
            seen.add(key)
            addresses.append(PublicAddress(family, socktype, protocol, sockaddr))

    if not addresses:
        raise UnsafeTargetError("Target has no usable public addresses")
    return addresses


def connect_public_target(host: str, port: int, timeout: float = 5) -> socket.socket:
    """Connect directly to a vetted IP so DNS cannot change between check and connect."""
    addresses = resolve_public_addresses(host, port)
    last_error: OSError | None = None
    for address in addresses:
        connection = socket.socket(address.family, address.socktype, address.protocol)
        connection.settimeout(timeout)
        try:
            connection.connect(address.sockaddr)
            return connection
        except OSError as exc:
            last_error = exc
            connection.close()
    if last_error is not None:
        raise last_error
    raise UnsafeTargetError("Target has no usable public addresses")


def _read_bounded_body(reader, headers: dict[str, str], max_body_bytes: int) -> bytes:
    transfer_encoding = headers.get("transfer-encoding", "").lower()
    if "chunked" in transfer_encoding:
        body = bytearray()
        total = 0
        while total <= max_body_bytes:
            line = reader.readline(128)
            total += len(line)
            if not line.endswith(b"\n") or total > 8192:
                raise OSError("Invalid chunked response")
            try:
                chunk_size = int(line.split(b";", 1)[0].strip(), 16)
            except ValueError as exc:
                raise OSError("Invalid chunked response") from exc
            if chunk_size == 0:
                while True:
                    trailer = reader.readline(8192)
                    total += len(trailer)
                    if not trailer or total > 32768 or trailer in (b"\r\n", b"\n"):
                        break
                return bytes(body)
            if len(body) + chunk_size > max_body_bytes:
                return bytes(body)
            chunk = reader.read(chunk_size)
            if len(chunk) != chunk_size:
                raise OSError("Incomplete chunked response")
            body.extend(chunk)
            total += chunk_size
            ending = reader.read(2)
            total += len(ending)
            if ending != b"\r\n":
                raise OSError("Invalid chunked response")
        return bytes(body)

    content_length = headers.get("content-length")
    if content_length is not None:
        try:
            length = int(content_length)
        except ValueError as exc:
            raise OSError("Invalid response length") from exc
        if length < 0:
            raise OSError("Invalid response length")
        return reader.read(min(length, max_body_bytes))
    return reader.read(max_body_bytes)


def public_http_get(
    host: str,
    scheme: str,
    *,
    timeout: float = 5,
    max_body_bytes: int = 10000,
) -> PublicHTTPResponse:
    """Fetch only `/` from a public host, without following redirects or using proxies."""
    scheme = scheme.lower()
    if scheme not in {"http", "https"}:
        raise UnsafeTargetError("Unsupported target scheme")
    normalized = _normalize_host(host)
    port = 443 if scheme == "https" else 80
    connection = connect_public_target(normalized, port, timeout=timeout)
    reader = None
    try:
        if scheme == "https":
            context = ssl.create_default_context()
            connection = context.wrap_socket(connection, server_hostname=normalized)

        authority = f"[{normalized}]" if ":" in normalized else normalized
        connection.sendall(
            (
                f"GET / HTTP/1.1\r\n"
                f"Host: {authority}\r\n"
                "User-Agent: SecureLink-Scanner/1.0\r\n"
                "Accept: text/html,application/xhtml+xml,*/*;q=0.1\r\n"
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
        )
        reader = connection.makefile("rb")
        status_line = reader.readline(8192)
        if not status_line.endswith(b"\n"):
            raise OSError("Invalid HTTP status line")
        try:
            status_parts = status_line.decode("iso-8859-1").rstrip("\r\n").split(" ", 2)
            version, status = status_parts[:2]
            status_code = int(status)
        except (ValueError, UnicodeDecodeError) as exc:
            raise OSError("Invalid HTTP status line") from exc
        if not version.startswith("HTTP/") or not 100 <= status_code <= 599:
            raise OSError("Invalid HTTP status line")

        headers: dict[str, str] = {}
        header_bytes = 0
        header_count = 0
        while True:
            line = reader.readline(8192)
            header_bytes += len(line)
            if not line.endswith(b"\n") or header_bytes > 32768:
                raise OSError("HTTP headers exceed limits")
            if line in (b"\r\n", b"\n"):
                break
            header_count += 1
            if header_count > 100 or line[:1] in (b" ", b"\t") or b":" not in line:
                raise OSError("Invalid HTTP headers")
            name, value = line.split(b":", 1)
            header_name = name.decode("ascii", "strict").strip().lower()
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]+", header_name):
                raise OSError("Invalid HTTP header name")
            header_value = value.decode("iso-8859-1").strip()
            if "\r" in header_value or "\n" in header_value:
                raise OSError("Invalid HTTP header value")
            if header_name in headers:
                headers[header_name] += ", " + header_value
            else:
                headers[header_name] = header_value

        body = _read_bounded_body(reader, headers, max_body_bytes)
        return PublicHTTPResponse(
            url=f"{scheme}://{authority}/",
            status_code=status_code,
            headers=headers,
            text=body.decode("utf-8", "replace"),
        )
    finally:
        if reader is not None:
            reader.close()
        connection.close()
