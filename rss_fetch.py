"""DNS-pinned direct feed fetcher, isolated from both existing proxy routes.

The URL sent to HTTPX contains only a validated IP. HTTPcore's sni_hostname
extension restores the original TLS server name (including certificate hostname
verification); Host is set separately. A new non-pooling client per hop prevents
cross-host TLS reuse and cookie propagation. No inbound headers are accepted. XML/feed validation is left to the caller.

Verified with HTTPX 0.28.1 / HTTPcore 1.0.9, including real TLS handshakes.
See https://www.encode.io/httpcore/extensions/#sni_hostname and
httpcore/_async/connection.py (1.0.9), httpx/_transports/default.py (0.28.1).
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
from urllib.parse import urlsplit

import httpx
from starlette.responses import JSONResponse, Response

MAX_BYTES = 16 * 1024 * 1024
TOTAL_TIMEOUT = 30.0
MAX_REDIRECTS = 5
# Match PodPie's conservative special-purpose policy across Python versions.
_SPECIAL_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "192.0.0.0/24",
        "192.88.99.0/24",
        "2001::/23",
        "3ffe::/16",
        "3fff::/20",
    )
)


class InvalidDestinationError(ValueError):
    """Destination failed the public-feed policy."""


def _public_ip(value: str) -> str:
    ip = ipaddress.ip_address(value)
    if (
        not ip.is_global
        or any(ip in network for network in _SPECIAL_NETWORKS)
        or ip.is_multicast
        or ip.is_reserved
        or getattr(ip, "is_site_local", False)
        or getattr(ip, "ipv4_mapped", None) is not None
        or getattr(ip, "sixtofour", None) is not None
        or getattr(ip, "teredo", None) is not None
        or ip in ipaddress.ip_network("64:ff9b::/96")
        or ip in ipaddress.ip_network("64:ff9b:1::/48")
    ):
        raise InvalidDestinationError
    return str(ip)


def _safe_url_text(value: str) -> None:
    # Reject controls and credentials BEFORE HTTPX normalizes them.
    if not value or len(value) > 8192 or re.search(r"[\s\\\x00-\x1f\x7f]", value):
        raise InvalidDestinationError
    try:
        if "@" in urlsplit(value).netloc:
            raise InvalidDestinationError
    except ValueError:
        raise InvalidDestinationError from None


def _target(value: str) -> httpx.URL:
    _safe_url_text(value)
    try:
        url = httpx.URL(value)
        if (
            url.scheme not in {"http", "https"}
            or not url.host
            or url.userinfo
            or url.port not in (None, 443 if url.scheme == "https" else 80)
            or "%" in url.host
        ):
            raise InvalidDestinationError
        host = url.raw_host.decode("ascii").rstrip(".")
        try:
            _public_ip(host)
        except ValueError:
            if ":" in host or re.fullmatch(r"[0-9.]+", host):
                raise InvalidDestinationError from None
            if (
                "." not in host
                or host.endswith(
                    (
                        ".localhost",
                        ".local",
                        ".internal",
                        ".localdomain",
                        ".home.arpa",
                        ".lan",
                        ".home",
                        ".onion",
                        ".invalid",
                        ".test",
                    )
                )
                or any(
                    not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                    for part in host.split(".")
                )
            ):
                raise InvalidDestinationError from None
        return url.copy_with(fragment=None)
    except (httpx.InvalidURL, ValueError, IndexError):
        raise InvalidDestinationError from None


async def _resolve(host: str, port: int) -> list[str]:
    answers = await asyncio.get_running_loop().getaddrinfo(
        host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
    )
    return [answer[4][0] for answer in answers]


async def _pinned_ip(url: httpx.URL) -> str:
    try:
        ipaddress.ip_address(url.host)
    except ValueError:
        addresses = await _resolve(
            url.raw_host.decode("ascii"), 443 if url.scheme == "https" else 80
        )
    else:
        addresses = [url.host]
    if not addresses:
        raise InvalidDestinationError
    # Validate the entire answer set, not just the selected address.
    try:
        validated = [_public_ip(address) for address in addresses]
    except ValueError:
        raise InvalidDestinationError from None
    return validated[0]


def _make_client() -> httpx.AsyncClient:
    # Explicit verified TLS and no environment proxies, retries or shared pools.
    transport = httpx.AsyncHTTPTransport(
        verify=ssl.create_default_context(),
        trust_env=False,
        retries=0,
        limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
    )
    return httpx.AsyncClient(
        transport=transport,
        trust_env=False,
        follow_redirects=False,
        timeout=httpx.Timeout(TOTAL_TIMEOUT),
    )


def _redirect(target: httpx.URL, location: str) -> httpx.URL:
    _safe_url_text(location)
    try:
        return _target(str(target.join(location)))
    except httpx.InvalidURL:
        raise InvalidDestinationError from None


async def _read_feed(upstream: httpx.Response) -> Response:
    if not 200 <= upstream.status_code < 300:
        return _error(502, "Feed fetch failed.")
    encoding = upstream.headers.get("content-encoding", "identity").strip().lower()
    if encoding != "identity":
        return _error(502, "Feed fetch failed.")
    declared = upstream.headers.get("content-length")
    if declared is not None:
        if not declared.isascii() or not declared.isdecimal():
            return _error(502, "Feed fetch failed.")
        if int(declared) > MAX_BYTES:
            return _error(413, "Feed is too large.")
    body = bytearray()
    # Identity encoding only: no decompressor can expand these chunks.
    async for chunk in upstream.aiter_bytes(chunk_size=64 * 1024):
        if len(body) + len(chunk) > MAX_BYTES:
            return _error(413, "Feed is too large.")
        body.extend(chunk)
    return Response(
        bytes(body),
        media_type="application/xml",
        headers={
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": 'attachment; filename="feed.xml"',
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "no-store",
        },
    )


async def _fetch(url: str) -> Response:
    target = _target(url)
    require_https = target.scheme == "https"
    for hop in range(MAX_REDIRECTS + 1):
        if require_https and target.scheme != "https":
            raise InvalidDestinationError
        require_https = require_https or target.scheme == "https"
        address = await _pinned_ip(target)
        hostname = target.raw_host.decode("ascii")
        host = f"[{hostname}]" if ":" in hostname else hostname
        async with (
            _make_client() as client,
            client.stream(
                "GET",
                target.copy_with(host=address),
                headers={
                    "Host": host,
                    "Accept-Encoding": "identity",
                    "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml",
                },
                extensions={"sni_hostname": hostname},
            ) as upstream,
        ):
            if (
                upstream.headers.get("content-encoding", "identity").strip().lower()
                != "identity"
            ):
                return _error(502, "Feed fetch failed.")
            if upstream.status_code in {301, 302, 303, 307, 308}:
                location = upstream.headers.get("location")
                if hop == MAX_REDIRECTS or not location:
                    return _error(502, "Feed fetch failed.")
                # Join against the ORIGINAL host, never against the pinned IP.
                # Inspect the raw redirect before HTTPX can normalize controls.
                target = _redirect(target, location)
                continue
            return await _read_feed(upstream)
    return _error(502, "Feed fetch failed.")  # pragma: no cover


def _error(status: int, detail: str) -> Response:
    return JSONResponse({"detail": detail}, status_code=status)


async def fetch_feed(url: str) -> Response:
    """Fetch over direct egress, returning only bytes, never upstream headers."""
    try:
        return await asyncio.wait_for(_fetch(url), timeout=TOTAL_TIMEOUT)
    except (asyncio.TimeoutError, TimeoutError, httpx.TimeoutException):
        return _error(504, "Feed fetch timed out.")
    except InvalidDestinationError:
        return _error(400, "Invalid feed destination.")
    except (httpx.HTTPError, OSError, ValueError):
        return _error(502, "Feed fetch failed.")
