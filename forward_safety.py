"""Shared preconnection destination validation for the standalone app.

HTTPX/httpcore versions are pinned in requirements.txt. Each hop gets a fresh
non-pooling transport: numeric socket/CONNECT target, original Host and verified
TLS name. The caller retains the logical URL for HTTPX redirect handling.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
from collections.abc import AsyncIterator, Iterable
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx
from httpcore._backends.base import SOCKET_OPTION

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
    """Destination failed the public outbound policy."""


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
        raise InvalidDestinationError("Invalid outbound destination.")
    return str(ip)


def _safe_url_text(value: str) -> None:
    # Reject controls and credentials BEFORE HTTPX normalizes them.
    if not value or re.search(r"[\s\\\x00-\x1f\x7f]", value):
        raise InvalidDestinationError("Invalid outbound destination.")
    try:
        if "@" in urlsplit(value).netloc:
            raise InvalidDestinationError("Invalid outbound destination.")
    except ValueError:
        raise InvalidDestinationError from None


def destination_url(value: str) -> httpx.URL:
    """Validate URL syntax before HTTPX can erase raw credentials or controls."""
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
            raise InvalidDestinationError("Invalid outbound destination.")
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
        raise InvalidDestinationError("Invalid outbound destination.")
    # Validate the entire answer set, not just the selected address.
    try:
        validated = [_public_ip(address) for address in addresses]
    except ValueError:
        raise InvalidDestinationError from None
    return validated[0]


class _TunnelTLSStream(httpcore.AsyncNetworkStream):
    """Restore the verified origin TLS name after a numeric HTTP CONNECT.

    HTTPcore 1.0.9's tunnel ignores sni_hostname and uses remote_origin.host.
    Only HTTP upstream proxies are supported, so this stream's first TLS
    handshake is always the origin's, never an HTTPS proxy's handshake.
    """

    def __init__(
        self, stream: httpcore.AsyncNetworkStream, hostname: str, address: str
    ) -> None:
        self.stream = stream
        self.hostname = hostname
        self.address = address

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self.stream.read(max_bytes, timeout=timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        # HTTPcore 1.0.9 emits an unbracketed IPv6 CONNECT authority. h11 sends
        # this header block in one write; fix only the exact pinned authority.
        bare = f"{self.address}:443".encode("ascii")
        bracketed = f"[{self.address}]:443".encode("ascii")
        if ":" in self.address and buffer.startswith(
            b"CONNECT " + bare + b" HTTP/1.1\r\n"
        ):
            buffer = buffer.replace(b"CONNECT " + bare, b"CONNECT " + bracketed, 1)
            buffer = buffer.replace(
                b"\r\nHost: " + bare + b"\r\n", b"\r\nHost: " + bracketed + b"\r\n", 1
            )
        await self.stream.write(buffer, timeout=timeout)

    async def aclose(self) -> None:
        await self.stream.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del server_hostname  # HTTPcore supplies the numeric CONNECT target; restore origin name.
        return await self.stream.start_tls(
            ssl_context, server_hostname=self.hostname, timeout=timeout
        )

    def get_extra_info(self, info: str) -> Any:
        return self.stream.get_extra_info(info)


class _TunnelTLSBackend(httpcore.AsyncNetworkBackend):
    """Bind a TLS hostname to one hop, without shared client or task-local state."""

    def __init__(
        self, backend: httpcore.AsyncNetworkBackend, hostname: str, address: str
    ) -> None:
        self.backend = backend
        self.hostname = hostname
        self.address = address

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        stream = await self.backend.connect_tcp(
            host,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )
        return _TunnelTLSStream(stream, self.hostname, self.address)

    async def sleep(self, seconds: float) -> None:
        await self.backend.sleep(seconds)


class _ResponseStream(httpx.AsyncByteStream):
    """Keep a per-hop transport alive until its response stream closes."""

    def __init__(
        self,
        stream: httpx.AsyncByteStream,
        transport: httpx.AsyncBaseTransport,
        active: set[httpx.AsyncBaseTransport],
    ) -> None:
        self.stream = stream
        self.transport = transport
        self.active = active

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self.stream:
            yield chunk

    async def aclose(self) -> None:
        try:
            await self.stream.aclose()
        finally:
            try:
                await self.transport.aclose()
            finally:
                self.active.discard(self.transport)


class PublicDestinationTransport(httpx.AsyncBaseTransport):
    """Validate and pin every actual outbound request, after proxy header preparation."""

    def __init__(
        self, *, proxy: str | None = None, follow_redirects: bool = False
    ) -> None:
        """Configure operator-selected HTTP upstream routing and redirect policy."""
        if proxy is not None and httpx.URL(proxy).scheme != "http":
            raise ValueError(
                "Only operator-configured HTTP upstream proxies are supported."
            )
        self.proxy = proxy
        self.follow_redirects = follow_redirects
        self._active: set[httpx.AsyncBaseTransport] = set()

    async def aclose(self) -> None:
        """Close outstanding streams on client shutdown or a discarded retry."""
        for transport in tuple(self._active):
            try:
                await transport.aclose()
            finally:
                self._active.discard(transport)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Resolve and pin a logical request without mutating its redirect base URL."""
        target = destination_url(str(request.url))
        if (
            request.extensions.get("public_destination_https")
            and target.scheme != "https"
        ):
            raise InvalidDestinationError("HTTPS downgrade is forbidden.")
        request.extensions["public_destination_https"] = target.scheme == "https"
        timeout = request.extensions.get("timeout", {}).get("connect", 5.0)
        address = await asyncio.wait_for(_pinned_ip(target), timeout=timeout)
        hostname = target.raw_host.decode("ascii")
        headers = request.headers.copy()
        headers["host"] = target.netloc.decode("ascii")
        extensions = dict(request.extensions, sni_hostname=hostname)
        pinned = httpx.Request(
            request.method,
            target.copy_with(host=address),
            headers=headers,
            stream=request.stream,
            extensions=extensions,
        )
        transport = httpx.AsyncHTTPTransport(
            verify=ssl.create_default_context(),
            trust_env=False,
            proxy=self.proxy,
            retries=0,
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
        )
        if self.proxy is not None:
            # Version-pinned private seam: AsyncHTTPTransport has no backend argument.
            # CONNECT still uses the numeric URL; only TLS name verification changes.
            transport._pool._network_backend = _TunnelTLSBackend(
                transport._pool._network_backend, hostname, address
            )
        self._active.add(transport)
        try:
            response = await transport.handle_async_request(pinned)
            if self.follow_redirects and response.has_redirect_location:
                try:
                    location = response.headers["location"]
                    _safe_url_text(location)
                    redirect = destination_url(str(target.join(location)))
                    if target.scheme == "https" and redirect.scheme != "https":
                        raise InvalidDestinationError("HTTPS downgrade is forbidden.")
                except (ValueError, httpx.InvalidURL):
                    await response.aclose()
                    raise InvalidDestinationError(
                        "Invalid redirect destination."
                    ) from None
        except BaseException:
            try:
                await transport.aclose()
            finally:
                self._active.discard(transport)
            raise
        assert isinstance(response.stream, httpx.AsyncByteStream)
        response.stream = _ResponseStream(response.stream, transport, self._active)
        return response
