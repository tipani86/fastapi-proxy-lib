"""Runnable FastAPI app that exposes two forward-proxy routes.

- /{path:path}:
    Direct forward proxy (no upstream proxy), uses a long-lived httpx.AsyncClient.
- /p/{path:path}:
    Forward proxy with per-request upstream HTTP proxy rotation, backed by a global pool
    refreshed periodically from a URL.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import random
import re
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI
from loguru import logger
from starlette.background import BackgroundTask, BackgroundTasks
from starlette.requests import Request
from starlette.responses import JSONResponse, Response as StarletteResponse

from fastapi_proxy_lib.core.http import ForwardHttpProxy
from fastapi_proxy_lib.core.tool import default_proxy_filter

# Load `.env` early so module-level config reads see the values.
load_dotenv(override=False)

# ---- Logging (loguru) ----
# Configure at import-time; control verbosity via env var LOGURU_LEVEL.
logger.remove()
logger.add(
    sys.stderr,
    level=os.environ.get("LOGURU_LEVEL", "INFO").strip().upper() or "INFO",
)

# ---- Header hygiene ----
# These headers commonly carry "client chain" data across proxy hops and can cause
# upstream services (e.g. httpbin) to report multi-IP "origin" lists.
_STRIP_PROXY_CHAIN_HEADERS = (
    "x-forwarded-for",
    "forwarded",
    "via",
    "x-real-ip",
    # Optional/common variants (kept for robustness; stripping is limited to /p route only)
    "accept-encoding",
    "cf-connecting-ip",
    "cf-ipcountry",
    "cf-ray",
    "cf-visitor",
    "cdn-loop",
    "cookie",
    "true-client-ip",
    "x-client-ip",
)


def _clone_request_without_headers(
    request: Request, *, strip_headers: tuple[str, ...]
) -> tuple[Request, list[str]]:
    """Clone request with filtered scope['headers'] while preserving the ASGI receive callable."""
    strip_set = {h.encode("ascii") for h in strip_headers}

    scope = dict(request.scope)
    original_headers: list[tuple[bytes, bytes]] = list(scope.get("headers") or [])

    removed: list[str] = []
    filtered_headers: list[tuple[bytes, bytes]] = []
    for k, v in original_headers:
        lk = k.lower()
        if lk in strip_set:
            removed.append(lk.decode("ascii", errors="ignore"))
            continue
        filtered_headers.append((k, v))

    scope["headers"] = filtered_headers

    # Preserve the original ASGI receive callable so streaming bodies keep working.
    receive = getattr(request, "_receive", None)
    if receive is None:
        receive = request.receive  # type: ignore[assignment]

    return Request(scope, receive), removed


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


# ---- Config (env) ----
PROXY_LIST_URL: Optional[str] = os.environ.get("PROXY_LIST_URL") or None
PROXY_REFRESH_INTERVAL_SECONDS: int = int(
    os.environ.get("PROXY_REFRESH_INTERVAL_SECONDS", "600")
)
PROXIED_RETRY_N: int = int(os.environ.get("PROXIED_RETRY_N", "3"))
FOLLOW_REDIRECTS: bool = _env_bool("FOLLOW_REDIRECTS", False)

UPSTREAM_PROXY_CONNECT_TIMEOUT: float = float(
    os.environ.get("UPSTREAM_PROXY_CONNECT_TIMEOUT", "5.0")
)
UPSTREAM_PROXY_READ_TIMEOUT: float = float(
    os.environ.get("UPSTREAM_PROXY_READ_TIMEOUT", "30.0")
)


def _parse_ip_port(line: str) -> Optional[str]:
    """Parse a single proxy endpoint line into canonical 'host:port' (IPv6 must be bracketed).

    Accepted inputs:
    - '1.2.3.4:8080'
    - '[2001:db8::1]:8080'
    - 'user:pass@1.2.3.4:8080'
    - 'user:pass@brd.superproxy.io:33335'
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None

    username: Optional[str] = None
    password: Optional[str] = None
    hostport = s
    if "@" in s:
        userinfo, hostport = s.rsplit("@", 1)
        if ":" not in userinfo:
            return None
        username, password = userinfo.split(":", 1)
        if not username or not password:
            return None

    host: str
    port_str: str
    is_bracketed_ipv6 = hostport.startswith("[")

    if is_bracketed_ipv6:
        # Bracketed IPv6: [addr]:port
        rb = hostport.find("]")
        if rb <= 1:
            return None
        host = hostport[1:rb]
        rest = hostport[rb + 1 :]
        if not rest.startswith(":"):
            return None
        port_str = rest[1:]
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return None
    else:
        # IPv4/hostname:port
        if ":" not in hostport:
            return None
        host, port_str = hostport.rsplit(":", 1)
        if not host:
            return None
        if ":" in host:
            return None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
                return None
            if host.startswith(".") or host.endswith(".") or ".." in host:
                return None

    try:
        port = int(port_str)
    except ValueError:
        return None
    if port < 1 or port > 65535:
        return None

    # Canonicalize output
    host_out = f"[{host}]" if is_bracketed_ipv6 else host
    if username is not None and password is not None:
        return f"{username}:{password}@{host_out}:{port}"
    return f"{host_out}:{port}"


def _redact_proxy_creds(proxy: str) -> str:
    """Mask user:pass@ in proxy strings for logging."""
    if "@" not in proxy:
        return proxy
    userinfo, rest = proxy.rsplit("@", 1)
    if ":" not in userinfo:
        return proxy
    return f"***:***@{rest}"


@dataclass
class ProxyPool:
    """Global proxy pool guarded by an asyncio lock."""

    proxies: list[str] = field(default_factory=list)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_refresh_ts: Optional[float] = None

    async def refresh_from_url(
        self, *, fetch_client: httpx.AsyncClient, url: str
    ) -> None:
        """Fetch a proxy list text file from url and atomically swap into pool."""
        started = time.monotonic()
        resp = await fetch_client.get(url)
        resp.raise_for_status()
        text = resp.text

        seen: set[str] = set()
        parsed: list[str] = []
        for raw_line in text.splitlines():
            p = _parse_ip_port(raw_line)
            if p is None:
                continue
            if p in seen:
                continue
            seen.add(p)
            parsed.append(p)

        async with self.lock:
            self.proxies = parsed
            self.last_refresh_ts = time.time()

        logger.info(
            "proxy-pool refresh ok: count={} elapsed_ms={:.2f}",
            len(parsed),
            (time.monotonic() - started) * 1000.0,
        )

    async def get_random(self) -> Optional[str]:
        """Return a random proxy endpoint or None if empty."""
        async with self.lock:
            if not self.proxies:
                return None
            return random.choice(self.proxies)

    async def remove(self, proxy: str) -> bool:
        """Remove a proxy endpoint if present."""
        async with self.lock:
            try:
                self.proxies.remove(proxy)
            except ValueError:
                return False
            return True


@dataclass
class ProxyPoolRefresher:
    """Singleflight + deadline-based refresh controller for a ProxyPool."""

    pool: ProxyPool
    fetch_client: httpx.AsyncClient
    url: str
    interval_seconds: int
    deadline_monotonic: float
    wakeup_event: asyncio.Event = field(default_factory=asyncio.Event)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _in_flight: Optional[asyncio.Task[bool]] = None

    async def refresh_now(self, *, reason: str) -> bool:
        """Refresh the pool now (singleflight) and reset the deadline."""
        async with self.lock:
            if self._in_flight is not None and not self._in_flight.done():
                task = self._in_flight
            else:

                async def _do_refresh() -> bool:
                    try:
                        await self.pool.refresh_from_url(
                            fetch_client=self.fetch_client,
                            url=self.url,
                        )
                        logger.info("proxy-pool refreshed: reason={}", reason)
                        return True
                    except Exception:
                        logger.exception("proxy-pool refresh failed: reason={}", reason)
                        return False

                task = asyncio.create_task(_do_refresh())
                self._in_flight = task

        ok = await task

        now = time.monotonic()
        async with self.lock:
            if self._in_flight is task:
                self._in_flight = None
            self.deadline_monotonic = now + float(self.interval_seconds)
            self.wakeup_event.set()

        return ok

    async def refresh_loop(self) -> None:
        """Periodic refresh loop that sleeps until deadline (woken by deadline changes)."""
        while True:
            try:
                async with self.lock:
                    sleep_seconds = max(0.0, self.deadline_monotonic - time.monotonic())
                    event = self.wakeup_event

                try:
                    await asyncio.wait_for(event.wait(), timeout=sleep_seconds)
                    event.clear()
                    continue
                except TimeoutError:
                    pass

                await self.refresh_now(reason="scheduled")
            except asyncio.CancelledError:
                raise


def _is_clear_upstream_proxy_error(exc: BaseException) -> bool:
    """Classifier for delete-worthy upstream proxy failures (exception-based)."""
    return isinstance(
        exc,
        (
            httpx.ProxyError,
            httpx.ConnectTimeout,
            httpx.ConnectError,
            httpx.RemoteProtocolError,
            httpx.ProtocolError,
        ),
    )


def _make_proxied_async_client(*, proxy: str) -> httpx.AsyncClient:
    """Create a short-lived client configured to use an upstream HTTP proxy."""
    timeout = httpx.Timeout(
        connect=UPSTREAM_PROXY_CONNECT_TIMEOUT,
        read=UPSTREAM_PROXY_READ_TIMEOUT,
        write=UPSTREAM_PROXY_READ_TIMEOUT,
        pool=UPSTREAM_PROXY_CONNECT_TIMEOUT,
    )
    proxy_url = f"http://{proxy}"
    try:
        # Older httpx API (documented in this repo) supports `proxies=...`.
        return httpx.AsyncClient(
            proxies={"http://": proxy_url, "https://": proxy_url},
            verify=False,
            timeout=timeout,
        )
    except TypeError:
        # Newer httpx API uses `proxy=...` (best-effort compatibility).
        return httpx.AsyncClient(proxy=proxy_url, verify=False, timeout=timeout)


def _attach_close_client_background(
    *, resp: StarletteResponse, client: httpx.AsyncClient
) -> StarletteResponse:
    """Attach `client.aclose()` to response background without dropping existing background."""
    new_bg = BackgroundTasks()
    existing = resp.background
    if existing is not None:
        if isinstance(existing, BackgroundTasks):
            new_bg.tasks.extend(existing.tasks)
        elif isinstance(existing, BackgroundTask):
            new_bg.tasks.append(existing)
        else:  # pragma: no cover
            # Best-effort fallback for unexpected background types.
            new_bg.add_task(existing)  # type: ignore[arg-type]
    new_bg.add_task(client.aclose)
    resp.background = new_bg
    return resp


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.debug(
        "lifespan startup: PROXY_LIST_URL={} PROXY_REFRESH_INTERVAL_SECONDS={} PROXIED_RETRY_N={} FOLLOW_REDIRECTS={}",
        PROXY_LIST_URL,
        PROXY_REFRESH_INTERVAL_SECONDS,
        PROXIED_RETRY_N,
        FOLLOW_REDIRECTS,
    )
    pool = ProxyPool()

    unproxied_client = httpx.AsyncClient()
    unproxied_forward_proxy = ForwardHttpProxy(
        unproxied_client,
        proxy_filter=default_proxy_filter,
        follow_redirects=FOLLOW_REDIRECTS,
    )

    refresh_client = httpx.AsyncClient()
    refresh_task: Optional[asyncio.Task[None]] = None
    proxy_refresher: Optional[ProxyPoolRefresher] = None

    if PROXY_LIST_URL is not None:
        logger.debug(
            "proxy refresher enabled: url={} interval_seconds={}",
            PROXY_LIST_URL,
            PROXY_REFRESH_INTERVAL_SECONDS,
        )
        proxy_refresher = ProxyPoolRefresher(
            pool=pool,
            fetch_client=refresh_client,
            url=PROXY_LIST_URL,
            interval_seconds=PROXY_REFRESH_INTERVAL_SECONDS,
            deadline_monotonic=time.monotonic(),
        )
        ok = await proxy_refresher.refresh_now(reason="startup")
        logger.debug("proxy refresher startup refresh: ok={}", ok)
        refresh_task = asyncio.create_task(proxy_refresher.refresh_loop())
    else:
        logger.debug("proxy refresher disabled: PROXY_LIST_URL is not configured")

    app.state.proxy_pool = pool
    app.state.proxy_refresher = proxy_refresher
    app.state.unproxied_forward_proxy = unproxied_forward_proxy

    try:
        yield
    finally:
        logger.debug("lifespan shutdown: starting cleanup")
        if refresh_task is not None:
            refresh_task.cancel()
            try:
                await refresh_task
            except asyncio.CancelledError:
                pass
        await refresh_client.aclose()
        await unproxied_forward_proxy.aclose()
        logger.debug("lifespan shutdown: cleanup complete")


app = FastAPI(lifespan=_lifespan)


_ALL_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"]



@app.api_route("/p/{path:path}", methods=_ALL_HTTP_METHODS)
async def forward_proxied(request: Request, path: str = "") -> StarletteResponse:
    """Forward proxy with per-request upstream proxy rotation and retry."""
    _chain_headers = (
        "x-forwarded-for",
        "forwarded",
        "via",
        "x-real-ip",
        "cf-connecting-ip",
        "true-client-ip",
    )
    _present_chain = {h: request.headers.get(h) for h in _chain_headers if request.headers.get(h)}
    _chain_header_set = set(_chain_headers)
    _non_chain_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in _chain_header_set
    }
    logger.debug(
        "forward_proxied entry: method={} incoming_url={} client={} chain_headers={}",
        request.method,
        str(request.url),
        getattr(request.client, "host", None),
        _present_chain,
    )
    logger.debug("forward_proxied non_chain_headers={}", _non_chain_headers)

    filtered_request, removed_chain = _clone_request_without_headers(
        request, strip_headers=_STRIP_PROXY_CHAIN_HEADERS
    )
    if removed_chain:
        logger.debug(
            "forward_proxied stripped chain headers: removed={}",
            sorted(set(removed_chain)),
        )
        _present_after = {
            h: filtered_request.headers.get(h)
            for h in _chain_headers
            if filtered_request.headers.get(h)
        }
        logger.debug(
            "forward_proxied chain headers after strip: {}",
            _present_after,
        )
    if PROXY_LIST_URL is None:
        return JSONResponse(
            {"detail": "PROXY_LIST_URL is not configured."}, status_code=503
        )

    # Parse/validate target url (same behavior as ForwardHttpProxy: path is full URL).
    if not path:
        return JSONResponse({"detail": "Must provide target url."}, status_code=400)
    try:
        target_url = httpx.URL(path)
    except httpx.InvalidURL:
        return JSONResponse({"detail": "Invalid target url."}, status_code=400)
    logger.debug(
        "forward_proxied parsed target_url: scheme={} host={} path={}",
        target_url.scheme,
        target_url.host,
        target_url.path,
    )

    # Apply default proxy filter (reject localhost/non-public IP, etc.).
    filter_result = default_proxy_filter(target_url)
    if filter_result is not None:
        return JSONResponse({"detail": filter_result}, status_code=403)

    pool: ProxyPool = app.state.proxy_pool
    refresher: ProxyPoolRefresher = app.state.proxy_refresher

    last_exc: Optional[BaseException] = None
    for _attempt in range(max(PROXIED_RETRY_N, 1)):
        logger.debug("forward_proxied attempt: {}", _attempt + 1)
        upstream = await pool.get_random()
        if upstream is None:
            logger.debug("proxy pool empty; forcing refresh")
            await refresher.refresh_now(reason="empty_pool")
            upstream = await pool.get_random()
            if upstream is None:
                return JSONResponse({"detail": "Proxy pool is empty."}, status_code=503)
        logger.debug("selected upstream proxy: {}", _redact_proxy_creds(upstream))

        temp_client: Optional[httpx.AsyncClient] = None
        try:
            temp_client = _make_proxied_async_client(proxy=upstream)
            temp_forward_proxy = ForwardHttpProxy(
                temp_client,
                proxy_filter=default_proxy_filter,
                follow_redirects=FOLLOW_REDIRECTS,
            )
            resp = await temp_forward_proxy.send_request_to_target(
                request=filtered_request, target_url=target_url
            )

            # Special-case: proxy authentication required is clearly upstream-proxy related.
            if getattr(resp, "status_code", None) == 407:
                removed = await pool.remove(upstream)
                logger.warning(
                    "removed upstream proxy due to 407: proxy={} removed={}",
                    upstream,
                    removed,
                )
                # Close this temp client immediately since we are not returning its response.
                await temp_client.aclose()
                temp_client = None
                continue

            # Important: response streams from the temp client; close it after response is sent.
            return _attach_close_client_background(resp=resp, client=temp_client)
        except Exception as exc:
            last_exc = exc
            logger.debug(
                "forward_proxied exception: upstream={} exc_type={} exc={}",
                upstream,
                type(exc).__name__,
                str(exc),
            )
            if temp_client is not None:
                await temp_client.aclose()
                temp_client = None
            if _is_clear_upstream_proxy_error(exc):
                removed = await pool.remove(upstream)
                logger.warning(
                    "removed upstream proxy due to error: proxy={} exc={} removed={}",
                    upstream,
                    type(exc).__name__,
                    removed,
                )
                continue
            # Non-clear failures: do not delete; return an error response.
            break

    # Retries exhausted or non-clear failure encountered.
    if last_exc is not None:
        status_code = 502 if _is_clear_upstream_proxy_error(last_exc) else 500
        return JSONResponse(
            {
                "detail": "Proxy request failed.",
                "error_type": type(last_exc).__name__,
                "error": str(last_exc),
            },
            status_code=status_code,
        )

    return JSONResponse({"detail": "Proxy request failed."}, status_code=502)



@app.api_route("/{path:path}", methods=_ALL_HTTP_METHODS)
async def forward_unproxied(request: Request, path: str = "") -> StarletteResponse:
    """Forward proxy without an upstream proxy."""
    _chain_headers = (
        "x-forwarded-for",
        "forwarded",
        "via",
        "x-real-ip",
        "cf-connecting-ip",
        "true-client-ip",
    )
    _present_chain = {h: request.headers.get(h) for h in _chain_headers if request.headers.get(h)}
    _chain_header_set = set(_chain_headers)
    _non_chain_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in _chain_header_set
    }
    logger.debug(
        "forward_unproxied entry: method={} incoming_url={} client={} chain_headers={}",
        request.method,
        str(request.url),
        getattr(request.client, "host", None),
        _present_chain,
    )
    logger.debug("forward_unproxied non_chain_headers={}", _non_chain_headers)
    proxy: ForwardHttpProxy = app.state.unproxied_forward_proxy
    return await proxy.proxy(request=request, path=path)