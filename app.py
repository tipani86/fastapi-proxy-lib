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
import logging
import os
import random
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI
from starlette.background import BackgroundTask, BackgroundTasks
from starlette.requests import Request
from starlette.responses import JSONResponse, Response as StarletteResponse

from fastapi_proxy_lib.core.http import ForwardHttpProxy
from fastapi_proxy_lib.core.tool import default_proxy_filter

_logger = logging.getLogger(__name__)

# Load `.env` early so module-level config reads see the values.
load_dotenv(override=False)


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
    """Parse a single proxy endpoint line into canonical 'ip:port' (IPv6 must be bracketed).

    Accepted inputs:
    - '1.2.3.4:8080'
    - '[2001:db8::1]:8080'
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None

    host: str
    port_str: str

    if s.startswith("["):
        # Bracketed IPv6: [addr]:port
        rb = s.find("]")
        if rb <= 1:
            return None
        host = s[1:rb]
        rest = s[rb + 1 :]
        if not rest.startswith(":"):
            return None
        port_str = rest[1:]
    else:
        # IPv4:port
        if s.count(":") != 1:
            return None
        host, port_str = s.split(":", 1)

    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None

    try:
        port = int(port_str)
    except ValueError:
        return None
    if port < 1 or port > 65535:
        return None

    # Canonicalize output
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


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

        _logger.info(
            "proxy-pool refresh ok: count=%s elapsed_ms=%.2f",
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
                        _logger.info("proxy-pool refreshed: reason=%s", reason)
                        return True
                    except Exception:
                        _logger.exception("proxy-pool refresh failed: reason=%s", reason)
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
            timeout=timeout,
        )
    except TypeError:
        # Newer httpx API uses `proxy=...` (best-effort compatibility).
        return httpx.AsyncClient(proxy=proxy_url, timeout=timeout)


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
        proxy_refresher = ProxyPoolRefresher(
            pool=pool,
            fetch_client=refresh_client,
            url=PROXY_LIST_URL,
            interval_seconds=PROXY_REFRESH_INTERVAL_SECONDS,
            deadline_monotonic=time.monotonic(),
        )
        await proxy_refresher.refresh_now(reason="startup")
        refresh_task = asyncio.create_task(proxy_refresher.refresh_loop())

    app.state.proxy_pool = pool
    app.state.proxy_refresher = proxy_refresher
    app.state.unproxied_forward_proxy = unproxied_forward_proxy

    try:
        yield
    finally:
        if refresh_task is not None:
            refresh_task.cancel()
            try:
                await refresh_task
            except asyncio.CancelledError:
                pass
        await refresh_client.aclose()
        await unproxied_forward_proxy.aclose()


app = FastAPI(lifespan=_lifespan)


_ALL_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"]



@app.api_route("/p/{path:path}", methods=_ALL_HTTP_METHODS)
async def forward_proxied(request: Request, path: str = "") -> StarletteResponse:
    """Forward proxy with per-request upstream proxy rotation and retry."""
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

    # Apply default proxy filter (reject localhost/non-public IP, etc.).
    filter_result = default_proxy_filter(target_url)
    if filter_result is not None:
        return JSONResponse({"detail": filter_result}, status_code=403)

    pool: ProxyPool = app.state.proxy_pool
    refresher: ProxyPoolRefresher = app.state.proxy_refresher

    last_exc: Optional[BaseException] = None
    for _attempt in range(max(PROXIED_RETRY_N, 1)):
        upstream = await pool.get_random()
        if upstream is None:
            await refresher.refresh_now(reason="empty_pool")
            upstream = await pool.get_random()
            if upstream is None:
                return JSONResponse({"detail": "Proxy pool is empty."}, status_code=503)

        temp_client: Optional[httpx.AsyncClient] = None
        try:
            temp_client = _make_proxied_async_client(proxy=upstream)
            temp_forward_proxy = ForwardHttpProxy(
                temp_client,
                proxy_filter=default_proxy_filter,
                follow_redirects=FOLLOW_REDIRECTS,
            )
            resp = await temp_forward_proxy.send_request_to_target(
                request=request, target_url=target_url
            )

            # Special-case: proxy authentication required is clearly upstream-proxy related.
            if getattr(resp, "status_code", None) == 407:
                removed = await pool.remove(upstream)
                _logger.warning(
                    "removed upstream proxy due to 407: proxy=%s removed=%s",
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
            if temp_client is not None:
                await temp_client.aclose()
                temp_client = None
            if _is_clear_upstream_proxy_error(exc):
                removed = await pool.remove(upstream)
                _logger.warning(
                    "removed upstream proxy due to error: proxy=%s exc=%s removed=%s",
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
    proxy: ForwardHttpProxy = app.state.unproxied_forward_proxy
    return await proxy.proxy(request=request, path=path)