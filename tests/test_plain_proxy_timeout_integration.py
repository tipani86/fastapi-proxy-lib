# ruff: noqa: ANN001, ANN201, D103
"""Local-only real HTTP timeout regression; each request is bounded below 15s.

Run separately with pytest tests/test_plain_proxy_timeout_integration.py -s.
Only DNS and the TCP dial destination are redirected; HTTP reads use real sockets.
"""

import asyncio
import time
from urllib.parse import quote

import httpx
import pytest
from httpcore._backends.anyio import AnyIOBackend

import app as proxy_app
import forward_safety as safety


@pytest.fixture
async def slow_origin(monkeypatch):
    tasks = set()
    received = []

    async def serve(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        try:
            received.append(await reader.readuntil(b"\r\n\r\n"))
            # No headers/first byte until after HTTPX's old 5s read deadline.
            await asyncio.sleep(6.0)
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow"
            )
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            tasks.discard(task)

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    original_dial = AnyIOBackend.connect_tcp

    async def dial(backend, host, port, **kwargs):
        assert (host, port) == ("93.184.216.34", 80)
        return await original_dial(backend, "127.0.0.1", local_port, **kwargs)

    async def resolve(host, port):
        assert (host, port) == ("public.example.com", 80)
        return ["93.184.216.34"]

    local_port = port
    monkeypatch.setattr(AnyIOBackend, "connect_tcp", dial)
    monkeypatch.setattr(safety, "_resolve", resolve)
    monkeypatch.setattr(proxy_app, "PROXY_LIST_URL", None)
    try:
        yield received
    finally:
        server.close()
        await server.wait_closed()
        for task in tuple(tasks):
            task.cancel()
        if tasks:
            await asyncio.gather(*tuple(tasks), return_exceptions=True)


@pytest.mark.anyio
@pytest.mark.timeout(15)
async def test_real_plain_route_waits_past_old_five_second_read_limit(slow_origin):
    async def old_default_control():
        async with httpx.AsyncClient(
            transport=safety.PublicDestinationTransport(), trust_env=False
        ) as legacy:
            start = time.monotonic()
            with pytest.raises(httpx.ReadTimeout):
                await legacy.get("http://public.example.com/slow")
            elapsed = time.monotonic() - start
            print(f"old HTTPX default: ReadTimeout after {elapsed:.3f}s")
            assert 5.0 <= elapsed < 10.0

    async def plain_route():
        async with (
            proxy_app.app.router.lifespan_context(proxy_app.app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=proxy_app.app),
                base_url="http://proxy.test",
            ) as inbound,
        ):
            start = time.monotonic()
            response = await inbound.get(
                "/" + quote("http://public.example.com/slow", safe="")
            )
            elapsed = time.monotonic() - start
            print(f"plain route: HTTP {response.status_code} after {elapsed:.3f}s")
            assert response.status_code == 200
            assert response.content == b"slow"
            assert elapsed >= 6.0

    await asyncio.wait_for(asyncio.gather(old_default_control(), plain_route()), 12.0)
    assert len(slow_origin) == 2  # No retries, just the control and proxy request.
    assert all(
        b"host: public.example.com\r\n" in request.lower() for request in slow_origin
    )
