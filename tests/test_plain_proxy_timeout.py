# ruff: noqa: ANN001, ANN201, D103
"""Plain-route timeout policy at client construction and at the socket boundary."""

import importlib.util
import sys
from contextlib import asynccontextmanager
from urllib.parse import quote

import httpx
import pytest

import app as proxy_app
import forward_safety as safety
from tests.test_forward_safety import Chunks


@pytest.fixture
def plain_client(monkeypatch):
    seen = []

    async def resolve(host, port):
        assert (host, port) == ("public.example.com", 80)
        return ["93.184.216.34"]

    async def handle(_transport, request):
        seen.append(request)
        await request.aread()
        return httpx.Response(200, stream=Chunks([b"streamed response"]))

    monkeypatch.setattr(safety, "_resolve", resolve)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", handle)
    monkeypatch.setattr(proxy_app, "PROXY_LIST_URL", None)

    @asynccontextmanager
    async def client(module=proxy_app):
        monkeypatch.setattr(module, "PROXY_LIST_URL", None)
        async with module.app.router.lifespan_context(module.app):
            outbound = module.app.state.unproxied_forward_proxy.client
            assert isinstance(outbound._transport, safety.PublicDestinationTransport)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=module.app),
                base_url="http://proxy.test",
            ) as inbound:
                yield inbound, outbound, seen

    return client


@pytest.mark.anyio
async def test_plain_default_timeout_survives_build_stream_send_and_public_transport(
    plain_client,
):
    async with plain_client() as (inbound, outbound, seen):
        assert outbound.timeout.as_dict() == {
            "connect": 60.0,
            "read": 60.0,
            "write": 60.0,
            "pool": 60.0,
        }
        response = await inbound.post(
            "/" + quote("http://public.example.com/read", safe=""),
            params=[("q", "a"), ("q", "b")],
            content=b"streamed request",
        )
        assert response.status_code == 200
        assert response.content == b"streamed response"
        assert len(seen) == 1
        assert seen[0].extensions["timeout"] == outbound.timeout.as_dict()
        assert str(seen[0].url) == "http://93.184.216.34/read?q=a&q=b"
        assert seen[0].content == b"streamed request"


@pytest.mark.anyio
@pytest.mark.parametrize(("read", "connect"), [("73.5", "12.25"), ("0.25", "0.1")])
async def test_plain_env_overrides_reach_actual_client_and_stream_send(
    monkeypatch, plain_client, read, connect
):
    monkeypatch.setenv("UNPROXIED_READ_TIMEOUT", read)
    monkeypatch.setenv("UNPROXIED_CONNECT_TIMEOUT", connect)
    # Isolate import-time configuration without reloading the shared application.
    spec = importlib.util.spec_from_file_location(
        "_plain_timeout_test_app", proxy_app.__file__
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    expected = {
        "read": float(read),
        "write": float(read),
        "connect": float(connect),
        "pool": float(connect),
    }
    async with plain_client(module) as (inbound, outbound, seen):
        assert outbound.timeout.as_dict() == expected
        response = await inbound.get(
            "/" + quote("http://public.example.com/read", safe="")
        )
        assert response.status_code == 200
        assert len(seen) == 1
        assert seen[0].extensions["timeout"] == expected
