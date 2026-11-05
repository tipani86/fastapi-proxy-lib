# ruff: noqa: ANN001, ANN201, D101, D102, D103, D105, D107
"""Application-level public destination safety for both forwarding routes."""

from contextlib import asynccontextmanager
from urllib.parse import quote

import httpx
import pytest

import app as proxy_app
import forward_safety as safety


class Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk

    async def aclose(self):
        self.closed = True


@pytest.fixture(params=["/", "/p/"])
def forwarding(monkeypatch, request):
    prefix = request.param
    requests = []
    answers = ["93.184.216.34"]
    replies = []
    resolutions = []

    async def resolve(host, port):
        resolutions.append((host, port))
        return list(answers)

    async def handle(_self, outbound):
        requests.append(outbound)
        if not replies:
            pytest.fail("unsafe destination reached the outbound transport")
        response = replies.pop(0)
        response.request = outbound
        return response

    monkeypatch.setattr(safety, "_resolve", resolve)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", handle)
    monkeypatch.setattr(proxy_app, "PROXY_LIST_URL", None)
    monkeypatch.setattr(proxy_app, "FOLLOW_REDIRECTS", True)

    @asynccontextmanager
    async def client():
        async with proxy_app.app.router.lifespan_context(proxy_app.app):
            monkeypatch.setattr(
                proxy_app, "PROXY_LIST_URL", "https://operator.example.com/list"
            )
            proxy_app.app.state.proxy_pool.proxies = ["upstream.example.com:8080"]
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=proxy_app.app),
                base_url="http://proxy.test",
            ) as inbound:
                yield inbound
            assert proxy_app.app.state.proxy_pool.proxies == [
                "upstream.example.com:8080"
            ]

    return prefix, client, requests, answers, replies, resolutions


def endpoint(prefix, target):
    return prefix + quote(target, safe="")


@pytest.mark.anyio
@pytest.mark.parametrize(
    "answers",
    [
        ["127.0.0.1"],
        ["93.184.216.34", "10.0.0.1"],
        ["93.184.216.34", "::ffff:93.184.216.34"],
        [],
    ],
)
async def test_private_or_mixed_dns_initial_target_blocked_before_any_outbound_dial(
    forwarding, answers
):
    prefix, client, requests, resolved, _, _ = forwarding
    resolved[:] = answers
    async with client() as inbound:
        response = await inbound.get(
            endpoint(prefix, "http://public-looking.example.com/path")
        )
    assert response.status_code == 403
    assert not requests


@pytest.mark.anyio
@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://foo.internal/",
        "https://[::ffff:8.8.8.8]/",
        "http://169.254.169.254/",
        "http://@public.example.com/",
        "http://user:pass@public.example.com/",
        "http://public.example.com:8080/",
        "https://public.example.com:80/",
        "http://public.example.com/\r\nInjected:yes",
        "http://0x7f000001/",
    ],
)
async def test_raw_unsafe_initial_url_never_reaches_dial(forwarding, target):
    prefix, client, requests, _, _, _ = forwarding
    async with client() as inbound:
        response = await inbound.get(endpoint(prefix, target))
    assert response.status_code in (
        403,
        404,
    )  # Starlette rejects control-bearing paths at routing.
    assert not requests


@pytest.mark.anyio
@pytest.mark.parametrize(
    "location",
    [
        "http://127.0.0.1/private",
        "http://public.example.com/downgrade",
        "https://@public.example.com/",
        "https://public.example.com/\tbad",
    ],
)
async def test_redirects_rejected_before_next_dial(forwarding, location):
    prefix, client, requests, _, replies, _ = forwarding
    stream = Chunks([b"redirect"])
    replies.append(httpx.Response(302, headers={"location": location}, stream=stream))
    async with client() as inbound:
        response = await inbound.get(
            endpoint(prefix, "https://public.example.com/start")
        )
    assert response.status_code == 403
    assert len(requests) == 1
    assert stream.closed


@pytest.mark.anyio
async def test_relative_redirect_re_resolves_and_rejects_rebinding(
    forwarding, monkeypatch
):
    prefix, client, requests, _, replies, _ = forwarding
    calls = []

    async def rebind(host, port):
        calls.append((host, port))
        return ["93.184.216.34"] if len(calls) == 1 else ["127.0.0.1"]

    monkeypatch.setattr(safety, "_resolve", rebind)
    replies.append(
        httpx.Response(302, headers={"location": "/next"}, stream=Chunks([]))
    )
    async with client() as inbound:
        response = await inbound.get(
            endpoint(prefix, "https://public.example.com/start")
        )
    assert response.status_code == 403
    assert len(requests) == 1
    assert calls == [("public.example.com", 443)] * 2


@pytest.mark.anyio
async def test_public_stream_method_ua_host_sni_query_and_relative_redirect_preserved(
    forwarding,
):
    prefix, client, requests, _, replies, resolutions = forwarding
    large = b"x" * (17 * 1024 * 1024)
    replies.extend(
        [
            httpx.Response(307, headers={"location": "/next?new=1"}, stream=Chunks([])),
            httpx.Response(201, headers={"x-upstream": "kept"}, stream=Chunks([large])),
        ]
    )
    async with client() as inbound:
        response = await inbound.post(
            endpoint(prefix, "http://public.example.com/start?discard=1"),
            params=[("q", "a"), ("q", "b")],
            headers={"User-Agent": "PodPie/1.0"},
            content=b"payload",
        )
    assert response.status_code == 201
    assert response.content == large
    assert response.headers["x-upstream"] == "kept"
    assert [str(req.url) for req in requests] == [
        "http://93.184.216.34/start?q=a&q=b",
        "http://93.184.216.34/next?new=1",
    ]
    assert resolutions == [("public.example.com", 80)] * 2
    assert all(req.headers["host"] == "public.example.com" for req in requests)
    assert all(
        req.extensions["sni_hostname"] == "public.example.com" for req in requests
    )
    assert all(req.headers["user-agent"] == "PodPie/1.0" for req in requests)
    assert all(req.method == "POST" for req in requests)


@pytest.mark.anyio
async def test_unfollowed_redirect_retains_existing_response_semantics(
    forwarding, monkeypatch
):
    prefix, client, requests, _, replies, _ = forwarding
    monkeypatch.setattr(proxy_app, "FOLLOW_REDIRECTS", False)
    replies.append(
        httpx.Response(
            302, headers={"location": "http://127.0.0.1/"}, stream=Chunks([b"redirect"])
        )
    )
    async with client() as inbound:
        response = await inbound.get(
            endpoint(prefix, "https://public.example.com/start")
        )
    assert response.status_code == 302
    assert response.headers["location"] == "http://127.0.0.1/"
    assert len(requests) == 1


@pytest.mark.anyio
async def test_generic_forwarding_has_no_feed_only_url_length_cap(forwarding):
    prefix, client, requests, _, replies, _ = forwarding
    target = "https://public.example.com/" + "x" * 9000
    replies.append(httpx.Response(200, stream=Chunks([b"ok"])))
    async with client() as inbound:
        response = await inbound.get(endpoint(prefix, target))
    assert response.status_code == 200
    assert len(requests[0].url.path) == 9001


@pytest.mark.anyio
async def test_https_state_is_per_request_not_shared_client(forwarding):
    prefix, client, requests, _, replies, _ = forwarding
    replies.extend(httpx.Response(200, stream=Chunks([b"ok"])) for _ in range(2))
    async with client() as inbound:
        secure = await inbound.get(
            endpoint(prefix, "https://public.example.com/secure")
        )
        plain = await inbound.get(endpoint(prefix, "http://other.example.com/plain"))
    assert (secure.status_code, plain.status_code) == (200, 200)
    assert len(requests) == 2


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["exception", "407"])
async def test_rotating_retries_remove_only_failed_proxy_and_close_each_hop(
    monkeypatch, failure
):
    monkeypatch.setattr(proxy_app, "PROXY_LIST_URL", None)
    seen, closed = [], []
    original_close = httpx.AsyncHTTPTransport.aclose

    async def close(transport):
        closed.append(transport)
        await original_close(transport)

    async def resolve(_host, _port):
        return ["93.184.216.34"]

    async def handle(transport, _outbound):
        seen.append(transport)
        if len(seen) == 1:
            if failure == "exception":
                raise httpx.ProxyError("upstream unavailable")
            return httpx.Response(407, stream=Chunks([b"auth"]))
        return httpx.Response(200, stream=Chunks([b"ok"]))

    async def first(pool):
        return pool.proxies[0] if pool.proxies else None

    monkeypatch.setattr(safety, "_resolve", resolve)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", handle)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "aclose", close)
    monkeypatch.setattr(proxy_app.ProxyPool, "get_random", first)
    async with proxy_app.app.router.lifespan_context(proxy_app.app):
        monkeypatch.setattr(
            proxy_app, "PROXY_LIST_URL", "https://operator.example.com/list"
        )
        pool = proxy_app.app.state.proxy_pool
        pool.proxies = ["bad.example.com:8080", "good.example.com:8080"]
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app.app),
            base_url="http://proxy.test",
        ) as inbound:
            response = await inbound.get(endpoint("/p/", "https://public.example.com/"))
        assert response.status_code == 200
        assert pool.proxies == ["good.example.com:8080"]
        assert len(seen) == 2
        assert all(transport in closed for transport in seen)
