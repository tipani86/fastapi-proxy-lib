# ruff: noqa: ANN001, ANN201, D101, D102, D103, D105, D107

"""Security regressions for the standalone, direct-egress feed endpoint."""

import asyncio
import time

import httpx
import pytest

import app as proxy_app
import rss_fetch


@pytest.mark.anyio
async def test_public_feed_uses_pinned_ip_original_host_and_no_inbound_headers(
    monkeypatch,
):
    async def resolve(host, port):
        assert (host, port) == ("feeds.example.com", 443)
        return ["93.184.216.34"]

    requests = []

    async def handle(request):
        requests.append(request)
        return httpx.Response(200, content=b"<rss/>")

    monkeypatch.setattr(rss_fetch, "_resolve", resolve, raising=False)
    monkeypatch.setattr(
        rss_fetch,
        "_make_client",
        lambda: httpx.AsyncClient(transport=httpx.MockTransport(handle)),
        raising=False,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=proxy_app.app), base_url="http://proxy.test"
    ) as client:
        response = await client.get(
            "/rss",
            params={"url": "https://feeds.example.com/rss?key=x"},
            headers={"Authorization": "Bearer inbound", "Cookie": "session=secret"},
        )
    assert response.status_code == 200
    assert response.content == b"<rss/>"
    (request,) = requests
    assert str(request.url) == "https://93.184.216.34/rss?key=x"
    assert request.headers["host"] == "feeds.example.com"
    assert request.extensions["sni_hostname"] == "feeds.example.com"
    assert request.headers["accept-encoding"] == "identity"
    assert "authorization" not in request.headers
    assert "cookie" not in request.headers


@pytest.mark.anyio
async def test_rss_is_explicit_before_catchall_and_blocks_private_destinations():
    paths = [route.path for route in proxy_app.app.routes]
    assert "/rss" in paths
    assert paths.index("/rss") < paths.index("/{path:path}")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=proxy_app.app), base_url="http://proxy.test"
    ) as client:
        response = await client.get("/rss", params={"url": "http://127.0.0.1/feed"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid feed destination."}


@pytest.fixture
def outbound(monkeypatch):
    requests = []
    answers = ["93.184.216.34"]
    replies = []

    async def resolve(_host, _port):
        return list(answers)

    async def handle(request):
        requests.append(request)
        return replies.pop(0)

    monkeypatch.setattr(rss_fetch, "_resolve", resolve)
    monkeypatch.setattr(
        rss_fetch,
        "_make_client",
        lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(handle), follow_redirects=False
        ),
    )
    return requests, answers, replies


@pytest.mark.anyio
@pytest.mark.parametrize(
    "location",
    [
        "http://127.0.0.1/private",
        "https://10.0.0.1/private",
        "https://[::ffff:127.0.0.1]/",
        "http://feeds.example.com/downgrade",
    ],
)
async def test_redirect_destination_revalidated_and_https_never_downgrades(
    outbound, location
):
    requests, _, replies = outbound
    replies.append(httpx.Response(302, headers={"location": location}))
    response = await rss_fetch.fetch_feed("https://feeds.example.com/rss")
    assert response.status_code == 400
    assert len(requests) == 1


@pytest.mark.anyio
async def test_redirect_re_resolves_same_host_and_rejects_rebinding(
    outbound, monkeypatch
):
    requests, _, replies = outbound
    replies.append(httpx.Response(302, headers={"location": "/next"}))
    calls = []

    async def resolve(host, _port):
        calls.append(host)
        return ["93.184.216.34"] if len(calls) == 1 else ["127.0.0.1"]

    monkeypatch.setattr(rss_fetch, "_resolve", resolve)
    response = await rss_fetch.fetch_feed("https://feeds.example.com/rss")
    assert response.status_code == 400
    assert len(requests) == 1
    assert len(calls) == 2


@pytest.mark.anyio
async def test_relative_redirects_limited_to_five_without_cookie_leak(outbound):
    requests, _, replies = outbound
    replies.extend(
        httpx.Response(302, headers={"location": "/again", "set-cookie": "x=secret"})
        for _ in range(6)
    )
    response = await rss_fetch.fetch_feed("http://feeds.example.com/rss")
    assert response.status_code == 502
    assert len(requests) == 6
    assert all("cookie" not in r.headers for r in requests)


@pytest.mark.anyio
async def test_http_feed_redirect_can_upgrade_to_https(outbound):
    requests, _, replies = outbound
    replies.extend(
        [
            httpx.Response(301, headers={"location": "https://other.example.com/feed"}),
            httpx.Response(200, content=b"<rss/>"),
        ]
    )
    response = await rss_fetch.fetch_feed("http://feeds.example.com/rss")
    assert response.status_code == 200
    assert [r.url.scheme for r in requests] == ["http", "https"]
    assert requests[1].headers["host"] == "other.example.com"


class Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks, delay=0):
        self.chunks = chunks
        self.delay = delay
        self.read_count = 0
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            await asyncio.sleep(self.delay)
            self.read_count += 1
            yield chunk

    async def aclose(self):
        self.closed = True


@pytest.mark.anyio
@pytest.mark.parametrize("declared", [False, True])
async def test_feed_size_rejected_before_declared_or_streamed_overflow(
    outbound, declared
):
    _, _, replies = outbound
    cap = 16 * 1024 * 1024
    stream = Chunks([b"x" * (1024 * 1024)] * 17)
    headers = {"content-length": str(cap + 1)} if declared else {}
    replies.append(httpx.Response(200, headers=headers, stream=stream))
    response = await rss_fetch.fetch_feed("https://feeds.example.com/rss")
    assert response.status_code == 413
    assert stream.closed
    assert stream.read_count == (0 if declared else 17)


@pytest.mark.anyio
async def test_exact_size_limit_is_allowed(outbound):
    _, _, replies = outbound
    cap = 16 * 1024 * 1024
    replies.append(httpx.Response(200, stream=Chunks([b"x" * (1024 * 1024)] * 16)))
    response = await rss_fetch.fetch_feed("http://feeds.example.com/rss")
    assert response.status_code == 200
    assert len(response.body) == cap


@pytest.mark.anyio
@pytest.mark.parametrize("encoding", ["gzip", "br", "deflate", "identity, gzip"])
async def test_compression_rejected_before_read(outbound, encoding):
    _, _, replies = outbound
    stream = Chunks([b"compressed"])
    replies.append(
        httpx.Response(200, headers={"content-encoding": encoding}, stream=stream)
    )
    response = await rss_fetch.fetch_feed("https://feeds.example.com/rss")
    assert response.status_code == 502
    assert stream.read_count == 0
    assert stream.closed


@pytest.mark.anyio
@pytest.mark.parametrize("phase", ["dns", "read", "redirects"])
async def test_whole_request_deadline_covers_all_phases(outbound, monkeypatch, phase):
    _, _, replies = outbound
    monkeypatch.setattr(rss_fetch, "TOTAL_TIMEOUT", 0.06, raising=False)
    if phase == "dns":

        async def slow_resolve(_host, _port):
            await asyncio.sleep(1)
            return ["93.184.216.34"]

        monkeypatch.setattr(rss_fetch, "_resolve", slow_resolve)
    elif phase == "read":
        # Inactivity never exceeds the deadline; total time does.
        replies.append(httpx.Response(200, stream=Chunks([b"x"] * 100, delay=0.015)))
    else:

        async def slow_resolve(_host, _port):
            await asyncio.sleep(0.025)
            return ["93.184.216.34"]

        monkeypatch.setattr(rss_fetch, "_resolve", slow_resolve)
        replies.extend(
            httpx.Response(302, headers={"location": "/again"}) for _ in range(6)
        )
    start = time.monotonic()
    response = await rss_fetch.fetch_feed("https://feeds.example.com/rss")
    assert response.status_code == 504
    assert time.monotonic() - start < 0.5


@pytest.mark.anyio
async def test_legacy_asyncio_deadline_returns_504(monkeypatch):
    # Python 3.9/3.10 use a distinct exception, not built-in TimeoutError.
    class LegacyAsyncioTimeoutError(Exception):
        pass

    async def expired_wait_for(awaitable, timeout):
        assert timeout == rss_fetch.TOTAL_TIMEOUT
        awaitable.close()
        raise LegacyAsyncioTimeoutError

    monkeypatch.setattr(asyncio, "TimeoutError", LegacyAsyncioTimeoutError)
    monkeypatch.setattr(asyncio, "wait_for", expired_wait_for)
    response = await rss_fetch.fetch_feed("https://feeds.example.com/rss")
    assert response.status_code == 504
    assert response.body == b'{"detail":"Feed fetch timed out."}'


@pytest.mark.parametrize(
    "address", ["192.88.99.1", "2001:20::1", "2001:30::1", "3fff::1"]
)
def test_special_ranges_are_denied_independent_of_python_ipaddress_version(address):
    with pytest.raises(rss_fetch.InvalidDestinationError):
        rss_fetch._public_ip(address)


@pytest.fixture
def tls_certificate(tmp_path):
    import subprocess

    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=feeds.example.com",
            "-addext",
            "subjectAltName=DNS:feeds.example.com",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("target", "trusted", "expected"),
    [
        ("feeds.example.com", True, 200),
        ("wrong.example.com", True, 502),
        ("feeds.example.com", False, 502),
    ],
)
async def test_real_tls_keeps_original_sni_verifies_certificate_and_dials_only_pin(
    monkeypatch, tls_certificate, target, trusted, expected
):
    """Only reroute the TCP dial to a local server; TLS/HTTPX remain real."""
    import ssl

    from httpcore._backends.anyio import AnyIOBackend

    cert, key = tls_certificate
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    sni = []
    server_context.set_servername_callback(
        lambda _sock, name, _context: sni.append(name)
    )
    received = []

    async def serve(reader, writer):
        try:
            received.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\n<rss/>"
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=server_context)
    port = server.sockets[0].getsockname()[1]
    original_dial = AnyIOBackend.connect_tcp
    dials = []

    async def dial(self, host, port, **kwargs):
        dials.append((host, port))
        return await original_dial(self, host="127.0.0.1", port=local_port, **kwargs)

    local_port = port
    monkeypatch.setattr(AnyIOBackend, "connect_tcp", dial)

    async def resolve(host, _port):
        assert host == target
        return ["93.184.216.34"]

    monkeypatch.setattr(rss_fetch, "_resolve", resolve)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    if trusted:
        monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    else:
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    try:
        response = await rss_fetch.fetch_feed(f"https://{target}/feed")
    finally:
        server.close()
        await server.wait_closed()
    assert response.status_code == expected
    assert dials == [("93.184.216.34", 443)]
    assert sni == [target]
    if expected == 200:
        assert response.body == b"<rss/>"
        assert b"Host: feeds.example.com\r\n" in received[0]
    else:
        assert not received
        assert response.body == b'{"detail":"Feed fetch failed."}'


@pytest.mark.anyio
@pytest.mark.parametrize(
    "answers",
    [
        ["93.184.216.34", "127.0.0.1"],
        ["93.184.216.34", "::1"],
        ["93.184.216.34", "::ffff:93.184.216.34"],
        ["10.0.0.1", "93.184.216.34"],
        ["169.254.169.254"],
        ["100.64.0.1"],
        ["fec0::1"],
        ["224.0.0.1"],
        ["192.0.0.8"],
        ["64:ff9b::7f00:1"],
        ["2002:7f00:1::"],
        [],
    ],
)
async def test_entire_dns_answer_set_must_be_public(outbound, answers):
    requests, resolved, _ = outbound
    resolved[:] = answers
    response = await rss_fetch.fetch_feed("https://feeds.example.com/rss")
    assert response.status_code == 400
    assert not requests


@pytest.mark.anyio
@pytest.mark.parametrize(
    "url",
    [
        "",
        "file:///etc/passwd",
        "ftp://feeds.example.com/file",
        "gopher://feeds.example.com/",
        "http://user:pass@feeds.example.com/",
        "http://@feeds.example.com/",
        "https://feeds.example.com:80/",
        "http://feeds.example.com:443/",
        "http://feeds.example.com:8000/",
        "http://localhost/",
        "http://foo.local/",
        "http://foo.internal/",
        "http://foo.localdomain/",
        "http://foo.home.arpa/",
        "http://foo.localhost/",
        "http://localhost./",
        "http://127.0.0.1/",
        "https://[::1]/",
        "https://[::ffff:8.8.8.8]/",
        "http://169.254.169.254/",
        "http://10.0.0.1/",
        "http://0.0.0.0/",
        "http://feeds.example.com/\r\nInjected:yes",
        "http://feeds.example.com\\@127.0.0.1/",
        "https://[fe80::1%25eth0]/",
    ],
)
async def test_non_http_schemes_private_local_and_nonstandard_ports_rejected(
    outbound, url
):
    requests, _, _ = outbound
    response = await rss_fetch.fetch_feed(url)
    assert response.status_code == 400
    assert not requests


@pytest.mark.anyio
@pytest.mark.parametrize(
    "url",
    ["http://2130706433/feed", "http://0x7f000001/feed", "http://0177.0.0.1/feed"],
)
async def test_obscure_ipv4_forms_cannot_escape_dns_validation(outbound, url):
    requests, answers, _ = outbound
    answers[:] = ["127.0.0.1"]
    response = await rss_fetch.fetch_feed(url)
    assert response.status_code == 400
    assert not requests


@pytest.mark.anyio
async def test_public_path_need_not_have_xml_suffix_and_response_headers_not_forwarded(
    outbound,
):
    requests, _, replies = outbound
    replies.append(
        httpx.Response(
            200,
            headers={
                "content-type": "text/html",
                "set-cookie": "secret=x",
                "location": "http://internal.local/",
                "x-private": "secret",
            },
            content=b"not XML; caller validates the feed",
        )
    )
    response = await rss_fetch.fetch_feed(
        "http://feeds.example.com/any/path?format=rss"
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/xml"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "set-cookie" not in response.headers
    assert "location" not in response.headers
    assert "x-private" not in response.headers
    assert requests[0].url.query == b"format=rss"


@pytest.mark.anyio
async def test_idn_host_header_and_tls_name_use_ascii_dns_name(outbound):
    requests, _, replies = outbound
    replies.append(httpx.Response(200, content=b"<rss/>"))
    response = await rss_fetch.fetch_feed("https://bücher.example.com/rss")
    assert response.status_code == 200
    assert requests[0].headers["host"] == "xn--bcher-kva.example.com"
    assert requests[0].extensions["sni_hostname"] == "xn--bcher-kva.example.com"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "location", ["http://[broken/", "https://@feeds.example.com/next"]
)
async def test_malformed_or_empty_credentials_redirects_are_safe_errors(
    outbound, location
):
    requests, _, replies = outbound
    replies.append(httpx.Response(302, headers={"location": location}))
    response = await rss_fetch.fetch_feed("https://feeds.example.com/rss")
    assert response.status_code == 400
    assert len(requests) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("address", "authority"),
    [
        ("8.8.8.8", "8.8.8.8"),
        ("2001:4860:4860::8888", "[2001:4860:4860::8888]"),
    ],
)
async def test_public_ip_literals_are_supported_without_host_dns(
    outbound, monkeypatch, address, authority
):
    requests, _, replies = outbound

    async def forbidden(*_args):
        pytest.fail("IP literals must not resolve hostnames")

    monkeypatch.setattr(rss_fetch, "_resolve", forbidden)
    replies.append(httpx.Response(200, content=b"<rss/>"))
    response = await rss_fetch.fetch_feed(f"http://{authority}/feed")
    assert response.status_code == 200
    assert requests[0].url.host == address
    assert requests[0].headers["host"] == authority


@pytest.mark.anyio
@pytest.mark.parametrize("status", [304, 401, 404, 500])
async def test_non_success_upstream_status_never_passes_headers_or_diagnostics(
    outbound, status
):
    _, _, replies = outbound
    replies.append(httpx.Response(status, content=b"PRIVATE DIAGNOSTIC"))
    response = await rss_fetch.fetch_feed("https://feeds.example.com/rss")
    assert response.status_code == 502
    assert b"PRIVATE" not in response.body


@pytest.mark.anyio
async def test_dns_errors_are_generic_without_private_details(monkeypatch):
    async def broken(_host, _port):
        raise OSError("internal DNS resolver 10.0.0.53 secret")

    monkeypatch.setattr(rss_fetch, "_resolve", broken)
    response = await rss_fetch.fetch_feed("https://feeds.example.com/rss")
    assert response.status_code == 502
    assert response.body == b'{"detail":"Feed fetch failed."}'


@pytest.mark.anyio
async def test_compressed_redirect_is_rejected_without_reading_body(outbound):
    requests, _, replies = outbound
    stream = Chunks([b"compressed"])
    replies.append(
        httpx.Response(
            302,
            headers={
                "location": "/next",
                "content-encoding": "gzip",
            },
            stream=stream,
        )
    )
    response = await rss_fetch.fetch_feed("https://feeds.example.com/rss")
    assert response.status_code == 502
    assert len(requests) == 1
    assert stream.read_count == 0
    assert stream.closed
