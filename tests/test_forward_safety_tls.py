# ruff: noqa: ANN001, ANN201, D103
"""Real socket/TLS tests, including the upstream HTTP proxy CONNECT wire format."""

import asyncio
import ssl
import subprocess
from urllib.parse import quote

import httpx
import pytest
from httpcore._backends.anyio import AnyIOBackend

import app as proxy_app
import forward_safety as safety


@pytest.fixture
def tls_certificate(tmp_path):
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
            "/CN=public.example.com",
            "-addext",
            "subjectAltName=DNS:public.example.com",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


async def close_writer(writer):
    writer.close()
    try:
        await writer.wait_closed()
    except ConnectionError:
        pass


async def pump(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except ConnectionError:
        pass
    finally:
        await close_writer(writer)


@pytest.fixture
async def wire_servers(tls_certificate):
    cert, key = tls_certificate
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    sni, connects, received = [], [], []
    tasks = set()
    context.set_servername_callback(lambda _socket, name, _context: sni.append(name))

    async def serve(reader, writer):
        try:
            headers = await reader.readuntil(b"\r\n\r\n")
            length = next(
                (
                    int(line.split(b":", 1)[1])
                    for line in headers.split(b"\r\n")
                    if line.lower().startswith(b"content-length:")
                ),
                0,
            )
            received.append(headers + await reader.readexactly(length))
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata"
            )
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            await close_writer(writer)

    origin = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=context)
    origin_port = origin.sockets[0].getsockname()[1]

    async def tunnel(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        try:
            connects.append(await reader.readuntil(b"\r\n\r\n"))
            if connects[-1].startswith(b"CONNECT 93.184.216.35:443 "):
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                await close_writer(writer)
                return
            upstream_reader, upstream_writer = await asyncio.open_connection(
                "127.0.0.1", origin_port
            )
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            await asyncio.gather(
                pump(reader, upstream_writer), pump(upstream_reader, writer)
            )
        finally:
            tasks.discard(task)

    proxy = await asyncio.start_server(tunnel, "127.0.0.1", 0)
    try:
        yield origin_port, proxy.sockets[0].getsockname()[1], sni, connects, received
    finally:
        origin.close()
        proxy.close()
        await origin.wait_closed()
        await proxy.wait_closed()
        if tasks:
            await asyncio.gather(*tasks)


@pytest.mark.anyio
@pytest.mark.parametrize("proxied", [False, True])
@pytest.mark.parametrize("address", ["93.184.216.34", "2606:4700:4700::1111"])
@pytest.mark.parametrize(
    ("hostname", "trusted", "success"),
    [
        ("public.example.com", True, True),
        ("wrong.example.com", True, False),
        ("public.example.com", False, False),
    ],
)
async def test_real_verified_tls_original_sni_numeric_socket_or_connect(
    monkeypatch,
    tls_certificate,
    wire_servers,
    proxied,
    address,
    hostname,
    trusted,
    success,
):
    origin_port, proxy_port, sni, connects, received = wire_servers
    original_dial = AnyIOBackend.connect_tcp
    dials = []

    async def dial(self, host, port, **kwargs):
        dials.append((host, port))
        return await original_dial(
            self,
            host="127.0.0.1",
            port=proxy_port if proxied else origin_port,
            **kwargs,
        )

    async def resolve(host, port):
        assert (host, port) == (hostname, 443)
        return [address, "8.8.8.8"]

    monkeypatch.setattr(AnyIOBackend, "connect_tcp", dial)
    monkeypatch.setattr(safety, "_resolve", resolve)
    monkeypatch.setenv("HTTPS_PROXY", "http://environment.invalid:1234")
    monkeypatch.setenv("HTTP_PROXY", "http://environment.invalid:1234")
    if trusted:
        monkeypatch.setenv("SSL_CERT_FILE", str(tls_certificate[0]))
    else:
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.setattr(proxy_app, "PROXY_LIST_URL", None)
    monkeypatch.setattr(proxy_app, "PROXIED_RETRY_N", 3)
    async with proxy_app.app.router.lifespan_context(proxy_app.app):
        monkeypatch.setattr(
            proxy_app, "PROXY_LIST_URL", "https://operator.example.com/list"
        )
        proxy_app.app.state.proxy_pool.proxies = ["upstream.example.com:8080"]
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app.app),
            base_url="http://proxy.test",
        ) as client:
            prefix = "/p/" if proxied else "/"
            response = await client.get(
                prefix + quote(f"https://{hostname}/document", safe="")
            )
        assert proxy_app.app.state.proxy_pool.proxies == ["upstream.example.com:8080"]
    assert response.status_code == (200 if success else (502 if proxied else 500))
    assert dials == [("upstream.example.com", 8080) if proxied else (address, 443)]
    assert sni == [hostname]
    if proxied:
        authority = f"[{address}]:443" if ":" in address else f"{address}:443"
        assert connects[0].startswith(f"CONNECT {authority} HTTP/1.1\r\n".encode())
    if success:
        assert response.content == b"data"
        assert b"host: public.example.com\r\n" in received[0].lower()
    else:
        assert not received


@pytest.mark.anyio
@pytest.mark.parametrize("proxied", [False, True])
@pytest.mark.parametrize("address", ["93.184.216.34", "2606:4700:4700::1111"])
async def test_real_http_numeric_request_target_body_host_and_user_agent(
    monkeypatch, proxied, address
):
    received, dials = [], []

    async def serve(reader, writer):
        headers = await reader.readuntil(b"\r\n\r\n")
        body = await reader.readexactly(7)
        received.append((headers, body))
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        )
        await writer.drain()
        await close_writer(writer)

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    local_port = server.sockets[0].getsockname()[1]
    original_dial = AnyIOBackend.connect_tcp

    async def dial(self, host, port, **kwargs):
        dials.append((host, port))
        return await original_dial(self, host="127.0.0.1", port=local_port, **kwargs)

    async def resolve(host, port):
        assert (host, port) == ("public.example.com", 80)
        return [address]

    monkeypatch.setattr(AnyIOBackend, "connect_tcp", dial)
    monkeypatch.setattr(safety, "_resolve", resolve)
    monkeypatch.setattr(proxy_app, "PROXY_LIST_URL", None)
    try:
        async with proxy_app.app.router.lifespan_context(proxy_app.app):
            monkeypatch.setattr(
                proxy_app, "PROXY_LIST_URL", "https://operator.example.com/list"
            )
            proxy_app.app.state.proxy_pool.proxies = ["upstream.example.com:8080"]
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=proxy_app.app),
                base_url="http://proxy.test",
            ) as client:
                prefix = "/p/" if proxied else "/"
                response = await client.post(
                    prefix + quote("http://public.example.com/doc?discard=1", safe=""),
                    params={"outer": "kept"},
                    headers={"User-Agent": "PodPie/1.0"},
                    content=b"payload",
                )
    finally:
        server.close()
        await server.wait_closed()
    assert response.content == b"ok"
    assert dials == [("upstream.example.com", 8080) if proxied else (address, 80)]
    headers, body = received[0]
    authority = f"[{address}]" if ":" in address else address
    request_target = (
        f"http://{authority}/doc?outer=kept" if proxied else "/doc?outer=kept"
    )
    assert headers.startswith(f"POST {request_target} HTTP/1.1\r\n".encode())
    assert b"host: public.example.com\r\n" in headers.lower()
    assert b"user-agent: PodPie/1.0\r\n" in headers
    assert body == b"payload"


@pytest.mark.anyio
@pytest.mark.parametrize("proxied", [False, True])
async def test_real_tls_falls_back_without_resolving_again_or_replaying_body(
    monkeypatch, tls_certificate, wire_servers, proxied
):
    origin_port, proxy_port, sni, connects, received = wire_servers
    original_dial = AnyIOBackend.connect_tcp
    resolutions, dials = [], []

    async def resolve(host, port):
        resolutions.append((host, port))
        return ["93.184.216.35", "2606:4700:4700::1111"]

    async def dial(self, host, port, **kwargs):
        dials.append((host, port))
        if not proxied and host == "93.184.216.35":
            raise httpx.ConnectError("first validated address unavailable")
        return await original_dial(
            self,
            host="127.0.0.1",
            port=proxy_port if proxied else origin_port,
            **kwargs,
        )

    monkeypatch.setattr(AnyIOBackend, "connect_tcp", dial)
    monkeypatch.setattr(safety, "_resolve", resolve)
    monkeypatch.setenv("SSL_CERT_FILE", str(tls_certificate[0]))
    transport = safety.PublicDestinationTransport(
        proxy="http://upstream.example.com:8080" if proxied else None
    )
    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        response = await client.post(
            "https://public.example.com/document", content=b"payload"
        )
    assert response.content == b"data"
    assert resolutions == [("public.example.com", 443)]
    assert len(dials) == 2
    assert sni == ["public.example.com"]
    assert len(received) == 1
    assert received[0].startswith(b"POST /document HTTP/1.1\r\n")
    assert received[0].endswith(b"\r\n\r\npayload")
    if proxied:
        assert connects[0].startswith(b"CONNECT 93.184.216.35:443 ")
        assert connects[1].startswith(b"CONNECT [2606:4700:4700::1111]:443 ")
    else:
        assert dials == [("93.184.216.35", 443), ("2606:4700:4700::1111", 443)]
    assert not transport._active
