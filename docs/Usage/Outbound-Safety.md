# Standalone app: shared outbound destination safety

The runnable `app.py` applies the same public-destination policy to **both**
`/{path:path}` (direct egress) and `/p/{path:path}` (rotating upstream HTTP proxy).
There is no separate `/rss` endpoint. This is application configuration, not a
change to the reusable library's default filters or its reverse/WebSocket proxies.

## Requests and compatibility

Send any public HTTP(S) resource through the ordinary route; use `/p/` only when
upstream proxy rotation is wanted. Methods, request/response streaming and upstream
status/response headers retain the library's forwarding semantics. The caller's
User-Agent is passed through (`PodPie/1.0` is not imposed on other consumers).
There is no XML interpretation or feed-only content type, decompression rule,
16 MiB byte cap or 30-second whole-feed deadline. Existing HTTPX inactivity
and rotating connect/read/write/pool timeouts remain; DNS validation uses the
request's connect timeout. Streaming responses close their per-hop transport on
completion; client close also releases outstanding/discarded retry transports.

Behind reverse proxies that normalize slashes, percent-encode the entire target
origin/path into a single path component. Keep target query parameters on the
**outer** request: `ForwardHttpProxy` replaces the encoded URL's query with the
incoming query parameters (including repeated keys).

```python
from urllib.parse import quote

import httpx

path = quote("https://example.com/any/resource", safe="")
response = httpx.get(
    "http://127.0.0.1:8000/" + path,
    params=[("format", "rss"), ("tag", "a"), ("tag", "b")],
    headers={"User-Agent": "PodPie/1.0"},
)
```

## Preconnection policy, on every followed redirect

- Only HTTP on port 80 and HTTPS on port 443 are accepted.
- Raw credentials (including empty userinfo), controls, backslashes, invalid/local
  hostnames, private/local/non-global/multicast/reserved addresses, mapped IPv6,
  translation/tunneling ranges and explicitly listed special-use networks are denied.
- DNS uses the original ASCII/IDNA hostname. **Every** returned A/AAAA address must
  be public; an empty or mixed public/private answer is denied. Same-host redirects
  resolve again, so rebinding cannot inherit an earlier validation result.
- A fresh non-pooling `AsyncHTTPTransport` is created **after** validation for each
  hop. The wire request URL contains a validated numeric address, while `Host`
  retains the original origin. This runs after `ForwardHttpProxy` prepares headers.
  The logical HTTPX request URL is not mutated, so relative redirects, cross-origin
  header handling and query/method redirect semantics still use the original URL.
- Direct sockets dial only the selected numeric address. Proxied HTTP uses a
  numeric absolute-form request target; proxied HTTPS sends numeric `CONNECT`.
  Public IPv4 and IPv6 targets are supported (IPv6 CONNECT authorities are bracketed).
- TLS certificate chain **and original-hostname** verification are enabled for
  both routes. Direct HTTPS uses the `sni_hostname` extension. HTTPcore 1.0.9's
  CONNECT tunnel does **not** honor that extension: a per-hop network-stream adapter
  restores the original server name for the origin TLS handshake. It also corrects
  that version's unbracketed IPv6 CONNECT authority. Only HTTP upstream proxies
  are supported; HTTPS/SOCKS upstream configuration is intentionally rejected.
- HTTPS cannot downgrade back to HTTP anywhere in a followed redirect chain.
  Redirect state lives in the individual request's extensions, not shared client
  state. `FOLLOW_REDIRECTS` remains false by default: unfollowed redirects are
  returned unchanged and no redirect destination is contacted. When enabled,
  HTTPX's existing redirect count limit remains in effect, with raw redirect syntax
  checked before HTTPX normalization and destination DNS checked before the next dial.
- A destination-policy rejection returns 403 and does not evict an upstream proxy.
  Rotation/retries and the global proxy pool/refresher remain in place.
- Environment HTTP(S) proxy variables cannot reroute these destination requests;
  ordinary egress stays direct and `/p/` uses its selected operator-configured proxy.

## Trust boundary and deployment

Numeric forwarding removes the need for a **compliant** upstream proxy to resolve
an origin hostname. It is not control over the remote proxy's sockets. An untrusted
proxy can ignore the numeric absolute target/CONNECT authority, route using `Host`,
perform its own DNS lookup, follow hidden redirects or contact internal services.
No local preflight can guarantee otherwise. Use trusted upstreams and network-level
egress restrictions; do not advertise this as protection against a malicious remote
proxy. Operator-configured proxy-list fetching and proxy endpoints are trusted
configuration and are not subject to the user-destination public-only policy.

Pinned DNS does not authenticate HTTP plaintext, prevent abuse of public resources,
or validate returned XML. Consumers must still validate feed/XML before ingestion.
Restrict access to the proxy itself (authentication/rate limits/firewall as appropriate).

Runtime and cold-test dependencies pin **HTTPX 0.28.1 / HTTPcore 1.0.9** because the
transport/backend seam and CONNECT formatting are implementation-specific. Review
those sources and re-run wire/TLS regressions before changing either pin. Every
request/hop opens a new transport, trading connection reuse for isolation between
validated origins and TLS names.

## Verification

```bash
.venv/bin/pytest tests/test_forward_safety.py tests/test_forward_safety_tls.py -q
.venv/bin/pytest tests/ -q
.venv/bin/ruff check forward_safety.py tests/test_forward_safety.py tests/test_forward_safety_tls.py
.venv/bin/black --check forward_safety.py tests/test_forward_safety.py tests/test_forward_safety_tls.py
```

The tests exercise both real app routes and real HTTPX/HTTPcore sockets/TLS through
an in-process HTTP CONNECT relay (only TCP routing is redirected to test listeners).
They cover matching trusted certificates, wrong-host/untrusted failures, numeric
IPv4/IPv6 dials/CONNECT, original Host/SNI, HTTP absolute-form forwarding, POST body,
User-Agent/query preservation, private/mixed DNS rejection, rebinding/redirects,
large streaming responses and failed-proxy removal/retry cleanup. No live external
upstream proxy or production deployment is used by these tests.
