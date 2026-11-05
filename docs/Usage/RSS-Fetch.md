# Bounded public feed fetch (`app.py`)

`GET /rss?url=<percent-encoded-public-HTTP(S)-URL>` is a separate direct-egress
feed fetch endpoint. It is declared before the ordinary catchall. Existing
ordinary forwarding and `/p/` rotating-upstream forwarding retain their behavior;
neither route gains the guarantees described here.

```shell
curl --get --data-urlencode 'url=https://feeds.twit.tv/sn.xml' \
  http://127.0.0.1:8000/rss
```

## Contract

- Only HTTP port 80 or HTTPS port 443; credentials, local names, non-public IPs,
  IPv4-mapped IPv6 and IPv6 translation/tunnel ranges are rejected. Public HTTP
  feeds are intentionally supported; HTTPS connections always verify certificates.
- All addresses returned by DNS must pass the public-address policy. Every hop
  resolves anew and connects only to a validated numeric IP while retaining the
  original ASCII hostname in `Host`, TLS SNI and certificate hostname checking.
  Validation is not followed by an unpinned hostname fetch.
- Redirects are followed manually, at most five. All redirect destinations are
  revalidated. Once HTTPS is used, downgrade to HTTP is rejected.
- One 30-second wall-clock deadline covers DNS, connection/TLS, redirects and
  body reads together. OS DNS resolver work already running in an executor may
  finish after cancellation, but no subsequent connection is initiated by it.
- Responses are counted while streaming from the origin, up to 16 MiB. Declared
  lengths exceeding the cap are rejected before reading. No partial body is
  returned on failure: bounded bytes are buffered before responding.
- Outbound requests ask for `identity` encoding; other `Content-Encoding`
  values are rejected before body consumption, including redirect responses.
- No incoming authentication, cookies, ranges or other caller headers are
  forwarded. Clients are fresh per hop, so origin cookies cannot follow redirects.
  Environment proxy variables and the rotating proxy pool are not used.
- Only successful origin responses yield bytes. Origin headers, status details,
  cookies and diagnostics are not relayed. Successful bytes are served as an
  XML attachment, with `nosniff`, a restrictive CSP and `no-store`, not as a
  transparent arbitrary-media response.
- There is no filename-extension, domain allowlist or XML-parser restriction:
  public feed URLs need not end in `.xml`. **The caller must still validate XML
  and feed structure and disable dangerous DTD/entity processing.** Non-feed
  content is not made into a valid feed by this endpoint. Media downloads should
  not use this endpoint.

Errors are generic JSON: `400` invalid/blocked destination, `413` oversized feed,
`504` deadline/network timeout, `502` other origin/DNS/TLS/protocol failures or
excess redirects. No target IP, resolver details or exception text is returned.

## Transport dependency and verification

The app requirements pin HTTPX 0.28.1 / HTTPcore 1.0.9. The implementation uses
HTTPcore's documented `sni_hostname` request extension, passed unchanged through
HTTPX's transport. Consult the upstream HTTPcore extensions documentation and
`httpcore/_async/connection.py` / `httpx/_transports/default.py` for those versions.

Run the existing suite and focused security tests in a project virtualenv:

```shell
.venv/bin/python -m pytest tests/ -q
.venv/bin/ruff check rss_fetch.py tests/test_rss.py
.venv/bin/black --check rss_fetch.py tests/test_rss.py
```

The tests include real local TLS handshakes using OpenSSL-generated certificates
(OpenSSL CLI required). Only the TCP destination is rerouted to the local test
server: HTTPX/HTTPcore/TLS execute unchanged. They assert the numeric dial target,
wire `Host`, actual SNI, successful matching-certificate verification, and failure
for wrong-host or untrusted certificates. The tests also set failing environment
proxy URLs to verify direct egress. Other cases exercise private/mixed DNS,
redirect rebinding, byte limits, compression rejection and shared deadlines.
