# Run Behind a TCP Proxy (PROXY Protocol)

This guide shows you how to keep real client IP addresses when your `TLSServerProtocol` server sits behind a TCP relay such as HAProxy, Traefik, nginx `stream`, or a cloud load balancer.

## Prerequisites

- Tlacacoca installed (see [Installation](../installation.md))
- A server using `TLSServerProtocol` (see [Client Certificates](client-certificates.md))
- A relay that does **raw TCP passthrough** (no TLS termination) and can send a PROXY protocol header

## Why You Need It

A TCP relay opens its own connection to your server, so every client appears to come from the relay's IP. Anything keyed on the client IP stops working:

- `RateLimiter` collapses into a single bucket shared by everyone
- `AccessControl` allow/deny lists only ever see the relay
- Logs lose the real client addresses

The [PROXY protocol](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt) fixes this. The relay sends a small header with the original client address *before* the TLS ClientHello. Because `TLSServerProtocol` handles TLS manually, it can read that plaintext header, strip it, and then run the TLS handshake on the bytes that follow.

Both header formats are supported:

- **Version 2** (binary): IPv4, IPv6, `LOCAL`, and TLVs
- **Version 1** (text): `TCP4`, `TCP6`, and `UNKNOWN`

## Enable PROXY Protocol

PROXY protocol is **disabled by default**. Enable it by passing a `ProxyProtocolConfig` with the addresses of your relays:

```python
import asyncio

from tlacacoca import (
    ProxyProtocolConfig,
    TLSServerProtocol,
    create_permissive_server_context,
)

ssl_ctx = create_permissive_server_context(
    "server.pem", "server.key", request_client_cert=True
)

proxy = ProxyProtocolConfig(
    trusted_sources=[
        "100.101.1.2",            # the relay's address as seen by this server
        "fd7a:115c:a1e0::1",      # IPv6 works too
        "10.0.0.0/29",            # CIDRs are fine, but keep them tight
    ],
)

loop = asyncio.get_running_loop()
server = await loop.create_server(
    lambda: TLSServerProtocol(MyProtocol, ssl_ctx, proxy_protocol=proxy),
    "0.0.0.0",
    1965,
)
```

Invalid entries in `trusted_sources` raise `ValueError` when the config is created, so typos fail at startup.

!!! warning "Only list your relays"
    Any host in `trusted_sources` can claim any client address. List the relays' own addresses, not a whole network. For example, trusting an entire VPN or tailnet range would let every device on it spoof client IPs.

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `trusted_sources` | `[]` | IPs/CIDRs of relays allowed to send PROXY headers |
| `header_timeout` | `5.0` | Seconds a trusted relay has to send a complete header |
| `max_header_size` | `4096` | Maximum total header size in bytes (including TLVs) |

## Read the Client Address

Your inner protocol reads the client address the usual way. No code changes are needed:

```python
class MyProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        client_ip, client_port = transport.get_extra_info("peername")[:2]
```

When a trusted relay supplied a client address, `peername` returns that address. IPv4 addresses come back as `(host, port)` and IPv6 addresses as `(host, port, 0, 0)`, the same shapes asyncio uses for sockets.

Two extra keys help with debugging:

| Key | Value |
|-----|-------|
| `"proxy_peername"` | The relay's socket address if the header supplied the client address, otherwise `None` |
| `"proxy_header"` | The parsed `ProxyHeader` (version, command, addresses, TLVs), or `None` |

## How Trust Works

A PROXY header lets the sender claim **any** source address, so tlacacoca only honors headers from `trusted_sources`. The decision depends on the connection's real socket peer:

| Socket peer | Sends a PROXY header | Result |
|-------------|----------------------|--------|
| Trusted | Valid header | Client address from the header |
| Trusted | `LOCAL`, `UNKNOWN`, or `UNSPEC` header | Real socket peer (e.g. relay health checks) |
| Trusted | No header, malformed, or oversized | Connection closed, `proxy_protocol_invalid_header` logged |
| Trusted | Too slow (past `header_timeout`) | Connection closed, `proxy_protocol_timeout` logged |
| Untrusted | Anything that looks like a header | Connection closed, `proxy_protocol_untrusted_source` logged |
| Untrusted | No header (plain TLS) | Direct connection, real socket peer |

Notes:

- A trusted relay **must** send a header. The server never guesses whether one is present.
- Connections from untrusted peers are treated as direct clients, so you can still connect without the relay (for example, from inside your private network). If you want the relay to be the *only* way in, restrict the listener with a firewall.
- Dual-stack sockets report IPv4 peers as `::ffff:a.b.c.d`. These are matched against IPv4 entries in `trusted_sources`.
- Any bytes after the header in the same TCP segment are passed to TLS unchanged. Headers split across several segments are reassembled.

## Configure Your Relay

The relay must do TCP passthrough and send the PROXY header. Version 2 is recommended.

=== "Traefik"

    ```yaml
    tcp:
      services:
        my-service:
          loadBalancer:
            proxyProtocol:
              version: 2
            servers:
              - address: "100.101.102.103:1965"
    ```

    Newer Traefik releases also allow setting this on a TCP `serversTransport`. Check the docs for your version.

=== "HAProxy"

    ```text
    backend my_backend
        mode tcp
        server home 100.101.102.103:1965 send-proxy-v2
    ```

=== "nginx"

    ```nginx
    stream {
        server {
            listen 1965;
            proxy_pass 100.101.102.103:1965;
            proxy_protocol on;
        }
    }
    ```

## Troubleshooting

| Log event | Meaning |
|-----------|---------|
| `proxy_protocol_invalid_header` with `missing PROXY protocol header` | A trusted peer connected without a header. Check that the relay sends PROXY protocol, or remove that peer from `trusted_sources`. |
| `proxy_protocol_untrusted_source` | A peer outside `trusted_sources` sent a header. Add the relay's address (as seen by the server) to `trusted_sources`. |
| `proxy_protocol_timeout` | A trusted peer connected but did not finish the header within `header_timeout`. |
| `proxy_protocol_incomplete_header` | A trusted peer disconnected partway through a header. |
| `tls_error` right after enabling a relay | PROXY protocol is enabled on the relay but not on the server. |

## See Also

- [Rate Limiting](rate-limiting.md) - Per-IP rate limits, which depend on accurate client IPs
- [Access Control](access-control.md) - IP allow/deny lists
- [Security API Reference](../reference/api/security.md#proxyprotocolconfig)
