# Quick Start

Get up and running with Tlacacoca in 5 minutes. This guide covers the most common use cases to help you integrate security and middleware components into your TLS-based protocol implementation.

## Prerequisites

- Python 3.10 or higher
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

**Install uv** (if you don't have it):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Installation

```bash
# Add to your project
uv add tlacacoca

# Or with pip
pip install tlacacoca
```

---

## Use Case 1: TLS Context Creation

Create secure TLS contexts for client and server connections.

### Client TLS Context

```python
import ssl
from tlacacoca import create_client_context

# Development/testing - accept all certificates
context = create_client_context()

# Production - with certificate verification
# (Combine with TOFU for full validation)
context = create_client_context(
    verify_mode=ssl.CERT_REQUIRED,
    check_hostname=True
)

# With client certificate authentication
context = create_client_context(
    verify_mode=ssl.CERT_REQUIRED,
    check_hostname=True,
    certfile="client.pem",
    keyfile="client-key.pem"
)
```

### Server TLS Context

```python
from tlacacoca import create_server_context

# Basic server
context = create_server_context(
    certfile="server.pem",
    keyfile="server-key.pem"
)

# Server requesting client certificates
context = create_server_context(
    certfile="server.pem",
    keyfile="server-key.pem",
    request_client_cert=True,
    client_ca_certs=["trusted_client1.pem", "trusted_client2.pem"]
)
```

### Server Accepting Self-Signed Client Certificates

For TOFU-based protocols where clients have their own self-signed certificates:

```python
import asyncio
from tlacacoca import (
    create_permissive_server_context,
    TLSServerProtocol,
)

# Create PyOpenSSL context that accepts ANY client certificate
pyopenssl_ctx = create_permissive_server_context(
    certfile="server.pem",
    keyfile="server-key.pem",
    request_client_cert=True,
)

class MyProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport
        # Client cert is available as a cryptography object
        cert = transport.peer_certificate  # or None

    def data_received(self, data: bytes):
        self.transport.write(data)  # echo
        self.transport.close()

    def connection_lost(self, exc):
        pass

async def main():
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: TLSServerProtocol(MyProtocol, pyopenssl_ctx),
        "localhost", 1965,
        # No ssl= parameter — TLS handled by TLSServerProtocol
    )
    async with server:
        await server.serve_forever()
```

**Next Steps:**

- See [Certificate Management](how-to/certificates.md) for generating certificates
- Learn about [Client Certificate Authentication](how-to/client-certificates.md)

---

## Use Case 2: Certificate Management

Generate, load, and validate TLS certificates.

### Generate Self-Signed Certificates

```python
from pathlib import Path
from tlacacoca import generate_self_signed_cert

# Generate certificate for localhost
cert_pem, key_pem = generate_self_signed_cert("localhost")

# Save to files
Path("cert.pem").write_bytes(cert_pem)
Path("key.pem").write_bytes(key_pem)

# Generate with custom options
cert_pem, key_pem = generate_self_signed_cert(
    hostname="example.com",
    key_size=4096,
    valid_days=365,
    organization="My Organization"
)
```

### Load and Inspect Certificates

```python
from tlacacoca import (
    load_certificate,
    get_certificate_fingerprint,
    get_certificate_info,
    is_certificate_expired,
)

# Load certificate
cert = load_certificate(Path("cert.pem"))

# Get fingerprint (for TOFU)
fingerprint = get_certificate_fingerprint(cert)
print(f"SHA-256: {fingerprint}")

# Get detailed information
info = get_certificate_info(cert)
print(f"Subject: {info['subject']}")
print(f"Valid until: {info['not_after']}")

# Check expiration
if is_certificate_expired(cert):
    print("Certificate has expired!")
```

**Next Steps:**

- See [Certificate Management How-to](how-to/certificates.md) for advanced usage
- Learn about [TOFU Validation](how-to/tofu.md)

---

## Use Case 3: TOFU Certificate Validation

Implement Trust-On-First-Use certificate validation for your client.

### Basic TOFU Workflow

```python
import asyncio
from tlacacoca import TOFUDatabase, CertificateChangedError

async def verify_server_certificate(hostname: str, port: int, fingerprint: str):
    """Verify a server's certificate using TOFU."""
    async with TOFUDatabase(app_name="myapp") as tofu:
        # Check if we know this host
        if await tofu.is_known(hostname, port):
            # Verify fingerprint matches
            stored = await tofu.get_fingerprint(hostname, port)
            if stored != fingerprint:
                raise CertificateChangedError(
                    hostname, port, stored, fingerprint
                )
            print(f"Certificate verified for {hostname}:{port}")
        else:
            # First connection - trust and store
            await tofu.trust(hostname, port, fingerprint)
            print(f"First connection to {hostname}:{port} - certificate trusted")

# Use it
asyncio.run(verify_server_certificate("example.com", 1965, "sha256:abc123..."))
```

### Managing Known Hosts

```python
async def manage_tofu():
    async with TOFUDatabase(app_name="myapp") as tofu:
        # List all known hosts
        hosts = await tofu.list_hosts()
        for host in hosts:
            print(f"{host['hostname']}:{host['port']}")

        # Revoke trust for a host
        await tofu.revoke("old-server.com", 1965)

        # Export database for backup
        await tofu.export_toml(Path("tofu-backup.toml"))

        # Import from backup
        await tofu.import_toml(Path("tofu-backup.toml"))
```

**Next Steps:**

- See [TOFU How-to Guide](how-to/tofu.md) for detailed usage
- Learn about the [Security Model](explanation/security-model.md)

---

## Use Case 4: Rate Limiting

Protect your server from DoS attacks with token bucket rate limiting.

### Basic Rate Limiting

```python
from tlacacoca import RateLimiter, RateLimitConfig, DenialReason

# Configure rate limiter
config = RateLimitConfig(
    capacity=10,        # Burst size
    refill_rate=1.0,    # Tokens per second
    retry_after=30,     # Seconds to wait when limited
)

# Create rate limiter
rate_limiter = RateLimiter(config)

# Process a request
async def handle_request(client_ip: str, url: str):
    result = await rate_limiter.process_request(url, client_ip)

    if not result.allowed:
        # Map to protocol-specific response
        # Gemini: "44 SLOW DOWN. Retry after 30 seconds\r\n"
        # Scroll: "44 SLOW_DOWN 30\r\n"
        return f"Rate limited. Retry after {result.retry_after} seconds"

    # Handle request normally
    return "OK"
```

### Standalone Token Bucket

For custom rate limiting implementations:

```python
from tlacacoca import TokenBucket

# Create bucket
bucket = TokenBucket(capacity=10, refill_rate=1.0)

# Check if request is allowed
if bucket.consume():
    # Request allowed
    pass
else:
    # Request denied - bucket empty
    pass

# Get current token count
tokens = bucket.tokens
```

**Next Steps:**

- See [Rate Limiting How-to](how-to/rate-limiting.md) for configuration options
- Learn about [Access Control](how-to/access-control.md)

---

## Use Case 5: IP Access Control

Restrict access to your server based on client IP addresses.

### Allow/Deny Lists

```python
from tlacacoca import AccessControl, AccessControlConfig

# Whitelist mode - only allow specific IPs
config = AccessControlConfig(
    allow_list=["192.168.1.0/24", "10.0.0.0/8"],
    default_allow=False
)

# Blacklist mode - allow all except specific IPs
config = AccessControlConfig(
    deny_list=["203.0.113.0/24", "198.51.100.50"],
    default_allow=True
)

# Create access control
access_control = AccessControl(config)

# Check access
async def check_client_access(client_ip: str, url: str):
    result = await access_control.process_request(url, client_ip)

    if not result.allowed:
        # Gemini: "53 PROXY REFUSED\r\n"
        return "Access denied"

    return "Access granted"
```

**Next Steps:**

- See [Access Control How-to](how-to/access-control.md) for CIDR examples
- Learn about [Certificate Authentication](how-to/client-certificates.md)

---

## Use Case 6: Middleware Chain

Combine multiple middleware components for comprehensive request processing.

### Building a Middleware Chain

```python
from tlacacoca import (
    MiddlewareChain,
    RateLimiter,
    RateLimitConfig,
    AccessControl,
    AccessControlConfig,
    CertificateAuth,
    CertificateAuthConfig,
    DenialReason,
)

# Configure each middleware
access_config = AccessControlConfig(
    deny_list=["203.0.113.0/24"],
    default_allow=True
)

rate_config = RateLimitConfig(
    capacity=10,
    refill_rate=1.0,
    retry_after=30
)

# Create middleware chain
# Order matters: access control → rate limiting → cert auth
chain = MiddlewareChain([
    AccessControl(access_config),
    RateLimiter(rate_config),
])

# Process requests
async def process_request(url: str, client_ip: str, cert_fingerprint: str = None):
    result = await chain.process_request(url, client_ip, cert_fingerprint)

    if not result.allowed:
        # Map denial reason to protocol-specific response
        match result.denial_reason:
            case DenialReason.ACCESS_DENIED:
                return "53 Access denied\r\n"
            case DenialReason.RATE_LIMIT:
                return f"44 Rate limited. Retry after {result.retry_after}s\r\n"
            case DenialReason.CERT_REQUIRED:
                return "60 Client certificate required\r\n"
            case DenialReason.CERT_NOT_AUTHORIZED:
                return "61 Certificate not authorized\r\n"
            case _:
                return "50 Server error\r\n"

    # Request allowed - continue processing
    return handle_request(url)
```

**Next Steps:**

- See [API Reference](reference/api/middleware.md) for all middleware options
- Learn about extending `DenialReason` for custom protocols

---

## Use Case 7: Structured Logging

Configure privacy-preserving structured logging.

### Basic Setup

```python
from tlacacoca import configure_logging, get_logger

# Configure logging
configure_logging(
    level="INFO",
    format="json",  # or "console" for development
    hash_ips=True   # Privacy-preserving IP hashing
)

# Get a logger
log = get_logger("myapp.server")

# Log structured events
log.info("server_started", host="localhost", port=1965)
log.info("request_received", url="/index.gmi", client_ip="192.168.1.100")
log.warning("rate_limited", client_ip="203.0.113.50", retry_after=30)
log.error("connection_failed", error="timeout", host="upstream.example.com")
```

### Privacy-Preserving IP Logging

```python
from tlacacoca import hash_ip_processor
import structlog

# The hash_ip_processor automatically hashes IP addresses
# 192.168.1.100 → a1b2c3d4... (deterministic hash)

# This allows:
# - Tracking requests from the same client
# - Detecting abuse patterns
# - Complying with privacy regulations (GDPR)
```

**Next Steps:**

- See [Logging How-to](how-to/logging.md) for configuration options
- Learn about log output formats and filtering

---

## Complete Integration Example

Here's a complete example showing how to integrate tlacacoca into a simple TLS server:

```python
import asyncio
import ssl
from pathlib import Path
from tlacacoca import (
    # Security
    create_server_context,
    generate_self_signed_cert,
    # Middleware
    MiddlewareChain,
    RateLimiter,
    RateLimitConfig,
    AccessControl,
    AccessControlConfig,
    DenialReason,
    # Logging
    configure_logging,
    get_logger,
)

# Configure logging
configure_logging(level="INFO", hash_ips=True)
log = get_logger("myserver")

# Generate certificates (in production, use proper certs)
cert_pem, key_pem = generate_self_signed_cert("localhost")
Path("cert.pem").write_bytes(cert_pem)
Path("key.pem").write_bytes(key_pem)

# Create TLS context
ssl_context = create_server_context("cert.pem", "key.pem")

# Configure middleware
middleware = MiddlewareChain([
    AccessControl(AccessControlConfig(default_allow=True)),
    RateLimiter(RateLimitConfig(capacity=10, refill_rate=1.0)),
])

async def handle_client(reader, writer):
    """Handle a client connection."""
    # Get client IP
    peername = writer.get_extra_info('peername')
    client_ip = peername[0] if peername else "unknown"

    try:
        # Read request
        data = await reader.readline()
        url = data.decode().strip()

        log.info("request_received", url=url, client_ip=client_ip)

        # Process through middleware
        result = await middleware.process_request(url, client_ip)

        if not result.allowed:
            # Send protocol-specific denial response
            response = f"Error: {result.denial_reason}\r\n"
            writer.write(response.encode())
            log.warning("request_denied", reason=result.denial_reason, client_ip=client_ip)
        else:
            # Handle request
            response = "20 text/plain\r\nHello, World!\r\n"
            writer.write(response.encode())
            log.info("request_handled", url=url, client_ip=client_ip)

    except Exception as e:
        log.error("request_error", error=str(e), client_ip=client_ip)
    finally:
        writer.close()
        await writer.wait_closed()

async def main():
    server = await asyncio.start_server(
        handle_client,
        'localhost',
        1965,
        ssl=ssl_context
    )

    log.info("server_started", host="localhost", port=1965)

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Common Next Steps

Now that you've tried the basics, here are suggested learning paths:

### For Protocol Implementers

1. **[Security Model](explanation/security-model.md)** - Understand TOFU and TLS requirements
2. **[Certificate Management](how-to/certificates.md)** - Generate and manage certificates
3. **[Middleware API](reference/api/middleware.md)** - Complete middleware reference

### For Server Operators

1. **[Rate Limiting](how-to/rate-limiting.md)** - Configure protection against abuse
2. **[Access Control](how-to/access-control.md)** - IP-based access restrictions
3. **[Logging](how-to/logging.md)** - Set up privacy-preserving logging

### For Developers

1. **[API Reference](reference/index.md)** - Complete API documentation
2. **[Contributing Guide](https://github.com/alanbato/tlacacoca/blob/main/CONTRIBUTING.md)** - Join the project
3. **[Tutorials](tutorials/index.md)** - Step-by-step integration guides

---

## Getting Help

- **Documentation**: Browse this site for detailed guides and references
- **Issues**: Report bugs at [GitHub Issues](https://github.com/alanbato/tlacacoca/issues)
- **Discussions**: Ask questions at [GitHub Discussions](https://github.com/alanbato/tlacacoca/discussions)
