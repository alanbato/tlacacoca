# Client Certificate Authentication

This guide shows you how to implement client certificate authentication using Tlacacoca's `CertificateAuth` middleware and TLS context configuration.

## Prerequisites

- Tlacacoca installed (see [Installation](../installation.md))
- Understanding of TLS certificates

## Overview

Client certificate authentication allows servers to verify client identity. The server requests a certificate during TLS handshake and validates it against a list of authorized fingerprints.

## Server-Side Setup

### Configure TLS Context for Client Certificates

```python
from tlacacoca import create_server_context

# Create context that requests client certificates
ssl_context = create_server_context(
    certfile="server.pem",
    keyfile="server.key",
    request_client_cert=True,
    client_ca_certs=["trusted_client1.pem", "trusted_client2.pem"]
)
```

!!! warning "OpenSSL 3.x Requirement"
    When using `request_client_cert=True` with OpenSSL 3.x, you **must** provide `client_ca_certs`. For self-signed client certificates, include each client's certificate file in this list.

### Configure CertificateAuth Middleware

```python
from tlacacoca import (
    CertificateAuth,
    CertificateAuthConfig,
    CertificateAuthPathRule,
)

# Define which paths require authentication
config = CertificateAuthConfig(
    rules=[
        CertificateAuthPathRule(
            path_prefix="/admin/",
            require_cert=True,
            allowed_fingerprints=[
                "sha256:abc123...",  # Admin user 1
                "sha256:def456...",  # Admin user 2
            ]
        ),
        CertificateAuthPathRule(
            path_prefix="/private/",
            require_cert=True,
            # Any valid client cert is allowed
        ),
    ]
)

cert_auth = CertificateAuth(config)
```

### Process Requests

```python
async def handle_request(url: str, client_ip: str, client_cert_fingerprint: str | None):
    result = await cert_auth.process_request(url, client_ip, client_cert_fingerprint)

    if not result.allowed:
        if result.denial_reason == DenialReason.CERT_REQUIRED:
            # Gemini: "60 Client certificate required\r\n"
            return require_cert_response()
        elif result.denial_reason == DenialReason.CERT_NOT_AUTHORIZED:
            # Gemini: "61 Certificate not authorized\r\n"
            return not_authorized_response()

    # Continue processing
    return process_request(url)
```

## Client-Side Setup

### Generate Client Certificate

```python
from tlacacoca import generate_self_signed_cert

# Generate client identity certificate
cert_pem, key_pem = generate_self_signed_cert(
    hostname="client-identity",
    organization="Alice's Identity",
    valid_days=730  # 2 years
)

# Save certificate
from pathlib import Path
Path("alice.pem").write_bytes(cert_pem)
Path("alice.key").write_bytes(key_pem)
Path("alice.key").chmod(0o600)  # Protect private key
```

### Connect with Client Certificate

```python
from tlacacoca import create_client_context
import ssl

# Create context with client certificate
ssl_context = create_client_context(
    verify_mode=ssl.CERT_NONE,  # Or use TOFU
    check_hostname=False,
    certfile="alice.pem",
    keyfile="alice.key"
)

# Use context for connections
import asyncio

async def fetch_protected_resource():
    reader, writer = await asyncio.open_connection(
        "example.com",
        1965,
        ssl=ssl_context
    )

    # Send request
    writer.write(b"protocol://example.com/admin/users\r\n")
    await writer.drain()

    # Read response
    response = await reader.read()

    writer.close()
    await writer.wait_closed()

    return response
```

## Path-Based Rules

### Protect Specific Paths

```python
config = CertificateAuthConfig(
    rules=[
        # Admin area - specific fingerprints only
        CertificateAuthPathRule(
            path_prefix="/admin/",
            require_cert=True,
            allowed_fingerprints=["sha256:admin1...", "sha256:admin2..."]
        ),

        # User area - any valid cert
        CertificateAuthPathRule(
            path_prefix="/user/",
            require_cert=True,
        ),

        # Public area - no cert needed (default behavior)
    ]
)
```

### Order Matters

Rules are matched in order. More specific paths should come first:

```python
config = CertificateAuthConfig(
    rules=[
        # Specific paths first
        CertificateAuthPathRule(
            path_prefix="/admin/super/",
            require_cert=True,
            allowed_fingerprints=["sha256:superadmin..."]
        ),

        # Then broader paths
        CertificateAuthPathRule(
            path_prefix="/admin/",
            require_cert=True,
            allowed_fingerprints=["sha256:admin1...", "sha256:admin2..."]
        ),
    ]
)
```

## Get Certificate Fingerprint from TLS Connection

### During TLS Handshake

```python
import asyncio
from tlacacoca import get_certificate_fingerprint
from cryptography import x509

async def get_client_fingerprint(writer) -> str | None:
    """Extract client certificate fingerprint from TLS connection."""
    ssl_object = writer.get_extra_info('ssl_object')

    if ssl_object is None:
        return None

    # Get peer certificate (client's cert)
    cert_der = ssl_object.getpeercert(binary_form=True)

    if cert_der is None:
        return None  # Client didn't send certificate

    # Parse and fingerprint
    cert = x509.load_der_x509_certificate(cert_der)
    return get_certificate_fingerprint(cert)
```

## Use in Middleware Chain

```python
from tlacacoca import (
    MiddlewareChain,
    AccessControl,
    AccessControlConfig,
    RateLimiter,
    RateLimitConfig,
    CertificateAuth,
    CertificateAuthConfig,
    CertificateAuthPathRule,
)

# Configure all middleware
access_config = AccessControlConfig(default_allow=True)
rate_config = RateLimitConfig(capacity=10, refill_rate=1.0)
cert_config = CertificateAuthConfig(
    rules=[
        CertificateAuthPathRule(
            path_prefix="/admin/",
            require_cert=True,
            allowed_fingerprints=["sha256:..."]
        ),
    ]
)

# Create chain
chain = MiddlewareChain([
    AccessControl(access_config),   # 1. Check IP
    RateLimiter(rate_config),        # 2. Check rate limit
    CertificateAuth(cert_config),   # 3. Check certificate
])

# Process request
async def handle_request(url: str, client_ip: str, cert_fp: str | None):
    result = await chain.process_request(url, client_ip, cert_fp)

    if not result.allowed:
        return deny_response(result.denial_reason)

    return process_request(url)
```

## Complete Server Example

```python
import asyncio
from tlacacoca import (
    create_server_context,
    get_certificate_fingerprint,
    MiddlewareChain,
    CertificateAuth,
    CertificateAuthConfig,
    CertificateAuthPathRule,
    DenialReason,
)
from cryptography import x509

# Configure certificate authentication
cert_config = CertificateAuthConfig(
    rules=[
        CertificateAuthPathRule(
            path_prefix="/private/",
            require_cert=True,
            allowed_fingerprints=[
                "sha256:abc123...",
                "sha256:def456...",
            ]
        ),
    ]
)

cert_auth = CertificateAuth(cert_config)

# Create TLS context with client cert support
ssl_context = create_server_context(
    certfile="server.pem",
    keyfile="server.key",
    request_client_cert=True,
    client_ca_certs=["client1.pem", "client2.pem"]
)

async def handle_client(reader, writer):
    # Get client info
    peername = writer.get_extra_info('peername')
    client_ip = peername[0] if peername else "unknown"

    # Get client certificate fingerprint
    ssl_object = writer.get_extra_info('ssl_object')
    cert_fingerprint = None

    if ssl_object:
        cert_der = ssl_object.getpeercert(binary_form=True)
        if cert_der:
            cert = x509.load_der_x509_certificate(cert_der)
            cert_fingerprint = get_certificate_fingerprint(cert)

    try:
        # Read request
        data = await reader.readline()
        url = data.decode().strip()

        # Check certificate authentication
        result = await cert_auth.process_request(url, client_ip, cert_fingerprint)

        if not result.allowed:
            if result.denial_reason == DenialReason.CERT_REQUIRED:
                writer.write(b"60 Client certificate required\r\n")
            elif result.denial_reason == DenialReason.CERT_NOT_AUTHORIZED:
                writer.write(b"61 Certificate not authorized\r\n")
        else:
            # Process request
            writer.write(b"20 text/plain\r\nWelcome!\r\n")

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

    async with server:
        await server.serve_forever()

asyncio.run(main())
```

## Troubleshooting

### Client Certificate Not Received

**Problem:** Server doesn't receive client certificate.

**Causes:**

1. Client didn't provide certificate
2. TLS context not configured to request certs
3. OpenSSL 3.x without client_ca_certs

**Solutions:**

```python
# Ensure server requests certificates
ssl_context = create_server_context(
    certfile="server.pem",
    keyfile="server.key",
    request_client_cert=True,
    client_ca_certs=["all_trusted_clients.pem"]  # Required for OpenSSL 3.x
)
```

### Certificate Not Authorized

**Problem:** Valid certificate is rejected.

**Check:**

1. Fingerprint format matches (sha256:...)
2. Fingerprint is in allowed_fingerprints list
3. Path matches the rule's path_prefix

```python
# Debug: print certificate fingerprint
from tlacacoca import load_certificate, get_certificate_fingerprint

cert = load_certificate(Path("client.pem"))
fp = get_certificate_fingerprint(cert)
print(f"Client fingerprint: {fp}")

# Then add to allowed_fingerprints
```

### TLS Handshake Fails

**Problem:** Connection fails during TLS handshake with client certs.

**Common causes:**

1. OpenSSL 3.x without proper CA certs loaded
2. Client certificate expired
3. Client key doesn't match certificate

**Solution for OpenSSL 3.x:**

```python
# For self-signed client certs, add each client cert as a trusted CA
ssl_context = create_server_context(
    certfile="server.pem",
    keyfile="server.key",
    request_client_cert=True,
    client_ca_certs=[
        "client1.pem",  # Each self-signed client cert
        "client2.pem",
        # Or a CA cert if using CA-signed client certs
    ]
)
```

## See Also

- [Certificate Management](certificates.md) - Generate and manage certificates
- [API Reference](../reference/api/middleware.md) - CertificateAuth class documentation
- [Security Model](../explanation/security-model.md) - Understanding authentication
