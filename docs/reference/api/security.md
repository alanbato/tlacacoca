# Security API Reference

This page documents the security-related modules in Tlacacoca, including TLS context creation, certificate management, and TOFU (Trust On First Use) validation.

## Overview

The security modules provide:

- **TLS Context Creation** (`tlacacoca.security.tls`) - Create SSL contexts for client and server connections
- **PyOpenSSL TLS** (`tlacacoca.security.pyopenssl_tls`, `tlacacoca.security.tls_protocol`) - Accept self-signed client certificates using PyOpenSSL with asyncio memory BIO integration
- **Certificate Management** (`tlacacoca.security.certificates`) - Generate, load, validate, and fingerprint TLS certificates
- **TOFU Database** (`tlacacoca.security.tofu`) - Store and verify certificate fingerprints for known hosts

## TLS Context Creation

### create_client_context

```python
def create_client_context(
    verify_mode: ssl.VerifyMode = ssl.CERT_NONE,
    check_hostname: bool = False,
    certfile: str | None = None,
    keyfile: str | None = None,
) -> ssl.SSLContext
```

Create an SSL context for client connections with TLS 1.2 as minimum version.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `verify_mode` | `ssl.VerifyMode` | `CERT_NONE` | Certificate verification mode |
| `check_hostname` | `bool` | `False` | Check certificate hostname |
| `certfile` | `str \| None` | `None` | Path to client certificate |
| `keyfile` | `str \| None` | `None` | Path to client private key |

**Returns:** `ssl.SSLContext` configured for client connections.

**Example:**

```python
import ssl
from tlacacoca import create_client_context

# Development - accept all certificates
context = create_client_context()

# Production with TOFU
context = create_client_context(
    verify_mode=ssl.CERT_REQUIRED,
    check_hostname=True
)

# With client certificate
context = create_client_context(
    certfile="client.pem",
    keyfile="client.key"
)
```

### create_server_context

```python
def create_server_context(
    certfile: str,
    keyfile: str,
    request_client_cert: bool = False,
    client_ca_certs: list[str] | None = None,
) -> ssl.SSLContext
```

Create an SSL context for server connections.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `certfile` | `str` | Required | Path to server certificate |
| `keyfile` | `str` | Required | Path to server private key |
| `request_client_cert` | `bool` | `False` | Request client certificates |
| `client_ca_certs` | `list[str] \| None` | `None` | CA certs for client verification |

**Returns:** `ssl.SSLContext` configured for server connections.

!!! warning "OpenSSL 3.x"
    When using `request_client_cert=True` with OpenSSL 3.x, you **must** provide `client_ca_certs`. For self-signed client certs, include each client's certificate file.

**Example:**

```python
from tlacacoca import create_server_context

# Basic server
context = create_server_context("cert.pem", "key.pem")

# With client certificates
context = create_server_context(
    "cert.pem",
    "key.pem",
    request_client_cert=True,
    client_ca_certs=["client1.pem", "client2.pem"]
)
```

## PyOpenSSL TLS (Self-Signed Client Certificates)

These components use PyOpenSSL to accept arbitrary self-signed client certificates during TLS handshake, deferring trust decisions to the application layer.

### create_permissive_server_context

```python
def create_permissive_server_context(
    certfile: str,
    keyfile: str,
    request_client_cert: bool = False,
    session_id: bytes | None = None,
) -> SSL.Context
```

Create a PyOpenSSL context that accepts any client certificate (including self-signed).

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `certfile` | `str` | Required | Path to server certificate (PEM) |
| `keyfile` | `str` | Required | Path to server private key (PEM) |
| `request_client_cert` | `bool` | `False` | Request client certificates |
| `session_id` | `bytes \| None` | `None` | Session ID for TLS resumption |

**Returns:** `OpenSSL.SSL.Context` configured for server connections.

!!! info "Use with TLSServerProtocol"
    PyOpenSSL contexts cannot be passed to asyncio's `ssl=` parameter. Use `TLSServerProtocol` for asyncio integration.

**Example:**

```python
from tlacacoca import create_permissive_server_context, TLSServerProtocol

ctx = create_permissive_server_context(
    "server.pem", "server.key",
    request_client_cert=True,
    session_id=b"myapp",
)

server = await loop.create_server(
    lambda: TLSServerProtocol(my_protocol_factory, ctx),
    host, port,
)
```

### TLSServerProtocol

```python
class TLSServerProtocol(asyncio.Protocol):
    def __init__(
        self,
        inner_protocol_factory: Callable[[], asyncio.Protocol],
        ssl_context: SSL.Context,
    ) -> None
```

An `asyncio.Protocol` that handles TLS manually using PyOpenSSL memory BIOs. Wraps an inner protocol, performing encryption/decryption transparently.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `inner_protocol_factory` | `Callable[[], asyncio.Protocol]` | Factory for the inner protocol |
| `ssl_context` | `SSL.Context` | PyOpenSSL context from `create_permissive_server_context()` |

**Flow:**

1. TCP connection established (no TLS)
2. `TLSServerProtocol` performs TLS handshake via memory BIOs
3. After handshake, inner protocol receives decrypted data
4. Inner protocol writes are encrypted and sent over TCP

### TLSTransportWrapper

```python
class TLSTransportWrapper:
    peer_certificate: x509.Certificate | None
```

Transport wrapper passed to the inner protocol's `connection_made()`. Provides standard asyncio transport methods while handling TLS encryption.

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `peer_certificate` | `x509.Certificate \| None` | Client's certificate after handshake |

**Methods:**

- `write(data: bytes)` — Encrypt and send data
- `close()` — Initiate TLS shutdown with graceful delay
- `get_extra_info(name)` — Supports `"peername"` and `"ssl_object"`
- `is_closing()` — Check if transport is closing

### get_peer_certificate_from_connection

```python
def get_peer_certificate_from_connection(
    conn: SSL.Connection,
) -> crypto.X509 | None
```

Extract peer certificate from a PyOpenSSL connection. Returns `None` if no certificate is available or on error.

### x509_to_cryptography

```python
def x509_to_cryptography(cert: crypto.X509) -> x509.Certificate
```

Convert a PyOpenSSL `X509` certificate to a `cryptography` library `Certificate` object. This allows using tlacacoca's certificate utilities (fingerprinting, etc.) with certificates obtained via PyOpenSSL.

## Certificate Management

### generate_self_signed_cert

```python
def generate_self_signed_cert(
    hostname: str,
    key_size: int = 2048,
    valid_days: int = 365,
    organization: str | None = None,
) -> tuple[bytes, bytes]
```

Generate a self-signed certificate and private key.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hostname` | `str` | Required | Certificate common name |
| `key_size` | `int` | `2048` | RSA key size in bits |
| `valid_days` | `int` | `365` | Validity period in days |
| `organization` | `str \| None` | `None` | Organization name |

**Returns:** Tuple of `(certificate_pem, key_pem)` as bytes.

**Example:**

```python
from tlacacoca import generate_self_signed_cert
from pathlib import Path

cert_pem, key_pem = generate_self_signed_cert(
    "example.com",
    key_size=4096,
    valid_days=730
)

Path("cert.pem").write_bytes(cert_pem)
Path("key.pem").write_bytes(key_pem)
```

### load_certificate

```python
def load_certificate(path: Path) -> x509.Certificate
```

Load a certificate from a PEM file.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | `Path` | Path to PEM certificate file |

**Returns:** `cryptography.x509.Certificate` object.

**Raises:** `ValueError` if file is not valid PEM certificate.

### get_certificate_fingerprint

```python
def get_certificate_fingerprint(
    cert: x509.Certificate,
    algorithm: str = "sha256"
) -> str
```

Get the fingerprint of a certificate.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cert` | `x509.Certificate` | Required | Certificate object |
| `algorithm` | `str` | `"sha256"` | Hash algorithm |

**Returns:** Fingerprint string in format `algorithm:hexdigest`.

**Example:**

```python
from tlacacoca import load_certificate, get_certificate_fingerprint

cert = load_certificate(Path("cert.pem"))
fp = get_certificate_fingerprint(cert)
# Returns: "sha256:a1b2c3d4e5f6..."
```

### get_certificate_fingerprint_from_path

```python
def get_certificate_fingerprint_from_path(
    path: Path,
    algorithm: str = "sha256"
) -> str
```

Get fingerprint directly from certificate file path.

### get_certificate_info

```python
def get_certificate_info(cert: x509.Certificate) -> dict[str, Any]
```

Get detailed information about a certificate.

**Returns:** Dictionary with keys:

- `subject`: Subject string
- `issuer`: Issuer string
- `serial_number`: Serial number
- `not_before`: Validity start (datetime)
- `not_after`: Validity end (datetime)
- `fingerprint_sha256`: SHA-256 fingerprint
- `fingerprint_sha1`: SHA-1 fingerprint

### is_certificate_expired

```python
def is_certificate_expired(cert: x509.Certificate) -> bool
```

Check if certificate has expired.

### is_certificate_valid_for_hostname

```python
def is_certificate_valid_for_hostname(
    cert: x509.Certificate,
    hostname: str
) -> bool
```

Check if certificate is valid for hostname.

### validate_certificate_file

```python
def validate_certificate_file(path: Path) -> tuple[bool, str | None]
```

Validate a certificate file.

**Returns:** Tuple of `(is_valid, error_message)`.

## TOFU Database

### TOFUDatabase

```python
class TOFUDatabase:
    def __init__(
        self,
        db_path: Path | str | None = None,
        app_name: str = "tlacacoca"
    )
```

Trust-On-First-Use certificate database backed by SQLite.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `db_path` | `Path \| str \| None` | `None` | Database path |
| `app_name` | `str` | `"tlacacoca"` | App name for default path |

If `db_path` is None, uses `~/.{app_name}/tofu.db`.

**Methods:**

#### async is_known

```python
async def is_known(self, hostname: str, port: int) -> bool
```

Check if host is in database.

#### async get_fingerprint

```python
async def get_fingerprint(self, hostname: str, port: int) -> str | None
```

Get stored fingerprint for host.

#### async trust

```python
async def trust(self, hostname: str, port: int, fingerprint: str) -> None
```

Store fingerprint for host.

#### async revoke

```python
async def revoke(self, hostname: str, port: int) -> bool
```

Remove host from database.

#### async list_hosts

```python
async def list_hosts(self) -> list[dict[str, Any]]
```

List all known hosts.

#### async get_host_info

```python
async def get_host_info(self, hostname: str, port: int) -> dict[str, Any] | None
```

Get detailed info for host.

#### async export_toml

```python
async def export_toml(self, path: Path) -> int
```

Export database to TOML file. Returns count of exported hosts.

#### async import_toml

```python
async def import_toml(
    self,
    path: Path,
    merge: bool = True,
    replace: bool = False,
    on_conflict: Callable | None = None
) -> dict[str, int]
```

Import from TOML file.

**Example:**

```python
from tlacacoca import TOFUDatabase

async with TOFUDatabase(app_name="myapp") as tofu:
    # Check and trust
    if not await tofu.is_known("example.com", 1965):
        await tofu.trust("example.com", 1965, fingerprint)

    # List all hosts
    hosts = await tofu.list_hosts()

    # Export
    await tofu.export_toml(Path("backup.toml"))
```

### CertificateChangedError

```python
class CertificateChangedError(Exception):
    hostname: str
    port: int
    old_fingerprint: str
    new_fingerprint: str
```

Raised when a certificate fingerprint doesn't match the stored value.

**Example:**

```python
from tlacacoca import CertificateChangedError

try:
    verify_certificate(hostname, port, fingerprint)
except CertificateChangedError as e:
    print(f"Certificate changed for {e.hostname}:{e.port}")
    print(f"Old: {e.old_fingerprint}")
    print(f"New: {e.new_fingerprint}")
```
