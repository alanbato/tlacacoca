# Tlacacoca - Shared Foundation Library for TLS-Based Protocols

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

A protocol-agnostic foundation library providing shared components for building secure TLS-based network protocol implementations in Python. Tlacacoca (pronounced "tla-ka-KO-ka", from Nahuatl meaning "secure/safe") provides security, middleware, and logging utilities that can be shared across multiple protocol implementations.

## Key Features

- **Security First** - TLS context creation, TOFU certificate validation, certificate utilities
- **Middleware System** - Rate limiting, IP access control, certificate authentication
- **Structured Logging** - Privacy-preserving logging with IP hashing
- **Protocol Agnostic** - Abstract interfaces that any TLS-based protocol can build upon
- **Modern Python** - Full type hints, async/await support, and modern tooling with `uv`

## Quick Start

### Installation

```bash
# As a library
uv add tlacacoca

# From source (for development)
git clone https://github.com/alanbato/tlacacoca.git
cd tlacacoca && uv sync
```

### Basic Usage

```python
import ssl
from tlacacoca import (
    create_client_context,
    create_server_context,
    TOFUDatabase,
    RateLimiter,
    RateLimitConfig,
    AccessControl,
    AccessControlConfig,
    MiddlewareChain,
)

# Create TLS contexts
client_ctx = create_client_context(verify_mode=ssl.CERT_REQUIRED)
server_ctx = create_server_context("cert.pem", "key.pem")

# Set up TOFU certificate validation
async with TOFUDatabase(app_name="myapp") as tofu:
    # First connection - certificate is stored
    await tofu.verify_or_trust("example.com", 1965, cert_fingerprint)

    # Subsequent connections - certificate is verified
    await tofu.verify_or_trust("example.com", 1965, cert_fingerprint)

# Configure middleware chain
rate_config = RateLimitConfig(capacity=10, refill_rate=1.0)
access_config = AccessControlConfig(
    allow_list=["192.168.1.0/24"],
    default_allow=False
)

chain = MiddlewareChain([
    AccessControl(access_config),
    RateLimiter(rate_config),
])

# Process requests through middleware
result = await chain.process_request(
    request_url="protocol://example.com/path",
    client_ip="192.168.1.100"
)

if result.allowed:
    # Handle request
    pass
else:
    # Map denial_reason to protocol-specific response
    if result.denial_reason == "rate_limit":
        # e.g., Gemini: "44 SLOW DOWN\r\n"
        pass
```

## Components

### Security

| Component | Description |
|-----------|-------------|
| `create_client_context()` | Create TLS context for client connections |
| `create_server_context()` | Create TLS context for server connections |
| `TOFUDatabase` | Trust-On-First-Use certificate validation |
| `generate_self_signed_cert()` | Generate self-signed certificates |
| `get_certificate_fingerprint()` | Get SHA-256 fingerprint of certificate |
| `load_certificate()` | Load certificate from PEM file |
| `create_permissive_server_context()` | PyOpenSSL context accepting self-signed client certs |
| `TLSServerProtocol` | asyncio protocol for manual TLS via PyOpenSSL memory BIOs |
| `TLSTransportWrapper` | Transport wrapper exposing peer certificate to inner protocol |

### Middleware

| Component | Description |
|-----------|-------------|
| `MiddlewareChain` | Chain multiple middleware components |
| `RateLimiter` | Token bucket rate limiting per IP |
| `AccessControl` | IP-based allow/deny lists with CIDR support |
| `CertificateAuth` | Client certificate authentication |

### Logging

| Component | Description |
|-----------|-------------|
| `configure_logging()` | Configure structured logging |
| `get_logger()` | Get a logger instance |
| `hash_ip_processor()` | Privacy-preserving IP hashing |

## Protocol Implementations Using Tlacacoca

Tlacacoca is designed to be used by protocol-specific implementations:

- **nauyaca** - Gemini protocol server & client
- **amatl** - Scroll protocol implementation (planned)

## Documentation

### Middleware Return Types

Middleware components return `MiddlewareResult` with protocol-agnostic denial reasons:

```python
from tlacacoca import MiddlewareResult, DenialReason

# Allowed request
result = MiddlewareResult(allowed=True)

# Denied request
result = MiddlewareResult(
    allowed=False,
    denial_reason=DenialReason.RATE_LIMIT,
    retry_after=30
)
```

Protocol implementations map these to their specific status codes:

| Denial Reason | Gemini Status | Description |
|--------------|---------------|-------------|
| `RATE_LIMIT` | 44 SLOW DOWN | Rate limit exceeded |
| `ACCESS_DENIED` | 53 PROXY REFUSED | IP not allowed |
| `CERT_REQUIRED` | 60 CLIENT CERT REQUIRED | Need client certificate |
| `CERT_NOT_AUTHORIZED` | 61 CERT NOT AUTHORIZED | Certificate not in allowed list |

## Contributing

```bash
# Setup
git clone https://github.com/alanbato/tlacacoca.git
cd tlacacoca && uv sync

# Test
uv run pytest

# Lint & Type Check
uv run ruff check src/ tests/
uv run ty check src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Resources

- [SECURITY.md](SECURITY.md) - Security documentation
- [GitHub Issues](https://github.com/alanbato/tlacacoca/issues) - Bug reports
- [GitHub Discussions](https://github.com/alanbato/tlacacoca/discussions) - Questions and ideas

---

**Status**: Active development (pre-1.0). Core security and middleware features are stable.
