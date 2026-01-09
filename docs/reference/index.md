# Reference

Complete API reference documentation for Tlacacoca.

## API Reference

<div class="grid cards" markdown>

-   :material-shield-lock: **[Security API](api/security.md)**

    ---

    TLS contexts, certificates, and TOFU validation

-   :material-filter: **[Middleware API](api/middleware.md)**

    ---

    Rate limiting, access control, and certificate authentication

-   :material-text-box: **[Logging API](api/logging.md)**

    ---

    Structured logging configuration

</div>

## Quick Reference

### Security Functions

| Function | Description |
|----------|-------------|
| `create_client_context()` | Create TLS context for clients |
| `create_server_context()` | Create TLS context for servers |
| `generate_self_signed_cert()` | Generate self-signed certificate |
| `load_certificate()` | Load certificate from PEM file |
| `get_certificate_fingerprint()` | Get SHA-256 fingerprint |
| `get_certificate_info()` | Get certificate details |
| `is_certificate_expired()` | Check certificate expiration |
| `is_certificate_valid_for_hostname()` | Check hostname validity |

### Security Classes

| Class | Description |
|-------|-------------|
| `TOFUDatabase` | Trust-On-First-Use certificate database |
| `CertificateChangedError` | Raised when certificate fingerprint changes |

### Middleware Classes

| Class | Description |
|-------|-------------|
| `MiddlewareChain` | Chain multiple middleware components |
| `RateLimiter` | Token bucket rate limiting |
| `AccessControl` | IP-based access control |
| `CertificateAuth` | Client certificate authentication |
| `TokenBucket` | Standalone token bucket algorithm |

### Middleware Data Classes

| Class | Description |
|-------|-------------|
| `MiddlewareResult` | Result of middleware processing |
| `DenialReason` | Constants for denial reasons |
| `RateLimitConfig` | Rate limiter configuration |
| `AccessControlConfig` | Access control configuration |
| `CertificateAuthConfig` | Certificate auth configuration |
| `CertificateAuthPathRule` | Path-based auth rule |

### Logging Functions

| Function | Description |
|----------|-------------|
| `configure_logging()` | Configure structlog |
| `get_logger()` | Get a logger instance |
| `hash_ip_processor()` | Hash IP addresses for privacy |

## Import Shortcuts

All public API is available from the top-level package:

```python
from tlacacoca import (
    # Security - TLS
    create_client_context,
    create_server_context,
    # Security - Certificates
    generate_self_signed_cert,
    load_certificate,
    get_certificate_fingerprint,
    get_certificate_fingerprint_from_path,
    is_certificate_expired,
    is_certificate_valid_for_hostname,
    get_certificate_info,
    validate_certificate_file,
    # Security - TOFU
    TOFUDatabase,
    CertificateChangedError,
    # Middleware - Base
    DenialReason,
    MiddlewareResult,
    Middleware,
    MiddlewareChain,
    # Middleware - Rate limiting
    TokenBucket,
    RateLimiter,
    RateLimitConfig,
    # Middleware - Access control
    AccessControl,
    AccessControlConfig,
    # Middleware - Certificate auth
    CertificateAuth,
    CertificateAuthConfig,
    CertificateAuthPathRule,
    # Logging
    configure_logging,
    get_logger,
    hash_ip_processor,
)
```
