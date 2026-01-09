# Middleware API Reference

This page documents the middleware modules in Tlacacoca, including the base middleware types, rate limiting, access control, and certificate authentication.

## Overview

The middleware modules provide:

- **Base Types** (`tlacacoca.middleware.base`) - Protocol, result types, and middleware chain
- **Rate Limiting** (`tlacacoca.middleware.rate_limit`) - Token bucket rate limiting
- **Access Control** (`tlacacoca.middleware.access_control`) - IP-based allow/deny lists
- **Certificate Auth** (`tlacacoca.middleware.certificate_auth`) - Client certificate authentication

## Base Types

### DenialReason

```python
class DenialReason:
    RATE_LIMIT = "rate_limit"
    ACCESS_DENIED = "access_denied"
    CERT_REQUIRED = "cert_required"
    CERT_NOT_AUTHORIZED = "cert_not_authorized"
```

Constants for middleware denial reasons. Protocol implementations can subclass to add protocol-specific reasons.

**Example:**

```python
from tlacacoca import DenialReason

# Extend for Gemini-specific reasons
class GeminiDenialReason(DenialReason):
    SLOW_DOWN = "slow_down"  # Maps to status 44
    PROXY_REFUSED = "proxy_refused"  # Maps to status 53
```

### MiddlewareResult

```python
@dataclass
class MiddlewareResult:
    allowed: bool
    denial_reason: str | None = None
    retry_after: int | None = None
```

Result of middleware request processing.

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `allowed` | `bool` | Whether request should proceed |
| `denial_reason` | `str \| None` | Reason for denial (from DenialReason) |
| `retry_after` | `int \| None` | Seconds to wait (for rate limiting) |

**Example:**

```python
from tlacacoca import MiddlewareResult, DenialReason

# Allow request
result = MiddlewareResult(allowed=True)

# Deny with rate limit
result = MiddlewareResult(
    allowed=False,
    denial_reason=DenialReason.RATE_LIMIT,
    retry_after=30
)

# Map to protocol response
if not result.allowed:
    if result.denial_reason == DenialReason.RATE_LIMIT:
        response = f"44 Rate limited. Retry after {result.retry_after}s\r\n"
```

### Middleware (Protocol)

```python
class Middleware(Protocol):
    async def process_request(
        self,
        request_url: str,
        client_ip: str,
        client_cert_fingerprint: str | None = None,
    ) -> MiddlewareResult:
        ...
```

Protocol defining the middleware interface. Implement this to create custom middleware.

### MiddlewareChain

```python
class MiddlewareChain:
    def __init__(self, middlewares: list[Middleware])

    async def process_request(
        self,
        request_url: str,
        client_ip: str,
        client_cert_fingerprint: str | None = None,
    ) -> MiddlewareResult
```

Chain multiple middleware components together. Processes in order; returns first denial.

**Example:**

```python
from tlacacoca import (
    MiddlewareChain,
    AccessControl,
    AccessControlConfig,
    RateLimiter,
    RateLimitConfig,
)

chain = MiddlewareChain([
    AccessControl(AccessControlConfig(default_allow=True)),
    RateLimiter(RateLimitConfig(capacity=10, refill_rate=1.0)),
])

result = await chain.process_request(url, client_ip)
```

## Rate Limiting

### RateLimitConfig

```python
@dataclass
class RateLimitConfig:
    capacity: int = 10
    refill_rate: float = 1.0
    retry_after: int = 30
```

Configuration for rate limiting.

**Attributes:**

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `capacity` | `int` | `10` | Maximum burst size (tokens) |
| `refill_rate` | `float` | `1.0` | Tokens per second |
| `retry_after` | `int` | `30` | Seconds to wait when limited |

### RateLimiter

```python
class RateLimiter:
    def __init__(self, config: RateLimitConfig)

    async def process_request(
        self,
        request_url: str,
        client_ip: str,
        client_cert_fingerprint: str | None = None,
    ) -> MiddlewareResult
```

Per-IP rate limiting using token bucket algorithm.

**Example:**

```python
from tlacacoca import RateLimiter, RateLimitConfig

config = RateLimitConfig(
    capacity=10,        # 10 request burst
    refill_rate=1.0,    # 1 req/sec sustained
    retry_after=30      # Wait 30s when limited
)

limiter = RateLimiter(config)

result = await limiter.process_request(url, client_ip)
if not result.allowed:
    # result.denial_reason == DenialReason.RATE_LIMIT
    # result.retry_after == 30
    pass
```

### TokenBucket

```python
class TokenBucket:
    def __init__(self, capacity: float, refill_rate: float)

    def consume(self, tokens: float = 1.0) -> bool
    @property
    def tokens(self) -> float
```

Standalone token bucket implementation.

**Example:**

```python
from tlacacoca import TokenBucket

bucket = TokenBucket(capacity=10, refill_rate=1.0)

if bucket.consume():
    # Request allowed
    pass
else:
    # Bucket empty
    pass

# Check current tokens
print(f"Available: {bucket.tokens}")
```

## Access Control

### AccessControlConfig

```python
@dataclass
class AccessControlConfig:
    allow_list: list[str] = field(default_factory=list)
    deny_list: list[str] = field(default_factory=list)
    default_allow: bool = True
```

Configuration for IP-based access control.

**Attributes:**

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `allow_list` | `list[str]` | `[]` | IPs/CIDRs to allow |
| `deny_list` | `list[str]` | `[]` | IPs/CIDRs to deny |
| `default_allow` | `bool` | `True` | Default when no match |

**Processing order:**

1. Check deny_list → reject if match
2. Check allow_list → accept if match
3. Apply default_allow

### AccessControl

```python
class AccessControl:
    def __init__(self, config: AccessControlConfig)

    async def process_request(
        self,
        request_url: str,
        client_ip: str,
        client_cert_fingerprint: str | None = None,
    ) -> MiddlewareResult
```

IP-based access control with CIDR support.

**Example:**

```python
from tlacacoca import AccessControl, AccessControlConfig

# Whitelist mode
config = AccessControlConfig(
    allow_list=["192.168.1.0/24", "10.0.0.0/8"],
    default_allow=False
)

# Blacklist mode
config = AccessControlConfig(
    deny_list=["203.0.113.0/24"],
    default_allow=True
)

access = AccessControl(config)
result = await access.process_request(url, client_ip)
```

## Certificate Authentication

### CertificateAuthPathRule

```python
@dataclass
class CertificateAuthPathRule:
    path_prefix: str
    require_cert: bool = True
    allowed_fingerprints: list[str] = field(default_factory=list)
```

Rule for path-based certificate authentication.

**Attributes:**

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `path_prefix` | `str` | Required | URL path prefix to match |
| `require_cert` | `bool` | `True` | Require client certificate |
| `allowed_fingerprints` | `list[str]` | `[]` | Allowed cert fingerprints (empty = any) |

### CertificateAuthConfig

```python
@dataclass
class CertificateAuthConfig:
    rules: list[CertificateAuthPathRule] = field(default_factory=list)
```

Configuration for certificate authentication.

### CertificateAuth

```python
class CertificateAuth:
    def __init__(self, config: CertificateAuthConfig)

    async def process_request(
        self,
        request_url: str,
        client_ip: str,
        client_cert_fingerprint: str | None = None,
    ) -> MiddlewareResult
```

Client certificate authentication middleware.

**Example:**

```python
from tlacacoca import (
    CertificateAuth,
    CertificateAuthConfig,
    CertificateAuthPathRule,
)

config = CertificateAuthConfig(
    rules=[
        # Admin area - specific certs only
        CertificateAuthPathRule(
            path_prefix="/admin/",
            require_cert=True,
            allowed_fingerprints=["sha256:abc...", "sha256:def..."]
        ),
        # Private area - any valid cert
        CertificateAuthPathRule(
            path_prefix="/private/",
            require_cert=True,
        ),
    ]
)

auth = CertificateAuth(config)
result = await auth.process_request(url, client_ip, cert_fingerprint)

if not result.allowed:
    if result.denial_reason == DenialReason.CERT_REQUIRED:
        # Client didn't provide certificate
        pass
    elif result.denial_reason == DenialReason.CERT_NOT_AUTHORIZED:
        # Certificate not in allowed list
        pass
```
