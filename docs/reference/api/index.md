# API Reference

Complete API documentation for all Tlacacoca modules.

## Modules

- **[Security](security.md)** - TLS contexts, certificates, TOFU validation
- **[Middleware](middleware.md)** - Rate limiting, access control, certificate authentication
- **[Logging](logging.md)** - Structured logging with privacy features

## Usage Pattern

All public classes and functions are exported from the top-level `tlacacoca` package:

```python
from tlacacoca import (
    # Use what you need
    create_server_context,
    RateLimiter,
    configure_logging,
)
```

## Type Hints

Tlacacoca is fully typed. All public APIs have complete type annotations for use with mypy, Pyright, or other type checkers.

```python
from tlacacoca import RateLimitConfig, RateLimiter, MiddlewareResult

# Types are inferred correctly
config: RateLimitConfig = RateLimitConfig(capacity=10, refill_rate=1.0)
limiter: RateLimiter = RateLimiter(config)

async def check(url: str, ip: str) -> MiddlewareResult:
    return await limiter.process_request(url, ip)
```

## Async Support

Middleware and TOFU components are async:

```python
import asyncio
from tlacacoca import TOFUDatabase, RateLimiter, RateLimitConfig

async def main():
    # TOFU uses async context manager
    async with TOFUDatabase(app_name="myapp") as tofu:
        await tofu.trust("example.com", 1965, "sha256:...")

    # Middleware uses async methods
    limiter = RateLimiter(RateLimitConfig(capacity=10, refill_rate=1.0))
    result = await limiter.process_request("/path", "192.168.1.1")

asyncio.run(main())
```
