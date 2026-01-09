# Configure Logging

This guide shows you how to set up structured, privacy-preserving logging using Tlacacoca's logging utilities.

## Prerequisites

- Tlacacoca installed (see [Installation](../installation.md))

## Basic Logging Setup

### Configure Logging

```python
from tlacacoca import configure_logging, get_logger

# Basic configuration
configure_logging(level="INFO")

# Get a logger
log = get_logger("myapp.server")

# Log events
log.info("server_started", host="localhost", port=1965)
log.debug("connection_received", client_ip="192.168.1.100")
log.warning("rate_limited", client_ip="203.0.113.50")
log.error("connection_failed", error="timeout")
```

### Log Levels

| Level | Use For |
|-------|---------|
| `DEBUG` | Detailed information for debugging |
| `INFO` | Normal operation events |
| `WARNING` | Unexpected but handled situations |
| `ERROR` | Failures that prevent operations |
| `CRITICAL` | Severe failures requiring attention |

```python
# Development - verbose logging
configure_logging(level="DEBUG")

# Production - only warnings and errors
configure_logging(level="WARNING")
```

## Privacy-Preserving Logging

### Enable IP Hashing

Hash client IP addresses in logs for privacy:

```python
configure_logging(level="INFO", hash_ips=True)

log = get_logger("myapp")
log.info("request", client_ip="192.168.1.100")
# Output: {"event": "request", "client_ip": "a1b2c3d4..."}
```

The hash is deterministic, so you can still:

- Track requests from the same client
- Detect abuse patterns
- Correlate events

But you cannot:

- Identify the actual IP address
- Comply with data requests without the hash key

### Manual IP Hashing

Use the hash processor directly:

```python
from tlacacoca import hash_ip_processor

# Hash an IP address
hashed = hash_ip_processor("192.168.1.100")
print(hashed)  # a1b2c3d4e5f6...

# Same IP always produces same hash
assert hash_ip_processor("192.168.1.100") == hashed
```

## Output Formats

### JSON Format (Production)

Structured JSON output for log aggregation:

```python
configure_logging(level="INFO", format="json")

log = get_logger("myapp")
log.info("request_received", url="/index.gmi", status=20)
```

Output:
```json
{"timestamp": "2025-01-09T12:00:00Z", "level": "info", "logger": "myapp", "event": "request_received", "url": "/index.gmi", "status": 20}
```

### Console Format (Development)

Human-readable colored output:

```python
configure_logging(level="DEBUG", format="console")

log = get_logger("myapp")
log.info("request_received", url="/index.gmi", status=20)
```

Output:
```
2025-01-09 12:00:00 [info     ] request_received               url=/index.gmi status=20
```

## Structured Logging

### Add Context to Log Events

```python
log = get_logger("myapp.server")

# Log with structured context
log.info("request_received",
    url="/index.gmi",
    client_ip="192.168.1.100",
    method="GET"
)

log.info("response_sent",
    url="/index.gmi",
    status=20,
    content_type="text/gemini",
    bytes_sent=1234
)

log.warning("rate_limited",
    client_ip="203.0.113.50",
    retry_after=30,
    requests_per_minute=100
)

log.error("upstream_failed",
    upstream="backend.example.com",
    error="connection_timeout",
    retry_count=3
)
```

### Bind Persistent Context

Add context that applies to all subsequent log calls:

```python
# Bind request ID to logger
request_log = log.bind(request_id="abc123")

request_log.info("processing_started")
# Output includes request_id="abc123"

request_log.info("database_query", table="users")
# Output includes request_id="abc123"

request_log.info("processing_completed")
# Output includes request_id="abc123"
```

### Create Child Loggers

```python
# Parent logger
server_log = get_logger("myapp.server")

# Child loggers inherit parent name
handler_log = get_logger("myapp.server.handler")
middleware_log = get_logger("myapp.server.middleware")
```

## Integration Examples

### With Middleware

```python
from tlacacoca import (
    configure_logging,
    get_logger,
    MiddlewareChain,
    RateLimiter,
    RateLimitConfig,
    DenialReason,
)

configure_logging(level="INFO", hash_ips=True)
log = get_logger("myserver")

rate_limiter = RateLimiter(RateLimitConfig(capacity=10, refill_rate=1.0))

async def handle_request(url: str, client_ip: str):
    log.info("request_received", url=url, client_ip=client_ip)

    result = await rate_limiter.process_request(url, client_ip)

    if not result.allowed:
        log.warning("request_denied",
            url=url,
            client_ip=client_ip,
            reason=result.denial_reason,
            retry_after=result.retry_after
        )
        return deny_response(result)

    log.info("request_allowed", url=url, client_ip=client_ip)
    return process_request(url)
```

### With TOFU

```python
from tlacacoca import TOFUDatabase, CertificateChangedError

async def verify_certificate(hostname: str, port: int, fingerprint: str):
    try:
        async with TOFUDatabase(app_name="myapp") as tofu:
            if await tofu.is_known(hostname, port):
                stored = await tofu.get_fingerprint(hostname, port)
                if stored != fingerprint:
                    log.warning("certificate_changed",
                        hostname=hostname,
                        port=port,
                        old_fingerprint=stored[:16] + "...",
                        new_fingerprint=fingerprint[:16] + "..."
                    )
                    raise CertificateChangedError(hostname, port, stored, fingerprint)
                log.debug("certificate_verified", hostname=hostname, port=port)
            else:
                log.info("first_connection", hostname=hostname, port=port)
                await tofu.trust(hostname, port, fingerprint)

    except CertificateChangedError:
        log.error("certificate_mismatch",
            hostname=hostname,
            port=port,
            action="connection_refused"
        )
        raise
```

### Complete Server Example

```python
import asyncio
from tlacacoca import (
    configure_logging,
    get_logger,
    create_server_context,
    MiddlewareChain,
    RateLimiter,
    RateLimitConfig,
    AccessControl,
    AccessControlConfig,
)

# Configure logging
configure_logging(level="INFO", format="json", hash_ips=True)
log = get_logger("myserver")

# Create middleware
middleware = MiddlewareChain([
    AccessControl(AccessControlConfig(default_allow=True)),
    RateLimiter(RateLimitConfig(capacity=10, refill_rate=1.0)),
])

async def handle_client(reader, writer):
    peername = writer.get_extra_info('peername')
    client_ip = peername[0] if peername else "unknown"

    # Bind client IP to logger for this connection
    conn_log = log.bind(client_ip=client_ip)

    try:
        data = await reader.readline()
        url = data.decode().strip()

        conn_log.info("request_received", url=url)

        result = await middleware.process_request(url, client_ip)

        if not result.allowed:
            conn_log.warning("request_denied", reason=result.denial_reason)
            writer.write(b"Error\r\n")
        else:
            conn_log.info("request_processed", url=url, status=20)
            writer.write(b"20 text/plain\r\nOK\r\n")

    except Exception as e:
        conn_log.error("request_failed", error=str(e))
    finally:
        writer.close()
        await writer.wait_closed()
        conn_log.debug("connection_closed")

async def main():
    ssl_context = create_server_context("cert.pem", "key.pem")

    server = await asyncio.start_server(
        handle_client,
        'localhost',
        1965,
        ssl=ssl_context
    )

    log.info("server_started", host="localhost", port=1965)

    async with server:
        await server.serve_forever()

asyncio.run(main())
```

## Best Practices

### What to Log

**Always log:**

- Server startup/shutdown
- Connection errors
- Security events (rate limits, access denials, cert changes)
- Configuration changes

**Consider logging:**

- Request/response summaries
- Performance metrics
- Resource usage

**Avoid logging:**

- Sensitive data (passwords, tokens)
- Full request/response bodies
- Raw IP addresses (use hashing)

### Log Levels Guidelines

```python
# DEBUG: Detailed diagnostic information
log.debug("parsing_request", raw_bytes=len(data))

# INFO: Normal operation events
log.info("request_processed", url=url, status=20)

# WARNING: Unexpected but handled
log.warning("rate_limited", client_ip=ip, retry_after=30)

# ERROR: Operation failures
log.error("database_connection_failed", error=str(e))

# CRITICAL: System-level failures
log.critical("certificate_expired", cert_path=path)
```

### Performance Considerations

1. Use appropriate log levels - DEBUG logs in production are expensive
2. Avoid logging in tight loops
3. Use lazy formatting for expensive computations:

```python
# Good - only computed if DEBUG level is enabled
log.debug("computed_value", result=lambda: expensive_computation())

# Bad - always computed
log.debug("computed_value", result=expensive_computation())
```

## See Also

- [API Reference](../reference/api/logging.md) - Logging functions documentation
- [Security Model](../explanation/security-model.md) - Privacy considerations
