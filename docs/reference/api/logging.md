# Logging API Reference

This page documents the logging module in Tlacacoca, which provides structured logging with privacy features.

## Overview

The logging module provides:

- **configure_logging()** - Configure structlog with processors
- **get_logger()** - Get a logger instance
- **hash_ip_processor()** - Privacy-preserving IP hashing

## Functions

### configure_logging

```python
def configure_logging(
    level: str = "INFO",
    format: str = "json",
    hash_ips: bool = False,
) -> None
```

Configure structured logging using structlog.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `level` | `str` | `"INFO"` | Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `format` | `str` | `"json"` | Output format ("json" or "console") |
| `hash_ips` | `bool` | `False` | Hash IP addresses in log output |

**Example:**

```python
from tlacacoca import configure_logging

# Development
configure_logging(level="DEBUG", format="console")

# Production with privacy
configure_logging(level="INFO", format="json", hash_ips=True)
```

### get_logger

```python
def get_logger(name: str) -> structlog.BoundLogger
```

Get a logger instance.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | `str` | Logger name (typically module path) |

**Returns:** `structlog.BoundLogger` instance.

**Example:**

```python
from tlacacoca import get_logger

log = get_logger("myapp.server")

# Structured logging
log.info("request_received", url="/index.gmi", client_ip="192.168.1.100")
log.warning("rate_limited", client_ip="203.0.113.50", retry_after=30)
log.error("connection_failed", error="timeout")

# Bind context for multiple calls
request_log = log.bind(request_id="abc123")
request_log.info("processing_started")
request_log.info("processing_completed")
```

### hash_ip_processor

```python
def hash_ip_processor(ip_address: str) -> str
```

Hash an IP address for privacy-preserving logging.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `ip_address` | `str` | IP address to hash |

**Returns:** Deterministic hash of the IP address.

**Example:**

```python
from tlacacoca import hash_ip_processor

hashed = hash_ip_processor("192.168.1.100")
print(hashed)  # a1b2c3d4e5f6...

# Same IP always produces same hash
assert hash_ip_processor("192.168.1.100") == hashed
```

## Usage Patterns

### Structured Event Logging

```python
from tlacacoca import configure_logging, get_logger

configure_logging(level="INFO")
log = get_logger("myserver")

# Log events with context
log.info("server_started", host="localhost", port=1965)
log.info("request_received", url="/index.gmi", client_ip="192.168.1.100")
log.info("response_sent", url="/index.gmi", status=20, bytes=1234)
log.warning("rate_limited", client_ip="203.0.113.50", retry_after=30)
log.error("upstream_failed", upstream="backend.example.com", error="timeout")
```

### Binding Context

```python
log = get_logger("myserver")

# Bind persistent context
conn_log = log.bind(
    client_ip="192.168.1.100",
    connection_id="abc123"
)

# All subsequent logs include bound context
conn_log.info("connected")
conn_log.info("request_received", url="/index.gmi")
conn_log.info("response_sent", status=20)
conn_log.info("disconnected")
```

### Privacy-Preserving Logging

```python
from tlacacoca import configure_logging, get_logger

# Enable IP hashing
configure_logging(level="INFO", hash_ips=True)
log = get_logger("myserver")

# IPs are automatically hashed in output
log.info("request", client_ip="192.168.1.100")
# Output: {"event": "request", "client_ip": "a1b2c3d4..."}
```

### JSON Output (Production)

```python
configure_logging(level="INFO", format="json")
log = get_logger("myserver")

log.info("request_received", url="/index.gmi", status=20)
```

Output:
```json
{"timestamp": "2025-01-09T12:00:00Z", "level": "info", "logger": "myserver", "event": "request_received", "url": "/index.gmi", "status": 20}
```

### Console Output (Development)

```python
configure_logging(level="DEBUG", format="console")
log = get_logger("myserver")

log.info("request_received", url="/index.gmi", status=20)
```

Output:
```
2025-01-09 12:00:00 [info     ] request_received               url=/index.gmi status=20
```

## Log Levels

| Level | Numeric | Use For |
|-------|---------|---------|
| `DEBUG` | 10 | Detailed diagnostic information |
| `INFO` | 20 | Normal operation events |
| `WARNING` | 30 | Unexpected but handled situations |
| `ERROR` | 40 | Failures that prevent operations |
| `CRITICAL` | 50 | Severe failures requiring attention |

## Integration with structlog

The logging module uses [structlog](https://www.structlog.org/) under the hood. You can access advanced structlog features:

```python
import structlog
from tlacacoca import configure_logging, get_logger

# Configure first
configure_logging(level="INFO")

# Get structlog features
log = get_logger("myapp")

# Context managers
with structlog.contextvars.bound_contextvars(request_id="xyz"):
    log.info("in_context")  # Includes request_id

# Exception logging
try:
    raise ValueError("something went wrong")
except Exception:
    log.exception("operation_failed")  # Includes traceback
```
