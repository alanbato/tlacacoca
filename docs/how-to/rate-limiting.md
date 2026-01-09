# Configure Rate Limiting

This guide shows you how to configure Tlacacoca's rate limiting feature to protect your TLS-based protocol server from denial-of-service (DoS) attacks and abusive clients.

## Prerequisites

- Tlacacoca installed (see [Installation](../installation.md))
- Basic understanding of request rates and burst traffic

## Understanding Rate Limiting

Tlacacoca uses the **token bucket algorithm** for rate limiting:

- **Capacity**: Maximum burst size (number of requests allowed in rapid succession)
- **Refill Rate**: Sustained request rate (tokens added per second)
- **Retry-After**: How long clients should wait when rate limited

When a client exceeds the rate limit, the middleware returns a `MiddlewareResult` with `denial_reason=DenialReason.RATE_LIMIT` and the `retry_after` value.

## Basic Rate Limiting

### Create a Rate Limiter

```python
from tlacacoca import RateLimiter, RateLimitConfig

# Configure rate limiter
config = RateLimitConfig(
    capacity=10,        # Allow bursts of 10 requests
    refill_rate=1.0,    # 1 token per second sustained
    retry_after=30,     # Ask clients to wait 30 seconds
)

# Create rate limiter
rate_limiter = RateLimiter(config)
```

### Process Requests

```python
async def handle_request(client_ip: str, url: str):
    result = await rate_limiter.process_request(url, client_ip)

    if not result.allowed:
        # Client exceeded rate limit
        # Map to your protocol's response format
        return f"Rate limited. Retry after {result.retry_after} seconds"

    # Process request normally
    return process_request(url)
```

## Configure Token Bucket Parameters

### Capacity (Burst Size)

The **capacity** controls how many requests can be made in rapid succession:

```python
config = RateLimitConfig(
    capacity=20,  # Allow bursts of 20 requests
    refill_rate=1.0,
)
```

**When to increase:**

- Users frequently navigate multiple pages quickly
- Your server handles media-rich content with many subresources
- Legitimate client tools make rapid sequential requests

**When to decrease:**

- You have limited server resources
- You're experiencing abuse from scrapers
- Your content is primarily text-based with infrequent navigation

### Refill Rate (Sustained Request Rate)

The **refill_rate** determines the sustained request rate in tokens per second:

```python
config = RateLimitConfig(
    capacity=10,
    refill_rate=2.0,  # 2 requests per second sustained
)
```

Common settings:

- `0.5` = 1 request every 2 seconds (very strict)
- `1.0` = 1 request per second (default, reasonable)
- `2.0` = 2 requests per second (generous)
- `5.0` = 5 requests per second (very permissive)

**Formula:** After exhausting burst capacity, clients can make **refill_rate × seconds** additional requests.

### Retry-After (Client Wait Time)

The **retry_after** value tells rate-limited clients how long to wait:

```python
config = RateLimitConfig(
    capacity=10,
    refill_rate=1.0,
    retry_after=60,  # Wait 60 seconds
)
```

**Guidelines:**

- **15-30 seconds**: For suspected legitimate traffic spikes
- **30-60 seconds**: Default/balanced approach
- **60-300 seconds**: For detected abuse or scraping

## Choose Settings for Your Use Case

### Personal Server (Generous Limits)

```python
config = RateLimitConfig(
    capacity=20,        # Allow navigation bursts
    refill_rate=2.0,    # 2 requests/second sustained
    retry_after=15,     # Short wait time
)
```

### Public Server (Balanced Protection)

```python
config = RateLimitConfig(
    capacity=10,        # Standard burst allowance
    refill_rate=1.0,    # 1 request/second sustained
    retry_after=30,     # Standard wait time
)
```

### High-Traffic Server (Strict Protection)

```python
config = RateLimitConfig(
    capacity=5,         # Small bursts only
    refill_rate=0.5,    # 1 request every 2 seconds
    retry_after=60,     # Longer penalty
)
```

## Use in a Middleware Chain

Rate limiting typically runs after access control:

```python
from tlacacoca import (
    MiddlewareChain,
    RateLimiter,
    RateLimitConfig,
    AccessControl,
    AccessControlConfig,
)

# Configure middleware
access_config = AccessControlConfig(default_allow=True)
rate_config = RateLimitConfig(capacity=10, refill_rate=1.0)

# Create chain - order matters!
chain = MiddlewareChain([
    AccessControl(access_config),  # First: check if IP is allowed
    RateLimiter(rate_config),       # Then: apply rate limits
])

# Process requests
result = await chain.process_request(url, client_ip)
```

## Map to Protocol-Specific Responses

Each protocol has its own way of indicating rate limiting:

```python
from tlacacoca import DenialReason

async def handle_request(url: str, client_ip: str):
    result = await chain.process_request(url, client_ip)

    if not result.allowed:
        if result.denial_reason == DenialReason.RATE_LIMIT:
            # Gemini protocol
            return f"44 Rate limited. Retry after {result.retry_after} seconds\r\n"

            # Scroll protocol
            # return f"44 SLOW_DOWN {result.retry_after}\r\n"

            # Custom protocol
            # return {"error": "rate_limited", "retry_after": result.retry_after}

    # Continue processing
    ...
```

## Standalone Token Bucket

For custom rate limiting implementations, use the `TokenBucket` class directly:

```python
from tlacacoca import TokenBucket

# Create bucket
bucket = TokenBucket(capacity=10, refill_rate=1.0)

# Check if request is allowed
if bucket.consume():
    # Request allowed - token was consumed
    process_request()
else:
    # Request denied - bucket empty
    deny_request()

# Get current state
print(f"Tokens available: {bucket.tokens}")
print(f"Time until next token: {bucket.time_until_refill()}")
```

## Handle Rate Limited Responses (Client-Side)

If you're building a client, properly handle rate limit responses:

### Implement Exponential Backoff

```python
import asyncio

async def fetch_with_backoff(url: str, max_retries: int = 3):
    """Fetch URL with exponential backoff on rate limits."""
    for attempt in range(max_retries):
        response = await client.get(url)

        if response.status == 44:  # SLOW DOWN
            # Parse retry-after or use exponential backoff
            wait_time = parse_retry_after(response.meta)
            wait_time *= (2 ** attempt)  # Exponential component

            print(f"Rate limited, waiting {wait_time}s...")
            await asyncio.sleep(wait_time)
            continue

        return response

    raise Exception(f"Failed after {max_retries} retries")

def parse_retry_after(meta: str) -> int:
    """Extract retry-after seconds from response."""
    import re
    match = re.search(r'(\d+)', meta)
    return int(match.group(1)) if match else 30
```

### Good Client Practices

- Always parse and respect `retry_after` values
- Don't immediately retry after being rate limited
- Implement delays between requests (e.g., 1 second minimum)
- Consider caching responses to reduce requests

## Troubleshooting

### Legitimate Users Getting Rate Limited

**Symptoms:** Regular users see rate limit errors.

**Solutions:**

1. Increase `capacity` to allow larger bursts
2. Increase `refill_rate` for higher sustained rates
3. Reduce `retry_after` for shorter penalties
4. Check for misconfigured client tools making excessive requests

### Rate Limiting Not Working

**Symptoms:** Abusive clients continue making unlimited requests.

**Check:**

1. Verify rate limiter is in the middleware chain
2. Confirm requests are going through the middleware
3. Check that client IP is being passed correctly
4. Test with rapid requests from known IP

### Memory Usage Concerns

**Symptoms:** High memory usage from rate limiters.

**Solutions:**

1. Rate limiters are per-IP; distributed attacks bypass them
2. The rate limiter automatically cleans up idle entries
3. For severe cases, combine with [access control](access-control.md) to block networks

## See Also

- [Access Control](access-control.md) - Block abusive IPs completely
- [API Reference](../reference/api/middleware.md) - RateLimiter class documentation
- [Security Model](../explanation/security-model.md) - Understanding the security design
