# Configure IP-based Access Control

This guide shows you how to restrict access to your server based on client IP addresses using allow lists (whitelists) and deny lists (blacklists).

## Prerequisites

- Tlacacoca installed (see [Installation](../installation.md))
- Basic understanding of IP addresses and CIDR notation (explained below)

## Basic Access Control

### Create Access Control Middleware

```python
from tlacacoca import AccessControl, AccessControlConfig

# Allow all connections (default)
config = AccessControlConfig(default_allow=True)

# Or deny all connections by default
config = AccessControlConfig(default_allow=False)

# Create access control
access_control = AccessControl(config)
```

### Process Requests

```python
async def check_access(client_ip: str, url: str):
    result = await access_control.process_request(url, client_ip)

    if not result.allowed:
        # Client not allowed
        return "Access denied"

    # Continue processing
    return process_request(url)
```

## Create an Allow List (Whitelist)

An allow list restricts access to specific IP addresses or ranges. This is useful for internal-only servers or private deployments.

### Allow Specific IPs

```python
config = AccessControlConfig(
    allow_list=["192.168.1.100", "10.0.0.50"],
    default_allow=False
)
```

This allows only the two specified IP addresses to connect.

### Allow IP Ranges with CIDR Notation

```python
config = AccessControlConfig(
    allow_list=["192.168.1.0/24", "10.0.0.0/16"],
    default_allow=False
)
```

This allows:

- Any IP from `192.168.1.0` to `192.168.1.255` (256 addresses)
- Any IP from `10.0.0.0` to `10.0.255.255` (65,536 addresses)

### Internal-Only Server

For a server accessible only from your local network:

```python
config = AccessControlConfig(
    allow_list=[
        "127.0.0.0/8",      # Localhost
        "192.168.0.0/16",   # Private class C
        "10.0.0.0/8",       # Private class A
        "172.16.0.0/12",    # Private class B
    ],
    default_allow=False
)
```

## Create a Deny List (Blacklist)

A deny list blocks specific IP addresses while allowing all others. This is useful for blocking known bad actors while keeping your server publicly accessible.

### Block Specific IPs

```python
config = AccessControlConfig(
    deny_list=["198.51.100.10", "203.0.113.50"],
    default_allow=True
)
```

### Block IP Ranges

```python
config = AccessControlConfig(
    deny_list=["198.51.100.0/24"],
    default_allow=True
)
```

This blocks all IPs from `198.51.100.0` to `198.51.100.255`.

### Block Scrapers or Abusive Clients

```python
config = AccessControlConfig(
    deny_list=[
        "198.51.100.0/24",    # Known scraper network
        "203.0.113.45",        # Abusive individual IP
        "192.0.2.0/24"         # Another problematic range
    ],
    default_allow=True
)
```

## Understand Processing Order

Access control checks IPs in this order:

1. **Deny list first**: If IP matches deny_list, block immediately
2. **Allow list second**: If allow_list exists and IP matches, allow
3. **Default policy**: If no lists match, use `default_allow` setting

This means:

- Deny list always takes precedence
- Allow list is only checked if IP is not denied
- Default policy only applies if no rules match

### Example with Both Lists

```python
config = AccessControlConfig(
    allow_list=["192.168.1.0/24"],
    deny_list=["192.168.1.50"],
    default_allow=False
)
```

Result:

- `192.168.1.50`: Denied (in deny_list, even though in allow_list range)
- `192.168.1.100`: Allowed (in allow_list)
- `10.0.0.1`: Denied (not in allow_list, default_allow = False)

## Use CIDR Notation

CIDR (Classless Inter-Domain Routing) notation specifies IP address ranges using the format `IP/prefix-length`.

### Understanding CIDR

The number after the `/` indicates how many bits are fixed. The remaining bits can vary:

- `/32`: Single IPv4 address (32 bits fixed, 0 bits vary = 1 address)
- `/24`: Class C network (24 bits fixed, 8 bits vary = 256 addresses)
- `/16`: Class B network (16 bits fixed, 16 bits vary = 65,536 addresses)
- `/8`: Class A network (8 bits fixed, 24 bits vary = 16,777,216 addresses)

### Common IPv4 Examples

```python
# Single IP address
"192.168.1.50/32"    # or just "192.168.1.50"

# /24 network (256 addresses)
"192.168.1.0/24"     # 192.168.1.0 - 192.168.1.255

# /16 network (65,536 addresses)
"10.0.0.0/16"        # 10.0.0.0 - 10.0.255.255

# /8 network (16,777,216 addresses)
"10.0.0.0/8"         # 10.0.0.0 - 10.255.255.255

# Localhost range
"127.0.0.0/8"        # 127.0.0.0 - 127.255.255.255
```

### IPv6 Support

Tlacacoca supports IPv6 addresses and CIDR notation:

```python
config = AccessControlConfig(
    allow_list=[
        "2001:db8::/32",           # IPv6 network
        "::1",                      # IPv6 localhost
        "fe80::/10"                 # IPv6 link-local
    ],
    default_allow=False
)
```

## Use in a Middleware Chain

Access control typically runs first in a middleware chain:

```python
from tlacacoca import (
    MiddlewareChain,
    AccessControl,
    AccessControlConfig,
    RateLimiter,
    RateLimitConfig,
)

# Configure middleware
access_config = AccessControlConfig(
    deny_list=["203.0.113.0/24"],
    default_allow=True
)
rate_config = RateLimitConfig(capacity=10, refill_rate=1.0)

# Create chain - access control runs first
chain = MiddlewareChain([
    AccessControl(access_config),  # Block bad IPs early
    RateLimiter(rate_config),       # Rate limit allowed IPs
])
```

## Map to Protocol-Specific Responses

```python
from tlacacoca import DenialReason

async def handle_request(url: str, client_ip: str):
    result = await access_control.process_request(url, client_ip)

    if not result.allowed:
        if result.denial_reason == DenialReason.ACCESS_DENIED:
            # Gemini protocol
            return "53 Access denied\r\n"

            # Scroll protocol
            # return "53 ACCESS_DENIED\r\n"

            # HTTP-like
            # return {"status": 403, "message": "Forbidden"}

    # Continue processing
    ...
```

## Common Patterns

### Localhost Only

For development or a personal server:

```python
config = AccessControlConfig(
    allow_list=["127.0.0.1", "::1"],
    default_allow=False
)
```

### LAN Only

For a server accessible on your local network:

```python
config = AccessControlConfig(
    allow_list=[
        "127.0.0.0/8",      # Localhost
        "192.168.0.0/16",   # Private class C
        "10.0.0.0/8",       # Private class A
        "172.16.0.0/12",    # Private class B
        "::1",              # IPv6 localhost
        "fe80::/10"         # IPv6 link-local
    ],
    default_allow=False
)
```

### Public with Exceptions

Allow everyone except known problem IPs:

```python
config = AccessControlConfig(
    deny_list=[
        "198.51.100.0/24",  # Known scraper
        "203.0.113.45"       # Abusive client
    ],
    default_allow=True
)
```

### Allowlist with Temporary Exceptions

Allow a specific network but block one problematic host within it:

```python
config = AccessControlConfig(
    allow_list=["192.168.1.0/24"],
    deny_list=["192.168.1.100"],    # Deny takes precedence
    default_allow=False
)
```

## See Also

- [Rate Limiting Guide](rate-limiting.md) - Protect against DoS attacks
- [API Reference](../reference/api/middleware.md) - AccessControl class documentation
- [Security Model](../explanation/security-model.md) - Understanding the security design
