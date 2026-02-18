# Security Model

This document explains the security design philosophy and architecture of Tlacacoca. It focuses on **why** security features are designed the way they are, rather than **how** to configure them.

## Security Philosophy

Tlacacoca's security model is built on three core principles:

### 1. Defense in Depth

Multiple independent security layers protect against different attack vectors:

- **Network layer**: TLS encryption and certificate validation
- **Protocol layer**: Request size limits, timeout protection, validation
- **Application layer**: Rate limiting, access control, certificate authentication

If one layer is bypassed, others remain to prevent compromise.

### 2. Secure by Default

Security features use conservative defaults:

- TLS 1.2+ is **mandatory** - there is no plaintext option
- Request size and timeout limits are enforced
- Path canonicalization prevents directory traversal

Users must explicitly opt out of security features, not opt in.

### 3. Privacy-Preserving

Tlacacoca minimizes data collection and exposure:

- Client IP addresses can be hashed in logs
- Minimal logging by default
- TOFU model requires no third-party trust relationships

## TLS Requirements

### Why TLS 1.2+ Minimum?

Tlacacoca enforces TLS 1.2 as the minimum version because:

1. **TLS 1.0 and 1.1 are deprecated**: Both protocols have known vulnerabilities (BEAST, POODLE) and were officially deprecated by the IETF in March 2021.

2. **Modern cipher suites**: TLS 1.2 supports authenticated encryption modes (AES-GCM, ChaCha20-Poly1305) that provide both confidentiality and integrity.

3. **Widespread support**: TLS 1.2 was released in 2008 and is supported by all modern systems.

4. **Future-proofing**: While TLS 1.3 is preferred when available, requiring it would limit compatibility.

### No Plaintext Option

Unlike HTTP (which can fall back to unencrypted connections), tlacacoca provides **no plaintext mode**. Benefits:

- **No downgrade attacks**: Attackers cannot force weaker security
- **Simple implementation**: No protocol negotiation complexity
- **Clear guarantees**: All connections are encrypted

## TOFU vs CA-based PKI

### What is TOFU?

**Trust On First Use (TOFU)** is an alternative to traditional Certificate Authority (CA) based Public Key Infrastructure:

1. **First connection**: Accept the server's certificate and store its fingerprint (SHA-256 hash)
2. **Subsequent connections**: Verify the certificate matches the stored fingerprint
3. **Certificate change**: Prompt the user for confirmation

This is similar to how SSH handles host keys.

### Advantages Over the CA Model

The CA model has several fundamental problems that TOFU addresses:

**1. No Single Point of Failure**

In the CA model, compromise of any trusted CA allows an attacker to issue valid certificates for any domain. This has happened repeatedly (DigiNotar, Comodo, etc.).

With TOFU, there is **no trusted third party** to compromise. Each user maintains their own trust relationships.

**2. Simpler Trust Model**

The CA model requires:

- Trusting hundreds of CAs worldwide
- Certificate revocation lists (CRL) or OCSP
- Complex certificate chain validation

TOFU requires:

- Storing a single fingerprint per host
- Comparing current certificate to stored fingerprint

**3. No Costs or Barriers**

CA certificates require payment or proof of domain ownership. Self-signed certificates with TOFU require:

- One command to generate
- No external dependencies

**4. Privacy Benefits**

The CA model requires contacting OCSP responders (leaking browsing patterns). TOFU requires no external communication.

### Trade-offs and Limitations

TOFU has important limitations:

**1. No Protection on First Use**

On the **first connection**, TOFU provides no security. An attacker in a man-in-the-middle position can present their own certificate.

Mitigations:

- Verify fingerprints through secondary channels
- Use first connections only on trusted networks
- Share known_hosts databases from trusted sources

**2. No Revocation Mechanism**

If a server's private key is compromised, there's no automatic way to notify clients. Operators must announce changes out-of-band.

**3. Certificate Change Ambiguity**

When a certificate changes, the client cannot distinguish between legitimate renewal and attack. Users must make trust decisions with limited information.

## Self-Signed Client Certificates

### The Problem with CERT_OPTIONAL

Python's `ssl.CERT_OPTIONAL` validates client certificates against a CA trust store. Self-signed certificates — which have no CA — fail validation and the TLS handshake is terminated. This is a fundamental limitation of the stdlib `ssl` module, not a bug.

This breaks TOFU-based protocols where clients generate their own certificates and servers accept them on first use, validating by fingerprint at the application layer.

### PyOpenSSL Solution

Tlacacoca solves this with PyOpenSSL's `set_verify()` callback, which allows accepting any certificate during the TLS handshake:

1. **`create_permissive_server_context()`** creates a PyOpenSSL `SSL.Context` with a callback that always returns `True`
2. **`TLSServerProtocol`** handles TLS manually via memory BIOs, since PyOpenSSL contexts cannot be passed to asyncio's `ssl=` parameter
3. Client certificates are extracted after handshake and converted to `cryptography` objects for fingerprint validation at the application layer

This is the same proven approach used by [Jetforce](https://github.com/michael-lazar/jetforce) (Gemini server) and other TOFU-based servers.

### Two TLS Paths

Tlacacoca provides two distinct TLS paths for servers:

| Path | Function | Use Case |
|------|----------|----------|
| **Stdlib** | `create_server_context()` | Known client CAs, use with `ssl=` |
| **PyOpenSSL** | `create_permissive_server_context()` | Self-signed client certs, use with `TLSServerProtocol` |

Protocol implementations choose which path they need based on whether client certificates come from a known set (CA-signed) or an open set (self-signed, TOFU).

## Rate Limiting Design

### Token Bucket Algorithm

Tlacacoca uses the **token bucket** algorithm for rate limiting:

1. **Burst tolerance**: Clients can make several quick requests (up to capacity)
2. **Sustained rate control**: Tokens refill at a steady rate
3. **Simplicity**: Easy to understand and implement correctly

How it works:

```
Each client IP has a bucket with:
- capacity: Maximum tokens (e.g., 10)
- tokens: Current tokens (starts at capacity)
- refill_rate: Tokens per second (e.g., 1.0)

On each request:
1. Refill bucket based on time elapsed
2. If tokens >= 1: consume token, allow request
3. Else: deny request
```

This allows bursts of quick requests, then sustained rate afterward.

### Per-IP Tracking

Rate limits are tracked **per client IP address**:

- **Fair resource allocation**: Heavy users don't slow down others
- **DoS mitigation**: Attackers cannot exhaust server capacity
- **Simple implementation**: No authentication required

Limitations:

- **NAT/proxy issues**: Multiple users behind same IP share limits
- **IP rotation**: Attackers with multiple IPs can bypass limits
- **Memory usage**: Each unique IP requires state

Tlacacoca automatically cleans up idle rate limiters to manage memory.

## Access Control Layers

### 1. IP-based Filtering

The most basic layer, processed before any request handling:

```python
config = AccessControlConfig(
    allow_list=["192.168.1.0/24"],
    deny_list=["203.0.113.0/24"],
    default_allow=False
)
```

Processing order:

1. Check deny list → reject if match
2. Check allow list → accept if match
3. Apply default policy

### 2. Certificate-based Authentication

Servers can request client certificates for specific paths:

```python
rules = [
    CertificateAuthPathRule(
        path_prefix="/admin/",
        require_cert=True,
        allowed_fingerprints=["sha256:..."]
    )
]
```

This provides **identity-based** access control.

### 3. Defense in Depth

All layers work together:

```
Request to /admin/users:
1. IP-based: Is IP allowed? → Yes, continue
2. Rate limiting: Exceeded limits? → No, continue
3. Certificate: Has valid cert? → No, reject (60 CERT REQUIRED)
```

An attacker must bypass **all layers** to access protected resources.

## Privacy Features

### IP Address Hashing

Logs can contain hashed IPs instead of raw addresses:

```python
configure_logging(hash_ips=True)

log.info("request", client_ip="192.168.1.100")
# Output: {"client_ip": "a8f7e2..."}
```

Benefits:

- Audit trails for abuse detection
- Cannot identify individuals from logs
- Compliant with privacy regulations (GDPR, etc.)

### Minimal Logging

Default logging level is **ERROR** (not INFO):

- No logs of successful requests by default
- Only errors and security events
- Reduces information leakage

## Known Limitations

### What Tlacacoca DOES Protect Against

- **Path traversal attacks**: File access outside document root
- **Request smuggling**: Strict protocol validation
- **Slowloris attacks**: Request timeout protection
- **Basic DoS**: Rate limiting per IP
- **MITM on known hosts**: TOFU validation
- **Unauthorized access**: Certificate and IP-based access control

### What Tlacacoca DOES NOT Protect Against

- **MITM on first connection**: TOFU trusts first certificate
- **Distributed DoS (DDoS)**: IP-based rate limiting easily bypassed
- **Network-level attacks**: SYN floods, amplification attacks
- **Physical access attacks**: If attacker has server access
- **Compromised certificates**: No revocation mechanism
- **Social engineering**: Tricking users into accepting bad certificates

### Network-level Attacks

Tlacacoca operates at the **application layer**. For protection against network attacks:

- Use firewalls (iptables/nftables) for SYN flood protection
- Consider reverse proxy for connection buffering
- Use DDoS mitigation services for high-profile deployments

## Design Decisions

### Why Protocol-Agnostic?

Tlacacoca is designed to support multiple TLS-based protocols (Gemini, Scroll, Spartan, etc.). Benefits:

1. **Code reuse**: Security logic written once, tested once
2. **Consistency**: Same security guarantees across protocols
3. **Maintainability**: Security updates apply to all implementations

### Why Async?

Middleware and TOFU operations are async because:

1. **Database access**: TOFU database operations are I/O bound
2. **Composability**: Fits naturally with async protocol implementations
3. **Performance**: Non-blocking operations for high-throughput servers

### Why Abstract Return Types?

Middleware returns `MiddlewareResult` with abstract `denial_reason` (not protocol-specific responses):

1. **Separation of concerns**: Security logic doesn't know protocol details
2. **Flexibility**: Same middleware works with any protocol
3. **Testability**: Easier to test without protocol-specific formatting

Protocol implementations map denial reasons to their status codes:

```python
if result.denial_reason == DenialReason.RATE_LIMIT:
    # Gemini: "44 SLOW DOWN\r\n"
    # Scroll: "44 SLOW_DOWN\r\n"
    # HTTP-like: {"status": 429}
```

## See Also

- [TOFU Configuration](../how-to/tofu.md) - How to set up TOFU validation
- [Rate Limiting](../how-to/rate-limiting.md) - Configure rate limits
- [Access Control](../how-to/access-control.md) - IP-based access control
