# Tlacacoca

**A protocol-agnostic foundation library for building secure TLS-based network applications**

Tlacacoca (pronounced "tla-ka-KO-ka", meaning "foundation" in Nahuatl) provides shared security, middleware, and logging components that can be used across multiple TLS-based protocol implementations.

---

## Why Tlacacoca?

<div class="grid cards" markdown>

-   :lock: **Security First**

    ---

    TLS context creation, TOFU certificate validation, and certificate utilities - all the security primitives you need for TLS-based protocols

-   :shield: **Middleware System**

    ---

    Protocol-agnostic rate limiting, IP access control, and certificate authentication with abstract return types

-   :mag: **Structured Logging**

    ---

    Privacy-preserving logging with IP hashing and structured output using structlog

-   :hammer_and_wrench: **Protocol Agnostic**

    ---

    Build Gemini, Scroll, Spartan, or custom protocol implementations using the same foundation

</div>

---

## Quick Example

Get started with tlacacoca's core features:

=== "Security"

    ```python
    import ssl
    from tlacacoca import (
        create_client_context,
        create_server_context,
        TOFUDatabase,
        generate_self_signed_cert,
    )

    # Create TLS contexts
    client_ctx = create_client_context(verify_mode=ssl.CERT_REQUIRED)
    server_ctx = create_server_context("cert.pem", "key.pem")

    # Generate self-signed certificates
    cert_pem, key_pem = generate_self_signed_cert("localhost")

    # TOFU certificate validation
    async with TOFUDatabase(app_name="myapp") as tofu:
        await tofu.verify_or_trust("example.com", 1965, fingerprint)
    ```

=== "Middleware"

    ```python
    from tlacacoca import (
        MiddlewareChain,
        RateLimiter,
        RateLimitConfig,
        AccessControl,
        AccessControlConfig,
        DenialReason,
    )

    # Configure middleware
    rate_config = RateLimitConfig(capacity=10, refill_rate=1.0)
    access_config = AccessControlConfig(
        allow_list=["192.168.1.0/24"],
        default_allow=False
    )

    # Create middleware chain
    chain = MiddlewareChain([
        AccessControl(access_config),
        RateLimiter(rate_config),
    ])

    # Process requests
    result = await chain.process_request(url, client_ip)
    if not result.allowed:
        # Map denial_reason to protocol-specific response
        if result.denial_reason == DenialReason.RATE_LIMIT:
            # Gemini: "44 SLOW DOWN\r\n"
            # Scroll: "44 SLOW_DOWN\r\n"
            pass
    ```

=== "Logging"

    ```python
    from tlacacoca import configure_logging, get_logger, hash_ip_processor

    # Configure structured logging
    configure_logging(level="INFO", hash_ips=True)

    # Get logger
    log = get_logger("myapp.server")

    # Log with structured context
    log.info("request_received", url="/index.gmi", client_ip="192.168.1.100")
    # Output: {"event": "request_received", "url": "/index.gmi", "client_ip": "a1b2c3..."}
    ```

---

## Installation

```bash
# Add to your project
uv add tlacacoca

# Or with pip
pip install tlacacoca
```

**Requirements:** Python 3.10 or higher

---

## Core Components

### Security

Comprehensive TLS and certificate management:

| Component | Description |
|-----------|-------------|
| `create_client_context()` | Create TLS context for client connections |
| `create_server_context()` | Create TLS context for server connections |
| `TOFUDatabase` | Trust-On-First-Use certificate validation |
| `generate_self_signed_cert()` | Generate self-signed certificates |
| `get_certificate_fingerprint()` | Get SHA-256 fingerprint of certificate |
| `load_certificate()` | Load certificate from PEM file |

### Middleware

Protocol-agnostic request processing:

| Component | Description |
|-----------|-------------|
| `MiddlewareChain` | Chain multiple middleware components |
| `RateLimiter` | Token bucket rate limiting per IP |
| `AccessControl` | IP-based allow/deny lists with CIDR support |
| `CertificateAuth` | Client certificate authentication |
| `MiddlewareResult` | Abstract result type for protocol mapping |
| `DenialReason` | Extensible denial reason constants |

### Logging

Privacy-preserving structured logging:

| Component | Description |
|-----------|-------------|
| `configure_logging()` | Configure structlog with processors |
| `get_logger()` | Get a logger instance |
| `hash_ip_processor()` | Privacy-preserving IP hashing processor |

---

## Documentation Sections

<div class="grid cards" markdown>

-   :material-rocket-launch: **[Getting Started](installation.md)**

    ---

    Installation, requirements, and your first integration

    [:octicons-arrow-right-24: Get started](installation.md)

-   :material-book-open-variant: **[Tutorials](tutorials/index.md)**

    ---

    Step-by-step lessons for using tlacacoca components

    [:octicons-arrow-right-24: Learn by doing](tutorials/index.md)

-   :material-compass: **[How-To Guides](how-to/index.md)**

    ---

    Practical guides for common security and middleware tasks

    [:octicons-arrow-right-24: Solve problems](how-to/index.md)

-   :material-file-document: **[Reference](reference/index.md)**

    ---

    Complete API reference for all modules

    [:octicons-arrow-right-24: Look up details](reference/index.md)

-   :material-lightbulb-on: **[Explanation](explanation/index.md)**

    ---

    Understanding TOFU, security model, and design decisions

    [:octicons-arrow-right-24: Understand concepts](explanation/index.md)

</div>

---

## Protocol Implementations Using Tlacacoca

Tlacacoca provides the foundation for multiple protocol implementations:

| Protocol | Project | Status |
|----------|---------|--------|
| Gemini | [nauyaca](https://github.com/alanbato/nauyaca) | Active |
| Scroll | amatl | Planned |
| Spartan | teyaotlani | Planned |
| Gopher | mototli | Planned |

---

## Project Status

!!! success "Version 0.1.0 - Core Features Complete"

    Current phase: Initial release with core security and middleware

| Feature | Status |
|---------|--------|
| TLS Context Creation | :white_check_mark: Complete |
| Certificate Utilities | :white_check_mark: Complete |
| TOFU Database | :white_check_mark: Complete |
| Rate Limiting Middleware | :white_check_mark: Complete |
| Access Control Middleware | :white_check_mark: Complete |
| Certificate Auth Middleware | :white_check_mark: Complete |
| Structured Logging | :white_check_mark: Complete |
| Documentation | :construction: In Progress |

---

## Community & Support

<div class="grid cards" markdown>

-   :material-github: **[GitHub Repository](https://github.com/alanbato/tlacacoca)**

    ---

    Source code, issue tracker, and project development

-   :material-bug: **[Bug Reports](https://github.com/alanbato/tlacacoca/issues)**

    ---

    Report bugs and request features

-   :material-forum: **[Discussions](https://github.com/alanbato/tlacacoca/discussions)**

    ---

    Ask questions and share ideas with the community

-   :material-shield-alert: **[Security](https://github.com/alanbato/tlacacoca/security/policy)**

    ---

    Responsible disclosure for security vulnerabilities

</div>

---

## License

Tlacacoca is released under the **MIT License**. See the [LICENSE](https://github.com/alanbato/tlacacoca/blob/main/LICENSE) file for details.

---

## Next Steps

Ready to get started? Here's what to do next:

1. **[Install Tlacacoca](installation.md)** - Get up and running in minutes
2. **[Quick Start Guide](quickstart.md)** - Integrate security and middleware into your project
3. **[Explore Tutorials](tutorials/index.md)** - Learn by building real integrations
4. **[Read the Security Guide](explanation/security-model.md)** - Understand TOFU, rate limiting, and best practices

!!! info "Development Status"

    This project is in active development (pre-1.0). Core security and middleware features are stable, but the API may evolve based on community feedback.
