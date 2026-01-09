# Tutorials

Welcome to the Tlacacoca tutorials! These step-by-step guides will teach you how to integrate tlacacoca's security and middleware components into your TLS-based protocol implementations.

## What You'll Learn

These tutorials are designed to be followed in order, building up from basic concepts to complete integrations:

### Getting Started

<div class="grid cards" markdown>

-   :material-security: **[Setting Up Secure Connections](secure-connections.md)**

    ---

    Learn to create TLS contexts, generate certificates, and establish secure client-server connections

    [:octicons-arrow-right-24: Start tutorial](secure-connections.md)

-   :material-shield-check: **[Implementing TOFU Validation](tofu-validation.md)**

    ---

    Build a Trust-On-First-Use certificate validation system for your client

    [:octicons-arrow-right-24: Start tutorial](tofu-validation.md)

</div>

### Building Middleware

<div class="grid cards" markdown>

-   :material-filter: **[Creating a Middleware Pipeline](middleware-pipeline.md)**

    ---

    Combine rate limiting, access control, and authentication into a processing chain

    [:octicons-arrow-right-24: Start tutorial](middleware-pipeline.md)

</div>

## Prerequisites

Before starting these tutorials, you should have:

- **Python 3.10+** installed
- **Tlacacoca** installed (`uv add tlacacoca`)
- Basic understanding of:
    - Python async/await
    - TLS/SSL concepts
    - Network protocols

## Tutorial Format

Each tutorial follows a consistent format:

1. **Overview** - What you'll build and learn
2. **Prerequisites** - Required knowledge and setup
3. **Step-by-step Instructions** - Detailed walkthrough
4. **Complete Code** - Full working example
5. **Next Steps** - Where to go from here

## Getting Help

If you get stuck:

- Check the [How-to Guides](../how-to/index.md) for specific tasks
- Read the [API Reference](../reference/index.md) for detailed documentation
- Ask in [GitHub Discussions](https://github.com/alanbato/tlacacoca/discussions)

Ready to start? Begin with [Setting Up Secure Connections](secure-connections.md).
