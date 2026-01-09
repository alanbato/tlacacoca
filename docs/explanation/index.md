# Explanation

This section provides in-depth explanations of the concepts, design decisions, and security architecture behind Tlacacoca. Unlike tutorials (learning) or how-to guides (doing), these articles focus on **understanding**.

## Topics

<div class="grid cards" markdown>

-   :material-shield-lock: **[Security Model](security-model.md)**

    ---

    Understand TOFU vs CA-based PKI, why TLS 1.2+ is required, and the design philosophy behind tlacacoca's security features

    [:octicons-arrow-right-24: Read more](security-model.md)

</div>

## Key Concepts

### Trust On First Use (TOFU)

TOFU is an alternative to Certificate Authority (CA) validation. Instead of trusting a third party to verify certificates, clients:

1. Accept certificates on first connection
2. Store the certificate fingerprint
3. Verify subsequent connections match

This is similar to SSH's known_hosts model.

[Read more about TOFU →](security-model.md#tofu-vs-ca-based-pki)

### Token Bucket Rate Limiting

Token bucket is an algorithm for rate limiting that allows:

- **Bursts**: Quick succession of requests up to capacity
- **Sustained rate**: Steady stream at refill_rate per second

This balances user experience (allowing legitimate bursts) with protection (preventing abuse).

[Read more about rate limiting →](security-model.md#rate-limiting-design)

### Middleware Architecture

Tlacacoca uses a chain-of-responsibility pattern for middleware:

1. Each middleware processes requests independently
2. First denial stops the chain
3. Protocol implementations map abstract results to protocol-specific responses

This keeps security logic protocol-agnostic.

### Protocol Agnosticism

Tlacacoca is designed to support multiple protocols:

- All middleware returns `MiddlewareResult` with abstract `denial_reason`
- Protocol implementations map reasons to status codes
- No protocol-specific strings or formats in core library

Example mapping for Gemini:

| DenialReason | Gemini Status |
|--------------|---------------|
| `RATE_LIMIT` | 44 SLOW DOWN |
| `ACCESS_DENIED` | 53 PROXY REFUSED |
| `CERT_REQUIRED` | 60 CERT REQUIRED |
| `CERT_NOT_AUTHORIZED` | 61 CERT NOT AUTHORIZED |
