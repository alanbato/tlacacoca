# How-To Guides

These guides provide step-by-step instructions for accomplishing specific tasks with Tlacacoca. Unlike tutorials (which teach concepts), how-to guides assume you know what you want to do and need practical instructions.

## Security

<div class="grid cards" markdown>

-   :material-certificate: **[Manage Certificates](certificates.md)**

    ---

    Generate, load, validate, and inspect TLS certificates

-   :material-shield-lock: **[Configure TOFU](tofu.md)**

    ---

    Set up Trust-On-First-Use certificate validation

-   :material-key: **[Client Certificate Authentication](client-certificates.md)**

    ---

    Require and validate client certificates

</div>

## Middleware

<div class="grid cards" markdown>

-   :material-speedometer: **[Configure Rate Limiting](rate-limiting.md)**

    ---

    Protect against DoS attacks with token bucket rate limiting

-   :material-filter: **[Configure Access Control](access-control.md)**

    ---

    Restrict access by IP address with allow/deny lists

</div>

## Operations

<div class="grid cards" markdown>

-   :material-text-box: **[Configure Logging](logging.md)**

    ---

    Set up structured, privacy-preserving logging

</div>

## Quick Reference

| Task | Guide |
|------|-------|
| Generate self-signed certificate | [Certificates](certificates.md#generate-self-signed-certificates) |
| Get certificate fingerprint | [Certificates](certificates.md#get-certificate-fingerprint) |
| Set up TOFU database | [TOFU](tofu.md#basic-setup) |
| Export/import TOFU data | [TOFU](tofu.md#export-and-import) |
| Configure rate limits | [Rate Limiting](rate-limiting.md#configure-rate-limiting) |
| Set up IP allow list | [Access Control](access-control.md#create-an-allow-list) |
| Block IP ranges | [Access Control](access-control.md#create-a-deny-list) |
| Enable IP hashing in logs | [Logging](logging.md#privacy-preserving-logging) |

## Can't Find What You Need?

- **Tutorials** - For learning concepts: [Tutorials](../tutorials/index.md)
- **Reference** - For API details: [Reference](../reference/index.md)
- **Explanation** - For understanding design: [Explanation](../explanation/index.md)
