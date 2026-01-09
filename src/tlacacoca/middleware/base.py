"""Base middleware types and utilities.

This module provides the core abstractions for building middleware chains:
- DenialReason: Base class for denial reasons (extensible by protocol implementations)
- MiddlewareResult: Dataclass returned by middleware processing
- Middleware: Protocol defining the middleware interface
- MiddlewareChain: Chains multiple middleware components together
"""

from dataclasses import dataclass
from typing import Protocol


class DenialReason:
    """Base class for middleware denial reasons.

    This class defines common denial reasons used across protocols.
    Protocol implementations can subclass this to add protocol-specific
    denial reasons.

    Example:
        >>> class GeminiDenialReason(DenialReason):
        ...     '''Gemini-specific denial reasons.'''
        ...     SLOW_DOWN = "slow_down"  # Maps to status 44
        ...     PROXY_REFUSED = "proxy_refused"  # Maps to status 53
    """

    RATE_LIMIT = "rate_limit"
    ACCESS_DENIED = "access_denied"
    CERT_REQUIRED = "cert_required"
    CERT_NOT_AUTHORIZED = "cert_not_authorized"


@dataclass
class MiddlewareResult:
    """Result of middleware request processing.

    Middleware returns this dataclass to indicate whether a request should
    proceed or be denied. Protocol implementations map denial_reason values
    to their protocol-specific status codes and messages.

    Attributes:
        allowed: Whether the request should proceed.
        denial_reason: Reason for denial (from DenialReason class or subclass).
            None if allowed is True.
        retry_after: For rate limiting, seconds to wait before retrying.
            None if not applicable.

    Example:
        >>> # Allow request
        >>> result = MiddlewareResult(allowed=True)

        >>> # Deny with rate limit
        >>> result = MiddlewareResult(
        ...     allowed=False,
        ...     denial_reason=DenialReason.RATE_LIMIT,
        ...     retry_after=30
        ... )

        >>> # Protocol implementation maps to response
        >>> if not result.allowed:
        ...     if result.denial_reason == DenialReason.RATE_LIMIT:
        ...         response = f"44 Rate limited. Retry after {result.retry_after}s\\r\\n"
    """

    allowed: bool
    denial_reason: str | None = None
    retry_after: int | None = None


class Middleware(Protocol):
    """Protocol for middleware components.

    Middleware components process requests before they reach handlers.
    They can allow requests to proceed or deny them with a reason.

    Implementations must define the async process_request method.
    """

    async def process_request(
        self,
        request_url: str,
        client_ip: str,
        client_cert_fingerprint: str | None = None,
    ) -> MiddlewareResult:
        """Process a request.

        Args:
            request_url: The requested URL.
            client_ip: The client's IP address.
            client_cert_fingerprint: SHA-256 fingerprint of client certificate,
                or None if client didn't present a certificate.

        Returns:
            MiddlewareResult indicating whether request should proceed.
        """
        ...


class MiddlewareChain:
    """Chain multiple middleware components together.

    Processes requests through all middleware in order. Returns the first
    denial encountered, or allows the request if all middleware pass.

    Example:
        >>> chain = MiddlewareChain([
        ...     CertificateAuth(cert_config),
        ...     AccessControl(access_config),
        ...     RateLimiter(rate_config),
        ... ])
        >>> result = await chain.process_request(url, ip, cert_fingerprint)
    """

    def __init__(self, middlewares: list[Middleware]):
        """Initialize middleware chain.

        Args:
            middlewares: List of middleware instances to chain.
                Processed in order; first denial wins.
        """
        self.middlewares = middlewares

    async def process_request(
        self,
        request_url: str,
        client_ip: str,
        client_cert_fingerprint: str | None = None,
    ) -> MiddlewareResult:
        """Process request through all middleware.

        Args:
            request_url: The requested URL.
            client_ip: The client's IP address.
            client_cert_fingerprint: SHA-256 fingerprint of client certificate.

        Returns:
            MiddlewareResult from first denying middleware, or allowed result.
        """
        for middleware in self.middlewares:
            result = await middleware.process_request(
                request_url, client_ip, client_cert_fingerprint
            )
            if not result.allowed:
                return result

        return MiddlewareResult(allowed=True)
