"""Certificate-based authentication middleware.

This module provides path-based certificate authentication, allowing
different paths to have different certificate requirements.
"""

from dataclasses import dataclass, field
from urllib.parse import urlparse

from .base import DenialReason, MiddlewareResult


@dataclass
class CertificateAuthPathRule:
    """Certificate auth rule for a specific path prefix.

    Path rules define certificate requirements for URL prefixes.
    This enables mixing public and authenticated content on the same server.

    Attributes:
        prefix: URL path prefix to match (e.g., "/admin/", "/app/").
        require_cert: Whether a client certificate is required. Default: False.
        allowed_fingerprints: Set of allowed certificate fingerprints.
            If set, only certificates with matching fingerprints are allowed.
            If None, any certificate is accepted (when require_cert is True).

    Example:
        >>> # Public path - no certificate required
        >>> public_rule = CertificateAuthPathRule(prefix="/public/")

        >>> # App path - any certificate accepted
        >>> app_rule = CertificateAuthPathRule(
        ...     prefix="/app/",
        ...     require_cert=True
        ... )

        >>> # Admin path - specific certificates only
        >>> admin_rule = CertificateAuthPathRule(
        ...     prefix="/admin/",
        ...     require_cert=True,
        ...     allowed_fingerprints={"sha256:abc123...", "sha256:def456..."}
        ... )
    """

    prefix: str
    require_cert: bool = False
    allowed_fingerprints: set[str] | None = None


@dataclass
class CertificateAuthConfig:
    """Configuration for path-based certificate authentication.

    Path rules are checked in order - the first matching rule applies.
    If no rule matches a request path, the request is allowed without
    certificate requirements.

    Attributes:
        path_rules: List of path rules to apply. First match wins.
    """

    path_rules: list[CertificateAuthPathRule] = field(default_factory=list)


class CertificateAuth:
    """Certificate-based authentication middleware.

    Supports path-based certificate requirements:
    - Require any certificate for certain paths
    - Require specific certificate fingerprints for other paths
    - Allow public access to remaining paths

    This enables common patterns like:
    - Account registration using client certificates
    - Certificate-based access control for admin areas
    - User identity verification via certificate fingerprints
    - Mixed public/authenticated content serving

    Example:
        >>> config = CertificateAuthConfig(path_rules=[
        ...     CertificateAuthPathRule(
        ...         prefix="/admin/",
        ...         require_cert=True,
        ...         allowed_fingerprints={"sha256:admin_cert_fingerprint"}
        ...     ),
        ...     CertificateAuthPathRule(
        ...         prefix="/app/",
        ...         require_cert=True
        ...     ),
        ... ])
        >>> auth = CertificateAuth(config)
        >>> result = await auth.process_request("/admin/users", ip, None)
        >>> assert result.denial_reason == DenialReason.CERT_REQUIRED
    """

    def __init__(self, config: CertificateAuthConfig | None = None):
        """Initialize certificate authentication middleware.

        Args:
            config: Certificate auth configuration. Uses defaults if None.
        """
        self.config = config or CertificateAuthConfig()

    def _extract_path(self, request_url: str) -> str:
        """Extract path from a URL.

        Args:
            request_url: The full request URL.

        Returns:
            The path component of the URL, or "/" if none.
        """
        try:
            parsed = urlparse(request_url)
            return parsed.path or "/"
        except Exception:
            return "/"

    def _find_matching_rule(self, path: str) -> CertificateAuthPathRule | None:
        """Find the first matching path rule.

        Args:
            path: The request path.

        Returns:
            The first matching rule, or None if no rule matches.
        """
        for rule in self.config.path_rules:
            if path.startswith(rule.prefix):
                return rule
        return None

    async def process_request(
        self,
        request_url: str,
        client_ip: str,
        client_cert_fingerprint: str | None = None,
    ) -> MiddlewareResult:
        """Process request with path-based certificate authentication.

        Args:
            request_url: The requested URL.
            client_ip: The client's IP address (unused, for interface compatibility).
            client_cert_fingerprint: SHA-256 fingerprint of client certificate.

        Returns:
            MiddlewareResult with:
            - allowed=True if certificate requirements are met
            - denial_reason=CERT_REQUIRED if certificate is missing
            - denial_reason=CERT_NOT_AUTHORIZED if certificate not in whitelist
        """
        # Extract path from URL
        path = self._extract_path(request_url)

        # Find matching rule (first match wins)
        rule = self._find_matching_rule(path)

        if rule is None:
            # No rule matches - allow without cert
            return MiddlewareResult(allowed=True)

        # Apply rule's requirements
        if rule.require_cert and client_cert_fingerprint is None:
            return MiddlewareResult(
                allowed=False,
                denial_reason=DenialReason.CERT_REQUIRED,
            )

        if rule.allowed_fingerprints is not None:
            if client_cert_fingerprint is None:
                # Whitelist requires a cert
                return MiddlewareResult(
                    allowed=False,
                    denial_reason=DenialReason.CERT_REQUIRED,
                )

            if client_cert_fingerprint not in rule.allowed_fingerprints:
                return MiddlewareResult(
                    allowed=False,
                    denial_reason=DenialReason.CERT_NOT_AUTHORIZED,
                )

        return MiddlewareResult(allowed=True)
