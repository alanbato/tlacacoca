"""tlacacoca - Shared foundation library for TLS-based protocol implementations.

This library provides protocol-agnostic components for building secure
network protocol clients and servers:

- Security: TLS context creation, certificate utilities, TOFU validation
- Middleware: Rate limiting, access control, certificate authentication
- Logging: Structured logging with privacy-preserving IP hashing
"""

# Security
from .security.certificates import (
    generate_self_signed_cert,
    get_certificate_fingerprint,
    get_certificate_fingerprint_from_path,
    get_certificate_info,
    is_certificate_expired,
    is_certificate_valid_for_hostname,
    load_certificate,
    validate_certificate_file,
)
from .security.pyopenssl_tls import (
    create_permissive_server_context,
    get_peer_certificate_from_connection,
    x509_to_cryptography,
)
from .security.tls import create_client_context, create_server_context
from .security.tls_protocol import TLSServerProtocol, TLSTransportWrapper
from .security.tofu import CertificateChangedError, TOFUDatabase

# Middleware
from .middleware.access_control import AccessControl, AccessControlConfig
from .middleware.base import DenialReason, Middleware, MiddlewareChain, MiddlewareResult
from .middleware.certificate_auth import (
    CertificateAuth,
    CertificateAuthConfig,
    CertificateAuthPathRule,
)
from .middleware.rate_limit import RateLimitConfig, RateLimiter, TokenBucket

# Logging
from .logging.structured import configure_logging, get_logger, hash_ip_processor

__all__ = [
    # Security - TLS
    "create_client_context",
    "create_server_context",
    # Security - PyOpenSSL TLS
    "create_permissive_server_context",
    "get_peer_certificate_from_connection",
    "x509_to_cryptography",
    "TLSServerProtocol",
    "TLSTransportWrapper",
    # Security - Certificates
    "generate_self_signed_cert",
    "load_certificate",
    "get_certificate_fingerprint",
    "get_certificate_fingerprint_from_path",
    "is_certificate_expired",
    "is_certificate_valid_for_hostname",
    "get_certificate_info",
    "validate_certificate_file",
    # Security - TOFU
    "TOFUDatabase",
    "CertificateChangedError",
    # Middleware - Base
    "DenialReason",
    "MiddlewareResult",
    "Middleware",
    "MiddlewareChain",
    # Middleware - Rate limiting
    "TokenBucket",
    "RateLimiter",
    "RateLimitConfig",
    # Middleware - Access control
    "AccessControl",
    "AccessControlConfig",
    # Middleware - Certificate auth
    "CertificateAuth",
    "CertificateAuthConfig",
    "CertificateAuthPathRule",
    # Logging
    "configure_logging",
    "get_logger",
    "hash_ip_processor",
]
