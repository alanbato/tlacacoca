"""Middleware module for request processing, rate limiting, and access control."""

from .access_control import AccessControl, AccessControlConfig
from .base import DenialReason, Middleware, MiddlewareChain, MiddlewareResult
from .certificate_auth import (
    CertificateAuth,
    CertificateAuthConfig,
    CertificateAuthPathRule,
)
from .rate_limit import RateLimitConfig, RateLimiter, TokenBucket

__all__ = [
    # Base
    "DenialReason",
    "MiddlewareResult",
    "Middleware",
    "MiddlewareChain",
    # Rate limiting
    "TokenBucket",
    "RateLimiter",
    "RateLimitConfig",
    # Access control
    "AccessControl",
    "AccessControlConfig",
    # Certificate auth
    "CertificateAuth",
    "CertificateAuthConfig",
    "CertificateAuthPathRule",
]
