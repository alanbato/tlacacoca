"""Tests for middleware components."""

import asyncio
import time

import pytest

from tlacacoca.middleware import (
    AccessControl,
    AccessControlConfig,
    CertificateAuth,
    CertificateAuthConfig,
    CertificateAuthPathRule,
    DenialReason,
    MiddlewareChain,
    RateLimitConfig,
    RateLimiter,
    TokenBucket,
)


class TestTokenBucket:
    """Tests for TokenBucket."""

    def test_consume(self):
        """Test token bucket consumption."""
        bucket = TokenBucket(capacity=5, refill_rate=1.0)

        # Should be able to consume up to capacity
        assert bucket.consume(1)
        assert bucket.consume(1)
        assert bucket.consume(1)
        assert bucket.consume(1)
        assert bucket.consume(1)

        # Should fail when empty
        assert not bucket.consume(1)

    def test_refill(self):
        """Test token bucket refilling."""
        bucket = TokenBucket(capacity=5, refill_rate=10.0)  # Fast refill

        # Consume all
        for _ in range(5):
            assert bucket.consume(1)

        # Should be empty now
        assert not bucket.consume(1)

        # Wait for refill (0.2s should refill 2 tokens at 10 tokens/sec)
        time.sleep(0.2)

        assert bucket.consume(1)
        assert bucket.consume(1)
        assert not bucket.consume(1)  # Only 2 refilled

    def test_max_capacity(self):
        """Test that token bucket doesn't exceed capacity."""
        bucket = TokenBucket(capacity=3, refill_rate=100.0)  # Very fast refill

        # Consume 1 token
        assert bucket.consume(1)

        # Wait long enough to refill much more than capacity
        time.sleep(0.1)  # Should try to refill 10 tokens, but capped at 3

        # Should only have capacity tokens available
        assert bucket.consume(1)
        assert bucket.consume(1)
        assert bucket.consume(1)
        assert not bucket.consume(1)  # Only 3 available, not more


class TestRateLimiter:
    """Tests for RateLimiter middleware."""

    @pytest.mark.asyncio
    async def test_allows_within_limit(self):
        """Test rate limiter allows requests within limit."""
        config = RateLimitConfig(capacity=3, refill_rate=1.0)
        limiter = RateLimiter(config)

        # First 3 requests should succeed
        for _ in range(3):
            result = await limiter.process_request("gemini://test/", "192.168.1.1")
            assert result.allowed

    @pytest.mark.asyncio
    async def test_blocks_over_limit(self):
        """Test rate limiter blocks requests over limit."""
        config = RateLimitConfig(capacity=2, refill_rate=1.0, retry_after=30)
        limiter = RateLimiter(config)

        # First 2 requests succeed
        result = await limiter.process_request("gemini://test/", "192.168.1.1")
        assert result.allowed
        result = await limiter.process_request("gemini://test/", "192.168.1.1")
        assert result.allowed

        # Third request blocked
        result = await limiter.process_request("gemini://test/", "192.168.1.1")
        assert not result.allowed
        assert result.denial_reason == DenialReason.RATE_LIMIT
        assert result.retry_after == 30

    @pytest.mark.asyncio
    async def test_per_ip(self):
        """Test rate limiter tracks per-IP."""
        config = RateLimitConfig(capacity=1, refill_rate=1.0)
        limiter = RateLimiter(config)

        # Different IPs should have separate buckets
        result = await limiter.process_request("gemini://test/", "192.168.1.1")
        assert result.allowed

        # First IP exhausted, but second IP should still work
        result = await limiter.process_request("gemini://test/", "192.168.1.2")
        assert result.allowed  # Different IP, should succeed

        # Both IPs should now be exhausted
        result = await limiter.process_request("gemini://test/", "192.168.1.1")
        assert not result.allowed

        result = await limiter.process_request("gemini://test/", "192.168.1.2")
        assert not result.allowed

    @pytest.mark.asyncio
    async def test_cleanup_task(self):
        """Test rate limiter cleanup task can be started and stopped."""
        config = RateLimitConfig(capacity=10, refill_rate=1.0)
        limiter = RateLimiter(config)

        # Start cleanup task
        limiter.start()
        assert limiter._cleanup_task is not None

        # Add some IPs
        await limiter.process_request("gemini://test/", "192.168.1.1")
        await limiter.process_request("gemini://test/", "192.168.1.2")

        # Stop cleanup task
        await limiter.stop()
        assert limiter._cleanup_task.cancelled() or limiter._cleanup_task.done()

    @pytest.mark.asyncio
    async def test_refill_allows_more(self):
        """Test that rate limiter allows more requests after refill."""
        config = RateLimitConfig(capacity=1, refill_rate=5.0)  # 5 tokens per second
        limiter = RateLimiter(config)

        # First request succeeds
        result = await limiter.process_request("gemini://test/", "192.168.1.1")
        assert result.allowed

        # Second request immediately fails
        result = await limiter.process_request("gemini://test/", "192.168.1.1")
        assert not result.allowed

        # Wait for refill (0.3s should refill 1.5 tokens at 5/sec)
        await asyncio.sleep(0.3)

        # Should succeed now
        result = await limiter.process_request("gemini://test/", "192.168.1.1")
        assert result.allowed


class TestAccessControl:
    """Tests for AccessControl middleware."""

    @pytest.mark.asyncio
    async def test_allow_list(self):
        """Test access control with allow list."""
        config = AccessControlConfig(allow_list=["192.168.1.0/24"], default_allow=False)
        acl = AccessControl(config)

        # IP in allow list should be allowed
        result = await acl.process_request("gemini://test/", "192.168.1.100")
        assert result.allowed

        # IP not in allow list should be denied
        result = await acl.process_request("gemini://test/", "10.0.0.1")
        assert not result.allowed
        assert result.denial_reason == DenialReason.ACCESS_DENIED

    @pytest.mark.asyncio
    async def test_deny_list(self):
        """Test access control with deny list."""
        config = AccessControlConfig(deny_list=["203.0.113.0/24"], default_allow=True)
        acl = AccessControl(config)

        # IP in deny list should be blocked
        result = await acl.process_request("gemini://test/", "203.0.113.50")
        assert not result.allowed
        assert result.denial_reason == DenialReason.ACCESS_DENIED

        # Other IPs should be allowed
        result = await acl.process_request("gemini://test/", "192.168.1.1")
        assert result.allowed

    @pytest.mark.asyncio
    async def test_single_ip(self):
        """Test access control with single IP (not CIDR)."""
        config = AccessControlConfig(allow_list=["192.168.1.100"], default_allow=False)
        acl = AccessControl(config)

        # Exact IP should be allowed
        result = await acl.process_request("gemini://test/", "192.168.1.100")
        assert result.allowed

        # Different IP should be denied
        result = await acl.process_request("gemini://test/", "192.168.1.101")
        assert not result.allowed

    @pytest.mark.asyncio
    async def test_default_allow(self):
        """Test access control with no lists uses default policy."""
        # Default allow
        config = AccessControlConfig(default_allow=True)
        acl = AccessControl(config)

        result = await acl.process_request("gemini://test/", "192.168.1.1")
        assert result.allowed

        # Default deny
        config = AccessControlConfig(default_allow=False)
        acl = AccessControl(config)

        result = await acl.process_request("gemini://test/", "192.168.1.1")
        assert not result.allowed

    @pytest.mark.asyncio
    async def test_deny_takes_precedence(self):
        """Test that deny list takes precedence over allow list."""
        config = AccessControlConfig(
            allow_list=["192.168.1.0/24"],
            deny_list=["192.168.1.100"],  # Block one specific IP in allowed range
            default_allow=False,
        )
        acl = AccessControl(config)

        # IP in allow range but also in deny list should be blocked
        result = await acl.process_request("gemini://test/", "192.168.1.100")
        assert not result.allowed

        # Other IPs in allow range should work
        result = await acl.process_request("gemini://test/", "192.168.1.50")
        assert result.allowed

    @pytest.mark.asyncio
    async def test_invalid_ip(self):
        """Test access control handles invalid IP addresses."""
        config = AccessControlConfig(default_allow=True)
        acl = AccessControl(config)

        # Invalid IP should be denied
        result = await acl.process_request("gemini://test/", "not-an-ip")
        assert not result.allowed


class TestCertificateAuth:
    """Tests for CertificateAuth middleware."""

    @pytest.mark.asyncio
    async def test_no_path_rules(self):
        """Test certificate auth with no path rules allows all requests."""
        config = CertificateAuthConfig(path_rules=[])
        auth = CertificateAuth(config)

        # Any request should be allowed when there are no rules
        result = await auth.process_request("gemini://test/", "192.168.1.1", None)
        assert result.allowed

        result = await auth.process_request("gemini://test/app/", "192.168.1.1", None)
        assert result.allowed

        result = await auth.process_request(
            "gemini://test/admin/", "192.168.1.1", "sha256:abc123"
        )
        assert result.allowed

    @pytest.mark.asyncio
    async def test_protected_path_without_cert(self):
        """Test request to protected path without cert is denied."""
        config = CertificateAuthConfig(
            path_rules=[
                CertificateAuthPathRule(prefix="/app/", require_cert=True),
            ]
        )
        auth = CertificateAuth(config)

        # Request to protected path without cert
        result = await auth.process_request(
            "gemini://test/app/profile", "192.168.1.1", None
        )
        assert not result.allowed
        assert result.denial_reason == DenialReason.CERT_REQUIRED

    @pytest.mark.asyncio
    async def test_protected_path_with_cert(self):
        """Test request to protected path with cert is allowed."""
        config = CertificateAuthConfig(
            path_rules=[
                CertificateAuthPathRule(prefix="/app/", require_cert=True),
            ]
        )
        auth = CertificateAuth(config)

        # Request to protected path with cert - allowed
        result = await auth.process_request(
            "gemini://test/app/profile", "192.168.1.1", "sha256:abc123"
        )
        assert result.allowed

    @pytest.mark.asyncio
    async def test_unprotected_path_without_cert(self):
        """Test request to unprotected path without cert is allowed."""
        config = CertificateAuthConfig(
            path_rules=[
                CertificateAuthPathRule(prefix="/app/", require_cert=True),
            ]
        )
        auth = CertificateAuth(config)

        # Request to unprotected path (no matching rule) - allowed
        result = await auth.process_request(
            "gemini://test/public/page", "192.168.1.1", None
        )
        assert result.allowed

        # Root path - also allowed (no matching rule)
        result = await auth.process_request("gemini://test/", "192.168.1.1", None)
        assert result.allowed

    @pytest.mark.asyncio
    async def test_fingerprint_whitelist_for_path(self):
        """Test certificate auth with fingerprint whitelist for a path."""
        allowed = {"sha256:admin1", "sha256:admin2"}
        config = CertificateAuthConfig(
            path_rules=[
                CertificateAuthPathRule(
                    prefix="/admin/", require_cert=False, allowed_fingerprints=allowed
                ),
            ]
        )
        auth = CertificateAuth(config)

        # No cert for /admin/ - requires cert due to whitelist
        result = await auth.process_request(
            "gemini://test/admin/users", "192.168.1.1", None
        )
        assert not result.allowed
        assert result.denial_reason == DenialReason.CERT_REQUIRED

        # Trusted cert for /admin/ - allowed
        result = await auth.process_request(
            "gemini://test/admin/users", "192.168.1.1", "sha256:admin1"
        )
        assert result.allowed

        # Untrusted cert for /admin/ - not authorized
        result = await auth.process_request(
            "gemini://test/admin/users", "192.168.1.1", "sha256:untrusted"
        )
        assert not result.allowed
        assert result.denial_reason == DenialReason.CERT_NOT_AUTHORIZED

        # Other paths are not affected
        result = await auth.process_request(
            "gemini://test/public/", "192.168.1.1", None
        )
        assert result.allowed

    @pytest.mark.asyncio
    async def test_first_match_wins(self):
        """Test that first matching path rule takes precedence."""
        config = CertificateAuthConfig(
            path_rules=[
                # More specific rule first
                CertificateAuthPathRule(prefix="/app/public/", require_cert=False),
                # Less specific rule second
                CertificateAuthPathRule(prefix="/app/", require_cert=True),
            ]
        )
        auth = CertificateAuth(config)

        # /app/public/ matches first rule (no cert required)
        result = await auth.process_request(
            "gemini://test/app/public/page", "192.168.1.1", None
        )
        assert result.allowed

        # /app/secret/ matches second rule (cert required)
        result = await auth.process_request(
            "gemini://test/app/secret/", "192.168.1.1", None
        )
        assert not result.allowed
        assert result.denial_reason == DenialReason.CERT_REQUIRED

    @pytest.mark.asyncio
    async def test_multiple_protected_paths(self):
        """Test multiple protected paths with different requirements."""
        admin_fingerprints = {"sha256:admin"}
        config = CertificateAuthConfig(
            path_rules=[
                CertificateAuthPathRule(prefix="/app/", require_cert=True),
                CertificateAuthPathRule(
                    prefix="/admin/",
                    require_cert=True,
                    allowed_fingerprints=admin_fingerprints,
                ),
            ]
        )
        auth = CertificateAuth(config)

        # /app/ requires any cert
        result = await auth.process_request(
            "gemini://test/app/", "192.168.1.1", "sha256:user"
        )
        assert result.allowed

        # /admin/ requires specific cert
        result = await auth.process_request(
            "gemini://test/admin/", "192.168.1.1", "sha256:user"
        )
        assert not result.allowed
        assert result.denial_reason == DenialReason.CERT_NOT_AUTHORIZED

        result = await auth.process_request(
            "gemini://test/admin/", "192.168.1.1", "sha256:admin"
        )
        assert result.allowed

    @pytest.mark.asyncio
    async def test_path_extraction(self):
        """Test that path is correctly extracted from various URL formats."""
        config = CertificateAuthConfig(
            path_rules=[
                CertificateAuthPathRule(prefix="/app/", require_cert=True),
            ]
        )
        auth = CertificateAuth(config)

        # Various URL formats
        test_cases = [
            ("gemini://example.com/app/test", False),  # Protected
            ("gemini://example.com:1965/app/test", False),  # With port
            ("gemini://example.com/app/test?query=value", False),  # With query
            ("gemini://example.com/other/path", True),  # Not protected
            ("gemini://example.com/", True),  # Root
        ]

        for url, should_allow in test_cases:
            result = await auth.process_request(url, "192.168.1.1", None)
            assert result.allowed == should_allow, (
                f"URL {url} should {'allow' if should_allow else 'deny'}"
            )

    @pytest.mark.asyncio
    async def test_combined_require_and_whitelist(self):
        """Test path rule with both require_cert and fingerprint whitelist."""
        allowed = {"sha256:authorized"}
        config = CertificateAuthConfig(
            path_rules=[
                CertificateAuthPathRule(
                    prefix="/secure/", require_cert=True, allowed_fingerprints=allowed
                ),
            ]
        )
        auth = CertificateAuth(config)

        # No cert - requires cert
        result = await auth.process_request(
            "gemini://test/secure/data", "192.168.1.1", None
        )
        assert not result.allowed
        assert result.denial_reason == DenialReason.CERT_REQUIRED

        # Wrong cert - not authorized
        result = await auth.process_request(
            "gemini://test/secure/data", "192.168.1.1", "sha256:wrong"
        )
        assert not result.allowed
        assert result.denial_reason == DenialReason.CERT_NOT_AUTHORIZED

        # Correct cert - allowed
        result = await auth.process_request(
            "gemini://test/secure/data", "192.168.1.1", "sha256:authorized"
        )
        assert result.allowed


class TestMiddlewareChain:
    """Tests for MiddlewareChain."""

    @pytest.mark.asyncio
    async def test_all_allow(self):
        """Test middleware chain when all middlewares allow."""
        # Create middlewares that all allow
        config1 = AccessControlConfig(default_allow=True)
        config2 = RateLimitConfig(capacity=10, refill_rate=1.0)

        acl = AccessControl(config1)
        limiter = RateLimiter(config2)

        chain = MiddlewareChain([acl, limiter])

        # Should allow when all middlewares allow
        result = await chain.process_request("gemini://test/", "192.168.1.1")
        assert result.allowed

    @pytest.mark.asyncio
    async def test_first_denies(self):
        """Test middleware chain stops at first denial."""
        # First middleware denies
        config1 = AccessControlConfig(deny_list=["192.168.1.0/24"], default_allow=True)
        config2 = RateLimitConfig(capacity=10, refill_rate=1.0)

        acl = AccessControl(config1)
        limiter = RateLimiter(config2)

        chain = MiddlewareChain([acl, limiter])

        # Should deny and return access control error (not rate limit)
        result = await chain.process_request("gemini://test/", "192.168.1.100")
        assert not result.allowed
        assert result.denial_reason == DenialReason.ACCESS_DENIED

    @pytest.mark.asyncio
    async def test_second_denies(self):
        """Test middleware chain processes all until denial."""
        # First allows, second denies
        config1 = AccessControlConfig(default_allow=True)
        config2 = RateLimitConfig(
            capacity=0, refill_rate=1.0
        )  # No capacity = immediate deny

        acl = AccessControl(config1)
        limiter = RateLimiter(config2)

        chain = MiddlewareChain([acl, limiter])

        # Should deny with rate limit error
        result = await chain.process_request("gemini://test/", "192.168.1.1")
        assert not result.allowed
        assert result.denial_reason == DenialReason.RATE_LIMIT

    @pytest.mark.asyncio
    async def test_empty_chain(self):
        """Test middleware chain with no middlewares."""
        chain = MiddlewareChain([])

        # Should allow everything
        result = await chain.process_request("gemini://test/", "192.168.1.1")
        assert result.allowed

    @pytest.mark.asyncio
    async def test_certificate_auth_in_chain(self):
        """Test path-based certificate auth works in middleware chain."""
        cert_config = CertificateAuthConfig(
            path_rules=[
                CertificateAuthPathRule(prefix="/app/", require_cert=True),
            ]
        )
        access_config = AccessControlConfig(default_allow=True)

        cert_auth = CertificateAuth(cert_config)
        access = AccessControl(access_config)

        chain = MiddlewareChain([cert_auth, access])

        # Public path - should pass
        result = await chain.process_request("gemini://test/", "192.168.1.1", None)
        assert result.allowed

        # Protected path without cert - should fail at cert auth
        result = await chain.process_request(
            "gemini://test/app/page", "192.168.1.1", None
        )
        assert not result.allowed
        assert result.denial_reason == DenialReason.CERT_REQUIRED

        # Protected path with cert - should pass both middlewares
        result = await chain.process_request(
            "gemini://test/app/page", "192.168.1.1", "sha256:any"
        )
        assert result.allowed
