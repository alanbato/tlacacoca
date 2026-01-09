"""Rate limiting middleware using token bucket algorithm.

This module provides rate limiting capabilities to protect servers from
excessive requests. It tracks per-IP request rates and returns a denial
when limits are exceeded.
"""

import asyncio
import time
from dataclasses import dataclass

from .base import DenialReason, MiddlewareResult


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting.

    Attributes:
        capacity: Maximum burst size (tokens in bucket). Default: 10.
        refill_rate: Tokens added per second. Default: 1.0.
        retry_after: Seconds to wait before retrying when rate limited. Default: 30.
    """

    capacity: int = 10
    refill_rate: float = 1.0
    retry_after: int = 30


class TokenBucket:
    """Token bucket for rate limiting a single client.

    Implements the token bucket algorithm where:
    - Each client has a bucket with a maximum capacity
    - Tokens refill continuously at a fixed rate
    - Each request consumes one token
    - Requests are denied when the bucket is empty
    """

    def __init__(self, capacity: int, refill_rate: float):
        """Initialize token bucket.

        Args:
            capacity: Maximum number of tokens (burst size).
            refill_rate: Tokens added per second.
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = float(capacity)
        self.last_update = time.monotonic()

    def consume(self, tokens: int = 1) -> bool:
        """Attempt to consume tokens.

        Args:
            tokens: Number of tokens to consume.

        Returns:
            True if tokens were available and consumed, False otherwise.
        """
        now = time.monotonic()
        elapsed = now - self.last_update

        # Refill tokens based on elapsed time
        self.tokens = min(self.capacity, self.tokens + (elapsed * self.refill_rate))
        self.last_update = now

        # Try to consume
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True

        return False


class RateLimiter:
    """Rate limiting middleware using token bucket algorithm.

    Tracks per-IP request rates and denies requests when limits are exceeded.
    Includes automatic cleanup of idle client buckets.

    Example:
        >>> config = RateLimitConfig(capacity=10, refill_rate=1.0, retry_after=30)
        >>> limiter = RateLimiter(config)
        >>> limiter.start()  # Start cleanup task
        >>> result = await limiter.process_request(url, client_ip)
        >>> if not result.allowed:
        ...     print(f"Rate limited, retry after {result.retry_after}s")
        >>> await limiter.stop()  # Stop cleanup task
    """

    def __init__(self, config: RateLimitConfig | None = None):
        """Initialize rate limiter.

        Args:
            config: Rate limit configuration. Uses defaults if None.
        """
        self.config = config or RateLimitConfig()
        self.buckets: dict[str, TokenBucket] = {}
        self._cleanup_task: asyncio.Task | None = None

    def start(self) -> None:
        """Start background cleanup task.

        Should be called when the server starts. The cleanup task removes
        idle client buckets every 5 minutes to prevent memory growth.
        """
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop(self) -> None:
        """Stop background cleanup task.

        Should be called when the server stops.
        """
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def _cleanup_loop(self) -> None:
        """Periodically clean up old token buckets."""
        while True:
            await asyncio.sleep(300)  # Clean every 5 minutes

            now = time.monotonic()
            to_remove = [
                ip
                for ip, bucket in self.buckets.items()
                if now - bucket.last_update > 600  # 10 minutes idle
            ]

            for ip in to_remove:
                del self.buckets[ip]

    def _get_bucket(self, client_ip: str) -> TokenBucket:
        """Get or create a token bucket for the given IP.

        Uses try/except for atomic get-or-create to handle concurrent access.
        """
        try:
            return self.buckets[client_ip]
        except KeyError:
            bucket = TokenBucket(self.config.capacity, self.config.refill_rate)
            self.buckets[client_ip] = bucket
            return bucket

    async def process_request(
        self,
        request_url: str,
        client_ip: str,
        client_cert_fingerprint: str | None = None,
    ) -> MiddlewareResult:
        """Process request with rate limiting.

        Args:
            request_url: The requested URL (unused, for interface compatibility).
            client_ip: The client's IP address.
            client_cert_fingerprint: Client certificate fingerprint (unused).

        Returns:
            MiddlewareResult with allowed=True if within limits,
            or allowed=False with RATE_LIMIT denial reason if exceeded.
        """
        bucket = self._get_bucket(client_ip)

        # Try to consume token
        if bucket.consume():
            return MiddlewareResult(allowed=True)

        # Rate limit exceeded
        return MiddlewareResult(
            allowed=False,
            denial_reason=DenialReason.RATE_LIMIT,
            retry_after=self.config.retry_after,
        )
