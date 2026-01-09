"""IP-based access control middleware.

This module provides IP-based access control using allow/deny lists
with CIDR notation support.
"""

from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

from .base import DenialReason, MiddlewareResult


@dataclass
class AccessControlConfig:
    """Configuration for IP-based access control.

    Attributes:
        allow_list: List of allowed IPs/CIDRs. If set, only these IPs are allowed.
        deny_list: List of denied IPs/CIDRs. If set, these IPs are denied.
        default_allow: Default policy when IP is not in any list. Default: True.

    Note:
        Deny list takes precedence over allow list. If an IP matches both,
        it will be denied.
    """

    allow_list: list[str] | None = None
    deny_list: list[str] | None = None
    default_allow: bool = True


class AccessControl:
    """IP-based access control middleware.

    Supports allow/deny lists with CIDR notation. The deny list takes
    precedence over the allow list.

    Example:
        >>> config = AccessControlConfig(
        ...     allow_list=["192.168.1.0/24", "10.0.0.1"],
        ...     deny_list=["192.168.1.100"],
        ...     default_allow=False
        ... )
        >>> access = AccessControl(config)
        >>> result = await access.process_request(url, "192.168.1.50")
        >>> assert result.allowed is True
        >>> result = await access.process_request(url, "192.168.1.100")
        >>> assert result.allowed is False  # In deny list
    """

    def __init__(self, config: AccessControlConfig | None = None):
        """Initialize access control.

        Args:
            config: Access control configuration. Uses defaults if None.
        """
        self.config = config or AccessControlConfig()

        # Parse allow list
        self.allow_networks: list[IPv4Network | IPv6Network] = []
        if self.config.allow_list:
            for cidr in self.config.allow_list:
                self.allow_networks.append(self._parse_network(cidr))

        # Parse deny list
        self.deny_networks: list[IPv4Network | IPv6Network] = []
        if self.config.deny_list:
            for cidr in self.config.deny_list:
                self.deny_networks.append(self._parse_network(cidr))

    def _parse_network(self, cidr: str) -> IPv4Network | IPv6Network:
        """Parse a CIDR string or single IP into a network.

        Args:
            cidr: CIDR notation (e.g., "192.168.1.0/24") or single IP.

        Returns:
            Parsed network object.
        """
        try:
            return ip_network(cidr, strict=False)
        except ValueError:
            # Try as single IP - add appropriate prefix
            try:
                return ip_network(f"{cidr}/32", strict=False)
            except ValueError:
                # Try IPv6
                return ip_network(f"{cidr}/128", strict=False)

    def _is_allowed(self, ip: str) -> bool:
        """Check if an IP is allowed.

        Args:
            ip: IP address string.

        Returns:
            True if allowed, False if denied.
        """
        try:
            ip_obj = ip_address(ip)
        except ValueError:
            # Invalid IP - deny
            return False

        # Check deny list first (takes precedence)
        for network in self.deny_networks:
            if ip_obj in network:
                return False

        # Check allow list
        if self.allow_networks:
            for network in self.allow_networks:
                if ip_obj in network:
                    return True
            # Not in allow list
            return False

        # No allow list - use default policy
        return self.config.default_allow

    async def process_request(
        self,
        request_url: str,
        client_ip: str,
        client_cert_fingerprint: str | None = None,
    ) -> MiddlewareResult:
        """Process request with access control.

        Args:
            request_url: The requested URL (unused, for interface compatibility).
            client_ip: The client's IP address.
            client_cert_fingerprint: Client certificate fingerprint (unused).

        Returns:
            MiddlewareResult with allowed=True if IP is permitted,
            or allowed=False with ACCESS_DENIED denial reason if blocked.
        """
        if self._is_allowed(client_ip):
            return MiddlewareResult(allowed=True)

        # IP is blocked
        return MiddlewareResult(
            allowed=False,
            denial_reason=DenialReason.ACCESS_DENIED,
        )
