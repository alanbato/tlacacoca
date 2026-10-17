"""PROXY protocol (v1 and v2) parsing for servers behind TCP relays.

When a server sits behind a TCP load balancer or relay (HAProxy, Traefik,
nginx ``stream``, AWS NLB, ...) every connection appears to come from the
relay. The PROXY protocol fixes this: the relay sends a small header with
the original client address *before* any application bytes (for TLS
servers, before the ClientHello).

This module implements the receiver side of the specification at
https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt:

- Version 2 (binary) is fully supported, including TLVs.
- Version 1 (human-readable text) is supported as well.

Trust is the critical part: a PROXY header lets the sender claim *any*
source address, so headers must only be honored from known relays.
``ProxyProtocolConfig`` holds the list of trusted relay addresses;
``TLSServerProtocol`` uses it to decide whether a header is required.
"""

import ipaddress
import struct
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Literal

#: The 12-byte signature that starts every PROXY protocol v2 header.
PROXY_V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"

#: The prefix that starts every PROXY protocol v1 header.
PROXY_V1_PREFIX = b"PROXY "

#: Maximum length of a v1 header line, including the trailing CRLF.
PROXY_V1_MAX_LENGTH = 107

#: Size of the fixed part of a v2 header (signature + ver/cmd + fam + len).
PROXY_V2_FIXED_HEADER_SIZE = 16

#: Default upper bound on the total v2 header size (fixed part + addresses
#: + TLVs). The spec allows up to 16 + 65535 bytes; relays in practice send
#: far less, so a tighter bound limits memory held per pending connection.
DEFAULT_MAX_HEADER_SIZE = 4096

#: Default number of seconds a trusted peer has to send a complete header.
DEFAULT_HEADER_TIMEOUT = 5.0

_V2_CMD_LOCAL = 0x0
_V2_CMD_PROXY = 0x1

_V2_FAMILY_UNSPEC = 0x0
_V2_FAMILY_INET = 0x1
_V2_FAMILY_INET6 = 0x2
_V2_FAMILY_UNIX = 0x3

_V2_TRANSPORT_UNSPEC = 0x0
_V2_TRANSPORT_STREAM = 0x1
_V2_TRANSPORT_DGRAM = 0x2

# Address block sizes per family (src addr + dst addr + src port + dst port).
_V2_ADDRESS_SIZES = {
    _V2_FAMILY_UNSPEC: 0,
    _V2_FAMILY_INET: 12,
    _V2_FAMILY_INET6: 36,
    _V2_FAMILY_UNIX: 216,
}

_FAMILY_NAMES: dict[int, "ProxyFamily"] = {
    _V2_FAMILY_UNSPEC: "UNSPEC",
    _V2_FAMILY_INET: "INET",
    _V2_FAMILY_INET6: "INET6",
    _V2_FAMILY_UNIX: "UNIX",
}

ProxyCommand = Literal["PROXY", "LOCAL"]
ProxyFamily = Literal["UNSPEC", "INET", "INET6", "UNIX"]
IPNetwork = IPv4Network | IPv6Network


class ProxyProtocolError(Exception):
    """Raised when a PROXY protocol header is malformed or unsupported."""


@dataclass(frozen=True)
class ProxyHeader:
    """A parsed PROXY protocol header.

    Attributes:
        version: Protocol version, ``1`` (text) or ``2`` (binary).
        command: ``"PROXY"`` for relayed connections, ``"LOCAL"`` for
            connections the relay made on its own behalf (e.g. health checks).
        family: Address family of the relayed connection.
        source: Original client ``(host, port)``, or ``None`` when the real
            socket peer should be used (``LOCAL``, ``UNSPEC``, ``UNIX``,
            v1 ``UNKNOWN``, or a non-stream transport).
        destination: Original destination ``(host, port)``, or ``None``.
        tlvs: Raw v2 TLVs as ``(type, value)`` pairs, in wire order.
        length: Total size of the header in bytes.
    """

    version: int
    command: ProxyCommand
    family: ProxyFamily
    source: tuple[str, int] | None
    destination: tuple[str, int] | None
    tlvs: tuple[tuple[int, bytes], ...] = ()
    length: int = 0


@dataclass
class ProxyProtocolConfig:
    """Configuration for receiving PROXY protocol headers.

    Passing a config to ``TLSServerProtocol`` enables PROXY protocol
    support; passing ``None`` (the default) disables it entirely.

    Attributes:
        trusted_sources: IPs or CIDRs (IPv4 and/or IPv6) of relays allowed
            to send PROXY headers. Connections from these peers **must**
            start with a valid header. Connections from any other peer are
            treated as direct connections and never have a header parsed.
        header_timeout: Seconds a trusted peer has to deliver a complete
            header before the connection is closed.
        max_header_size: Upper bound on the total header size in bytes.

    Raises:
        ValueError: If a trusted source is not a valid IP or CIDR, or a
            numeric setting is out of range.

    Example:
        >>> config = ProxyProtocolConfig(trusted_sources=["100.64.0.0/10"])
        >>> config.is_trusted("100.101.102.103")
        True
        >>> config.is_trusted("203.0.113.9")
        False
    """

    trusted_sources: list[str] = field(default_factory=list)
    header_timeout: float = DEFAULT_HEADER_TIMEOUT
    max_header_size: int = DEFAULT_MAX_HEADER_SIZE
    _networks: list[IPNetwork] = field(
        init=False, repr=False, compare=False, default_factory=list
    )

    def __post_init__(self) -> None:
        if self.header_timeout <= 0:
            raise ValueError("header_timeout must be positive")
        if self.max_header_size < PROXY_V1_MAX_LENGTH:
            raise ValueError(f"max_header_size must be at least {PROXY_V1_MAX_LENGTH}")
        self._networks = [
            parse_trusted_source(source) for source in self.trusted_sources
        ]

    @property
    def networks(self) -> list[IPNetwork]:
        """Parsed trusted networks."""
        return list(self._networks)

    def is_trusted(self, ip: str) -> bool:
        """Check whether a socket peer address is a trusted relay.

        IPv4-mapped IPv6 addresses (``::ffff:a.b.c.d``, as seen on
        dual-stack sockets) are also matched against IPv4 networks.

        Args:
            ip: The peer IP address as reported by the socket.

        Returns:
            True if the address falls in one of ``trusted_sources``.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False

        candidates: list[IPv4Address | IPv6Address] = [addr]
        if isinstance(addr, IPv6Address):
            # Drop any zone index so "fe80::1%eth0" matches "fe80::/10".
            candidates = [IPv6Address(addr.packed)]
            if addr.ipv4_mapped is not None:
                candidates.append(addr.ipv4_mapped)

        return any(
            candidate.version == network.version and candidate in network
            for candidate in candidates
            for network in self._networks
        )


def parse_trusted_source(source: str) -> IPNetwork:
    """Parse a trusted source entry (single IP or CIDR) into a network.

    Args:
        source: An IP address (``"10.0.0.1"``, ``"fd7a::1"``) or CIDR
            (``"100.64.0.0/10"``). Host bits in a CIDR are ignored.

    Returns:
        The corresponding network (a single IP becomes a /32 or /128).

    Raises:
        ValueError: If the entry is not a valid IP or CIDR.
    """
    try:
        return ipaddress.ip_network(source.strip(), strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid PROXY protocol trusted source: {source!r}") from e


def looks_like_proxy_header(data: bytes) -> bool:
    """Check whether data starts like a PROXY protocol header (v1 or v2).

    Only the bytes available are compared, so a single ``b"P"`` counts as a
    match. A TLS ClientHello always starts with ``0x16`` and never matches.

    Args:
        data: The first bytes received on a connection.

    Returns:
        True if the bytes are a prefix of either header signature.
    """
    if not data:
        return False
    return PROXY_V2_SIGNATURE.startswith(
        data[: len(PROXY_V2_SIGNATURE)]
    ) or PROXY_V1_PREFIX.startswith(data[: len(PROXY_V1_PREFIX)])


def parse_proxy_header(
    data: bytes,
    max_header_size: int = DEFAULT_MAX_HEADER_SIZE,
) -> ProxyHeader | None:
    """Parse a PROXY protocol header from the start of a buffer.

    This is designed for incremental use: call it with everything received
    so far. It returns ``None`` while the header is still incomplete, and
    raises as soon as the bytes can no longer form a valid header.

    Args:
        data: Bytes received so far on the connection.
        max_header_size: Reject headers larger than this many bytes.

    Returns:
        The parsed header (``header.length`` bytes were consumed; anything
        after that belongs to the application), or ``None`` if more data
        is needed.

    Raises:
        ProxyProtocolError: If the data is not a valid PROXY header.
    """
    if not data:
        return None

    if data[:1] == PROXY_V2_SIGNATURE[:1]:
        return _parse_v2(data, max_header_size)
    if data[:1] == PROXY_V1_PREFIX[:1]:
        return _parse_v1(data)
    raise ProxyProtocolError("missing PROXY protocol header")


def _parse_v2(data: bytes, max_header_size: int) -> ProxyHeader | None:
    signature_part = data[: len(PROXY_V2_SIGNATURE)]
    if not PROXY_V2_SIGNATURE.startswith(signature_part):
        raise ProxyProtocolError("invalid PROXY v2 signature")
    if len(data) < PROXY_V2_FIXED_HEADER_SIZE:
        return None

    ver_cmd = data[12]
    fam_proto = data[13]
    (payload_length,) = struct.unpack("!H", data[14:16])

    version = ver_cmd >> 4
    command = ver_cmd & 0x0F
    if version != 2:
        raise ProxyProtocolError(f"unsupported PROXY protocol version {version}")
    if command not in (_V2_CMD_LOCAL, _V2_CMD_PROXY):
        raise ProxyProtocolError(f"unknown PROXY v2 command {command:#x}")

    family = fam_proto >> 4
    transport = fam_proto & 0x0F
    if family not in _V2_ADDRESS_SIZES:
        raise ProxyProtocolError(f"unknown PROXY v2 address family {family:#x}")
    if transport not in (
        _V2_TRANSPORT_UNSPEC,
        _V2_TRANSPORT_STREAM,
        _V2_TRANSPORT_DGRAM,
    ):
        raise ProxyProtocolError(f"unknown PROXY v2 transport {transport:#x}")

    total_length = PROXY_V2_FIXED_HEADER_SIZE + payload_length
    if total_length > max_header_size:
        raise ProxyProtocolError(
            f"PROXY v2 header too large ({total_length} > {max_header_size} bytes)"
        )
    if len(data) < total_length:
        return None

    payload = data[PROXY_V2_FIXED_HEADER_SIZE:total_length]
    family_name = _FAMILY_NAMES[family]

    if command == _V2_CMD_LOCAL:
        # Receivers must ignore address info and use the real endpoints.
        # The length field must still be honored to skip the payload.
        return ProxyHeader(
            version=2,
            command="LOCAL",
            family=family_name,
            source=None,
            destination=None,
            length=total_length,
        )

    address_size = _V2_ADDRESS_SIZES[family]
    if payload_length < address_size:
        raise ProxyProtocolError(
            f"PROXY v2 address block too short for {family_name} "
            f"({payload_length} < {address_size} bytes)"
        )

    source: tuple[str, int] | None = None
    destination: tuple[str, int] | None = None
    if transport == _V2_TRANSPORT_STREAM and family in (
        _V2_FAMILY_INET,
        _V2_FAMILY_INET6,
    ):
        addr_len = 4 if family == _V2_FAMILY_INET else 16
        addr_cls = IPv4Address if family == _V2_FAMILY_INET else IPv6Address
        src_addr = addr_cls(payload[:addr_len])
        dst_addr = addr_cls(payload[addr_len : 2 * addr_len])
        src_port, dst_port = struct.unpack(
            "!HH", payload[2 * addr_len : 2 * addr_len + 4]
        )
        source = (str(src_addr), src_port)
        destination = (str(dst_addr), dst_port)
    # UNSPEC, UNIX and non-stream transports fall back to the real socket
    # endpoints, as the spec allows ("falls back to the UNSPEC mode").

    return ProxyHeader(
        version=2,
        command="PROXY",
        family=family_name,
        source=source,
        destination=destination,
        tlvs=_parse_tlvs(payload[address_size:]),
        length=total_length,
    )


def _parse_tlvs(data: bytes) -> tuple[tuple[int, bytes], ...]:
    tlvs: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 3:
            raise ProxyProtocolError("truncated PROXY v2 TLV header")
        tlv_type = data[offset]
        (tlv_length,) = struct.unpack("!H", data[offset + 1 : offset + 3])
        start = offset + 3
        end = start + tlv_length
        if end > len(data):
            raise ProxyProtocolError("truncated PROXY v2 TLV value")
        tlvs.append((tlv_type, data[start:end]))
        offset = end
    return tuple(tlvs)


def _parse_v1(data: bytes) -> ProxyHeader | None:
    prefix_part = data[: len(PROXY_V1_PREFIX)]
    if not PROXY_V1_PREFIX.startswith(prefix_part):
        raise ProxyProtocolError("invalid PROXY v1 header")

    end = data.find(b"\r\n", 0, PROXY_V1_MAX_LENGTH)
    if end == -1:
        if len(data) >= PROXY_V1_MAX_LENGTH:
            raise ProxyProtocolError("PROXY v1 header too long or missing CRLF")
        if b"\n" in data or b"\r" in data[:-1]:
            raise ProxyProtocolError("PROXY v1 header has an invalid line ending")
        return None

    total_length = end + 2
    try:
        line = data[:end].decode("ascii")
    except UnicodeDecodeError as e:
        raise ProxyProtocolError("PROXY v1 header is not ASCII") from e

    parts = line.split(" ")
    if len(parts) < 2:
        raise ProxyProtocolError("PROXY v1 header missing protocol")

    proto = parts[1]
    if proto == "UNKNOWN":
        # Use the real connection endpoints; ignore the rest of the line.
        return ProxyHeader(
            version=1,
            command="PROXY",
            family="UNSPEC",
            source=None,
            destination=None,
            length=total_length,
        )

    if proto not in ("TCP4", "TCP6"):
        raise ProxyProtocolError(f"unsupported PROXY v1 protocol {proto!r}")
    if len(parts) != 6:
        raise ProxyProtocolError("malformed PROXY v1 header")

    expected_version = 4 if proto == "TCP4" else 6
    src_ip = _parse_v1_address(parts[2], expected_version)
    dst_ip = _parse_v1_address(parts[3], expected_version)
    src_port = _parse_v1_port(parts[4])
    dst_port = _parse_v1_port(parts[5])

    return ProxyHeader(
        version=1,
        command="PROXY",
        family="INET" if expected_version == 4 else "INET6",
        source=(src_ip, src_port),
        destination=(dst_ip, dst_port),
        length=total_length,
    )


def _parse_v1_address(value: str, expected_version: int) -> str:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as e:
        raise ProxyProtocolError(f"invalid PROXY v1 address {value!r}") from e
    if addr.version != expected_version:
        raise ProxyProtocolError(f"PROXY v1 address {value!r} does not match protocol")
    return str(addr)


def _parse_v1_port(value: str) -> int:
    if not value.isdigit() or len(value) > 5:
        raise ProxyProtocolError(f"invalid PROXY v1 port {value!r}")
    if len(value) > 1 and value.startswith("0"):
        raise ProxyProtocolError(f"invalid PROXY v1 port {value!r}")
    port = int(value)
    if port > 65535:
        raise ProxyProtocolError(f"invalid PROXY v1 port {value!r}")
    return port
