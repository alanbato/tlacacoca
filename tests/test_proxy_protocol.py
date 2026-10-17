"""Unit tests for PROXY protocol header parsing and trust configuration."""

import ipaddress
import struct

import pytest

from tlacacoca.security.proxy_protocol import (
    PROXY_V2_SIGNATURE,
    ProxyHeader,
    ProxyProtocolConfig,
    ProxyProtocolError,
    looks_like_proxy_header,
    parse_proxy_header,
    parse_trusted_source,
)


def build_v2(
    *,
    command: int = 0x1,
    family: int = 0x1,
    transport: int = 0x1,
    version: int = 0x2,
    src: str = "203.0.113.7",
    dst: str = "198.51.100.1",
    src_port: int = 51234,
    dst_port: int = 1958,
    tlvs: bytes = b"",
    payload: bytes | None = None,
) -> bytes:
    """Build a PROXY v2 header (addresses only used for INET/INET6)."""
    if payload is None:
        if family in (0x1, 0x2):
            payload = (
                ipaddress.ip_address(src).packed
                + ipaddress.ip_address(dst).packed
                + struct.pack("!HH", src_port, dst_port)
            )
        elif family == 0x3:
            payload = b"/tmp/src".ljust(108, b"\x00") + b"/tmp/dst".ljust(108, b"\x00")
        else:
            payload = b""
        payload += tlvs
    return (
        PROXY_V2_SIGNATURE
        + bytes([(version << 4) | command, (family << 4) | transport])
        + struct.pack("!H", len(payload))
        + payload
    )


def tlv(tlv_type: int, value: bytes) -> bytes:
    return bytes([tlv_type]) + struct.pack("!H", len(value)) + value


class TestParseV2:
    def test_proxy_ipv4(self):
        data = build_v2()
        header = parse_proxy_header(data)
        assert header == ProxyHeader(
            version=2,
            command="PROXY",
            family="INET",
            source=("203.0.113.7", 51234),
            destination=("198.51.100.1", 1958),
            tlvs=(),
            length=len(data),
        )
        assert header.length == 16 + 12

    def test_proxy_ipv6(self):
        data = build_v2(family=0x2, src="2001:db8::7", dst="2001:db8::1")
        header = parse_proxy_header(data)
        assert header is not None
        assert header.family == "INET6"
        assert header.source == ("2001:db8::7", 51234)
        assert header.destination == ("2001:db8::1", 1958)
        assert header.length == 16 + 36

    def test_local_command_has_no_address(self):
        header = parse_proxy_header(build_v2(command=0x0, family=0x0, transport=0x0))
        assert header is not None
        assert header.command == "LOCAL"
        assert header.source is None
        assert header.length == 16

    def test_local_command_ignores_address_block_but_skips_it(self):
        data = build_v2(command=0x0)
        header = parse_proxy_header(data + b"\x16\x03\x01")
        assert header is not None
        assert header.command == "LOCAL"
        assert header.source is None
        assert header.length == len(data)

    def test_unspec_family_falls_back_to_socket_peer(self):
        header = parse_proxy_header(build_v2(family=0x0, transport=0x0))
        assert header is not None
        assert header.command == "PROXY"
        assert header.family == "UNSPEC"
        assert header.source is None

    def test_unix_family_falls_back_to_socket_peer(self):
        data = build_v2(family=0x3)
        header = parse_proxy_header(data)
        assert header is not None
        assert header.family == "UNIX"
        assert header.source is None
        assert header.length == 16 + 216

    def test_dgram_transport_falls_back_to_socket_peer(self):
        header = parse_proxy_header(build_v2(transport=0x2))
        assert header is not None
        assert header.source is None

    def test_tlvs_are_parsed(self):
        tlvs = tlv(0x04, b"\x00\x00") + tlv(0x05, b"unique-id")
        data = build_v2(tlvs=tlvs)
        header = parse_proxy_header(data)
        assert header is not None
        assert header.tlvs == ((0x04, b"\x00\x00"), (0x05, b"unique-id"))
        assert header.source == ("203.0.113.7", 51234)

    def test_trailing_bytes_not_consumed(self):
        data = build_v2()
        header = parse_proxy_header(data + b"\x16\x03\x01\x02\x00trailing")
        assert header is not None
        assert header.length == len(data)

    @pytest.mark.parametrize("cut", [1, 5, 12, 15, 16, 20, 27])
    def test_incomplete_header_needs_more_data(self, cut):
        data = build_v2()
        assert parse_proxy_header(data[:cut]) is None

    def test_incremental_byte_by_byte(self):
        data = build_v2(family=0x2, src="2001:db8::7", dst="2001:db8::1")
        for i in range(1, len(data)):
            assert parse_proxy_header(data[:i]) is None
        assert parse_proxy_header(data) is not None

    def test_bad_signature(self):
        bad = b"\r\n\r\n\x00\r\nQUIX\n" + b"\x21\x11\x00\x00"
        with pytest.raises(ProxyProtocolError, match="signature"):
            parse_proxy_header(bad)

    def test_bad_signature_detected_early(self):
        with pytest.raises(ProxyProtocolError, match="signature"):
            parse_proxy_header(b"\r\n\r\nX")

    @pytest.mark.parametrize("version", [0x0, 0x1, 0x3, 0xF])
    def test_unsupported_version(self, version):
        with pytest.raises(ProxyProtocolError, match="version"):
            parse_proxy_header(build_v2(version=version))

    @pytest.mark.parametrize("command", [0x2, 0xF])
    def test_unknown_command(self, command):
        with pytest.raises(ProxyProtocolError, match="command"):
            parse_proxy_header(build_v2(command=command))

    def test_unknown_family(self):
        with pytest.raises(ProxyProtocolError, match="family"):
            parse_proxy_header(build_v2(family=0x4, payload=b""))

    def test_unknown_transport(self):
        with pytest.raises(ProxyProtocolError, match="transport"):
            parse_proxy_header(build_v2(transport=0x3))

    def test_address_block_too_short(self):
        with pytest.raises(ProxyProtocolError, match="too short"):
            parse_proxy_header(build_v2(family=0x1, payload=b"\x01\x02\x03\x04"))

    def test_ipv6_address_block_too_short(self):
        with pytest.raises(ProxyProtocolError, match="too short"):
            parse_proxy_header(build_v2(family=0x2, payload=b"\x00" * 12))

    def test_truncated_tlv(self):
        with pytest.raises(ProxyProtocolError, match="TLV"):
            parse_proxy_header(build_v2(tlvs=b"\x05\x00\x10abc"))

    def test_truncated_tlv_header(self):
        with pytest.raises(ProxyProtocolError, match="TLV"):
            parse_proxy_header(build_v2(tlvs=b"\x05\x00"))

    def test_oversized_header_rejected_before_body_arrives(self):
        fixed = PROXY_V2_SIGNATURE + b"\x21\x11" + struct.pack("!H", 65535)
        with pytest.raises(ProxyProtocolError, match="too large"):
            parse_proxy_header(fixed)

    def test_custom_max_header_size(self):
        data = build_v2(tlvs=tlv(0xE0, b"x" * 200))
        assert parse_proxy_header(data, max_header_size=len(data)) is not None
        with pytest.raises(ProxyProtocolError, match="too large"):
            parse_proxy_header(data, max_header_size=len(data) - 1)


class TestParseV1:
    def test_tcp4(self):
        data = b"PROXY TCP4 203.0.113.7 198.51.100.1 51234 1958\r\n"
        header = parse_proxy_header(data + b"\x16\x03\x01")
        assert header == ProxyHeader(
            version=1,
            command="PROXY",
            family="INET",
            source=("203.0.113.7", 51234),
            destination=("198.51.100.1", 1958),
            length=len(data),
        )

    def test_tcp6(self):
        data = b"PROXY TCP6 2001:db8::7 2001:db8::1 51234 1958\r\n"
        header = parse_proxy_header(data)
        assert header is not None
        assert header.family == "INET6"
        assert header.source == ("2001:db8::7", 51234)

    def test_unknown_uses_socket_peer(self):
        header = parse_proxy_header(b"PROXY UNKNOWN whatever is here\r\n")
        assert header is not None
        assert header.source is None
        assert header.family == "UNSPEC"

    def test_bare_unknown(self):
        header = parse_proxy_header(b"PROXY UNKNOWN\r\n")
        assert header is not None
        assert header.source is None

    def test_max_length_line_accepted(self):
        line = (
            b"PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff "
            b"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n"
        )
        assert len(line) == 104
        header = parse_proxy_header(line)
        assert header is not None
        assert header.source == ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 65535)

    def test_incomplete(self):
        data = b"PROXY TCP4 203.0.113.7 198.51.100.1 51234 1958\r\n"
        for i in range(1, len(data)):
            assert parse_proxy_header(data[:i]) is None

    def test_too_long_without_crlf(self):
        with pytest.raises(ProxyProtocolError, match="too long"):
            parse_proxy_header(b"PROXY UNKNOWN " + b"x" * 200)

    def test_lone_lf_rejected(self):
        with pytest.raises(ProxyProtocolError, match="line ending"):
            parse_proxy_header(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n")

    def test_lone_cr_rejected(self):
        with pytest.raises(ProxyProtocolError, match="line ending"):
            parse_proxy_header(b"PROXY TCP4 1.2.3.4\r5.6.7.8")

    @pytest.mark.parametrize(
        "line",
        [
            b"PROXY TCP4 203.0.113.7 198.51.100.1 51234\r\n",
            b"PROXY TCP4 203.0.113.7 198.51.100.1 51234 1958 extra\r\n",
            b"PROXY TCP4  203.0.113.7 198.51.100.1 51234 1958\r\n",
            b"PROXY TCP4 203.0.113.999 198.51.100.1 51234 1958\r\n",
            b"PROXY TCP4 2001:db8::7 198.51.100.1 51234 1958\r\n",
            b"PROXY TCP6 203.0.113.7 2001:db8::1 51234 1958\r\n",
            b"PROXY TCP4 203.0.113.7 198.51.100.1 65536 1958\r\n",
            b"PROXY TCP4 203.0.113.7 198.51.100.1 -1 1958\r\n",
            b"PROXY TCP4 203.0.113.7 198.51.100.1 051234 1958\r\n",
            b"PROXY TCP4 203.0.113.7 198.51.100.1 abc 1958\r\n",
            b"PROXY UDP4 203.0.113.7 198.51.100.1 51234 1958\r\n",
            b"PROXY \r\n",
            b"PROXY TCP4 203.0.113.7 198.51.100.\xff 51234 1958\r\n",
        ],
    )
    def test_malformed(self, line):
        with pytest.raises(ProxyProtocolError):
            parse_proxy_header(line)

    def test_bad_prefix(self):
        with pytest.raises(ProxyProtocolError, match="v1"):
            parse_proxy_header(b"PROXX TCP4")


class TestMissingHeader:
    def test_tls_client_hello_is_not_a_header(self):
        with pytest.raises(ProxyProtocolError, match="missing"):
            parse_proxy_header(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03")

    def test_empty_needs_more_data(self):
        assert parse_proxy_header(b"") is None


class TestLooksLikeProxyHeader:
    @pytest.mark.parametrize(
        "data",
        [b"P", b"PROXY ", b"PROXY TCP4 1.2.3.4", b"\r", b"\r\n\r\n\x00", build_v2()],
    )
    def test_matches(self, data):
        assert looks_like_proxy_header(data)

    @pytest.mark.parametrize("data", [b"", b"\x16\x03\x01", b"GET /", b"PROXX"])
    def test_does_not_match(self, data):
        assert not looks_like_proxy_header(data)


class TestProxyProtocolConfig:
    def test_defaults(self):
        config = ProxyProtocolConfig()
        assert config.trusted_sources == []
        assert config.header_timeout == 5.0
        assert config.max_header_size == 4096
        assert not config.is_trusted("127.0.0.1")

    def test_single_ipv4(self):
        config = ProxyProtocolConfig(trusted_sources=["100.100.1.2"])
        assert config.is_trusted("100.100.1.2")
        assert not config.is_trusted("100.100.1.3")

    def test_ipv4_cidr(self):
        config = ProxyProtocolConfig(trusted_sources=["100.64.0.0/10"])
        assert config.is_trusted("100.64.0.1")
        assert config.is_trusted("100.127.255.254")
        assert not config.is_trusted("100.128.0.1")

    def test_ipv6(self):
        config = ProxyProtocolConfig(trusted_sources=["fd7a:115c:a1e0::/48", "::1"])
        assert config.is_trusted("fd7a:115c:a1e0:ab12::1")
        assert config.is_trusted("::1")
        assert not config.is_trusted("2001:db8::1")

    def test_ipv4_mapped_ipv6_peer_matches_ipv4_network(self):
        config = ProxyProtocolConfig(trusted_sources=["10.0.0.0/8"])
        assert config.is_trusted("::ffff:10.1.2.3")
        assert not config.is_trusted("::ffff:11.1.2.3")

    def test_ipv4_does_not_match_ipv6_network(self):
        config = ProxyProtocolConfig(trusted_sources=["::/0"])
        assert not config.is_trusted("10.0.0.1")

    def test_scoped_ipv6_peer(self):
        config = ProxyProtocolConfig(trusted_sources=["fe80::/10"])
        assert config.is_trusted("fe80::1%eth0")

    def test_host_bits_ignored(self):
        config = ProxyProtocolConfig(trusted_sources=["192.168.1.77/24"])
        assert config.is_trusted("192.168.1.1")

    def test_invalid_peer_is_untrusted(self):
        config = ProxyProtocolConfig(trusted_sources=["0.0.0.0/0"])
        assert not config.is_trusted("not-an-ip")
        assert not config.is_trusted("")

    @pytest.mark.parametrize("source", ["", "nope", "10.0.0.0/33", "10.0.0.256"])
    def test_invalid_trusted_source_raises(self, source):
        with pytest.raises(ValueError, match="trusted source"):
            ProxyProtocolConfig(trusted_sources=[source])

    def test_invalid_timeout(self):
        with pytest.raises(ValueError, match="header_timeout"):
            ProxyProtocolConfig(header_timeout=0)

    def test_invalid_max_header_size(self):
        with pytest.raises(ValueError, match="max_header_size"):
            ProxyProtocolConfig(max_header_size=10)

    def test_networks_property(self):
        config = ProxyProtocolConfig(trusted_sources=["10.0.0.1", "fd00::/8"])
        assert [str(n) for n in config.networks] == ["10.0.0.1/32", "fd00::/8"]

    def test_parse_trusted_source(self):
        assert str(parse_trusted_source(" 10.0.0.1 ")) == "10.0.0.1/32"
        assert str(parse_trusted_source("fd00::1")) == "fd00::1/128"
