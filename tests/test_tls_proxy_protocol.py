"""Tests for PROXY protocol handling in TLSServerProtocol.

Covers the trust matrix (trusted/untrusted peer x header/no header),
fragmentation, timeouts, trailing bytes flowing into TLS, and backward
compatibility when PROXY protocol is disabled. End-to-end tests run real
TLS handshakes behind a PROXY header over loopback.
"""

import asyncio
import socket
import ssl
import time
from typing import Any

import pytest

from tlacacoca.security import tls_protocol
from tlacacoca.security.certificates import generate_self_signed_cert
from tlacacoca.security.proxy_protocol import ProxyHeader, ProxyProtocolConfig
from tlacacoca.security.pyopenssl_tls import create_permissive_server_context
from tlacacoca.security.tls_protocol import TLSServerProtocol

from .test_proxy_protocol import build_v2

pytestmark = pytest.mark.asyncio

V1_HEADER = b"PROXY TCP4 203.0.113.7 198.51.100.1 51234 1958\r\n"


class RecordingLogger:
    """Stand-in for the module logger that records events."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    def _record(self, level: str, event: str, **kw: Any) -> None:
        self.events.append((level, event, kw))

    def debug(self, event: str, **kw: Any) -> None:
        self._record("debug", event, **kw)

    def info(self, event: str, **kw: Any) -> None:
        self._record("info", event, **kw)

    def warning(self, event: str, **kw: Any) -> None:
        self._record("warning", event, **kw)

    def named(self, event: str) -> list[dict[str, Any]]:
        return [kw for _, name, kw in self.events if name == event]


@pytest.fixture
def log(monkeypatch) -> RecordingLogger:
    recorder = RecordingLogger()
    monkeypatch.setattr(tls_protocol, "logger", recorder)
    return recorder


class FakeTransport(asyncio.Transport):
    """Minimal transport capturing writes and close calls."""

    def __init__(self, peername: tuple[Any, ...]) -> None:
        super().__init__()
        self._peername = peername
        self.closed = False
        self.written = bytearray()

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        if name == "peername":
            return self._peername
        return default

    def write(self, data: bytes) -> None:  # type: ignore[override]
        self.written.extend(data)

    def close(self) -> None:
        self.closed = True

    def is_closing(self) -> bool:
        return self.closed


class RecordingProtocol(asyncio.Protocol):
    """Inner protocol recording what it sees, echoing then closing."""

    def __init__(self, sink: list[dict[str, Any]]) -> None:
        self.sink = sink
        self.transport: Any = None

    def connection_made(self, transport: Any) -> None:
        self.transport = transport
        self.sink.append(
            {
                "peername": transport.get_extra_info("peername"),
                "proxy_peername": transport.get_extra_info("proxy_peername"),
                "proxy_header": transport.get_extra_info("proxy_header"),
            }
        )

    def data_received(self, data: bytes) -> None:
        self.transport.write(data)
        self.transport.close()


@pytest.fixture
def server_ctx(tmp_path):
    cert_pem, key_pem = generate_self_signed_cert("localhost", "Test")
    cert_file = tmp_path / "server.pem"
    key_file = tmp_path / "server.key"
    cert_file.write_bytes(cert_pem)
    key_file.write_bytes(key_pem)
    return create_permissive_server_context(
        str(cert_file), str(key_file), request_client_cert=True
    )


def _make_protocol(
    server_ctx,
    proxy: ProxyProtocolConfig | None,
    peer: tuple[Any, ...] = ("10.0.0.5", 40000),
) -> tuple[TLSServerProtocol, FakeTransport, list[bytes]]:
    """Create a protocol attached to a fake transport, capturing TLS input."""
    protocol = TLSServerProtocol(lambda: asyncio.Protocol(), server_ctx, proxy)
    transport = FakeTransport(peer)
    protocol.connection_made(transport)
    fed: list[bytes] = []
    real_conn = protocol.tls_conn
    assert real_conn is not None

    class _BioWriteSpy:
        """Proxy for the SSL.Connection that records bio_write() input."""

        def __getattr__(self, name: str) -> Any:
            return getattr(real_conn, name)

        def bio_write(self, data: bytes) -> int:
            fed.append(bytes(data))
            return real_conn.bio_write(data)

    protocol.tls_conn = _BioWriteSpy()  # type: ignore[assignment]
    return protocol, transport, fed


TRUSTED = ProxyProtocolConfig(trusted_sources=["10.0.0.0/8"])
UNTRUSTED = ProxyProtocolConfig(trusted_sources=["192.0.2.0/24"])


class TestTrustMatrix:
    async def test_trusted_peer_with_header(self, server_ctx, log):
        protocol, transport, fed = _make_protocol(server_ctx, TRUSTED)
        protocol.data_received(build_v2())
        assert not transport.closed
        assert protocol.peername == ("203.0.113.7", 51234)
        assert protocol.proxy_peername == ("10.0.0.5", 40000)
        assert protocol.proxy_header is not None
        assert fed == []  # nothing after the header yet
        assert log.named("proxy_protocol_header_received") == [
            {"client_ip": "203.0.113.7", "proxy_ip": "10.0.0.5", "version": 2}
        ]

    async def test_trusted_peer_with_ipv6_header(self, server_ctx, log):
        protocol, transport, _ = _make_protocol(server_ctx, TRUSTED)
        protocol.data_received(build_v2(family=0x2, src="2001:db8::7", dst="::1"))
        assert protocol.peername == ("2001:db8::7", 51234, 0, 0)
        assert protocol.proxy_peername == ("10.0.0.5", 40000)

    async def test_trusted_peer_with_v1_header(self, server_ctx, log):
        protocol, transport, _ = _make_protocol(server_ctx, TRUSTED)
        protocol.data_received(V1_HEADER)
        assert not transport.closed
        assert protocol.peername == ("203.0.113.7", 51234)

    async def test_trusted_peer_without_header_is_closed(self, server_ctx, log):
        protocol, transport, fed = _make_protocol(server_ctx, TRUSTED)
        protocol.data_received(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03")
        assert transport.closed
        assert fed == []  # never reached TLS
        assert protocol.peername == ("10.0.0.5", 40000)
        events = log.named("proxy_protocol_invalid_header")
        assert len(events) == 1
        assert events[0]["proxy_ip"] == "10.0.0.5"
        assert "missing" in events[0]["error"]

    async def test_untrusted_peer_with_header_is_closed(self, server_ctx, log):
        protocol, transport, fed = _make_protocol(server_ctx, UNTRUSTED)
        protocol.data_received(build_v2() + b"\x16\x03\x01")
        assert transport.closed
        assert fed == []
        # Address is never spoofed.
        assert protocol.peername == ("10.0.0.5", 40000)
        assert protocol.proxy_peername is None
        assert protocol.proxy_header is None
        assert log.named("proxy_protocol_untrusted_source") == [
            {"client_ip": "10.0.0.5"}
        ]

    async def test_untrusted_peer_with_v1_header_is_closed(self, server_ctx, log):
        protocol, transport, fed = _make_protocol(server_ctx, UNTRUSTED)
        protocol.data_received(V1_HEADER)
        assert transport.closed
        assert fed == []
        assert protocol.peername == ("10.0.0.5", 40000)

    async def test_untrusted_peer_without_header_is_direct(self, server_ctx, log):
        protocol, transport, fed = _make_protocol(server_ctx, UNTRUSTED)
        hello = b"\x16\x03\x01"
        protocol.data_received(hello)
        assert fed == [hello]
        assert not transport.closed
        assert protocol.peername == ("10.0.0.5", 40000)
        assert protocol.proxy_peername is None

    async def test_untrusted_screening_only_applies_to_first_chunk(
        self, server_ctx, log
    ):
        protocol, transport, fed = _make_protocol(server_ctx, UNTRUSTED)
        protocol.data_received(b"\x16\x03")
        protocol.data_received(b"P")
        assert fed == [b"\x16\x03", b"P"]

    async def test_empty_trusted_list_trusts_nobody(self, server_ctx, log):
        protocol, transport, _ = _make_protocol(server_ctx, ProxyProtocolConfig())
        protocol.data_received(build_v2())
        assert transport.closed
        assert protocol.peername == ("10.0.0.5", 40000)

    async def test_ipv4_mapped_peer_is_trusted(self, server_ctx, log):
        protocol, transport, _ = _make_protocol(
            server_ctx, TRUSTED, peer=("::ffff:10.0.0.5", 40000, 0, 0)
        )
        protocol.data_received(build_v2())
        assert not transport.closed
        assert protocol.peername == ("203.0.113.7", 51234)


class TestHeaderHandling:
    @pytest.mark.parametrize(
        "header",
        [
            build_v2(command=0x0, family=0x0, transport=0x0),
            build_v2(command=0x0),
            build_v2(family=0x0, transport=0x0),
            b"PROXY UNKNOWN\r\n",
        ],
        ids=["local", "local-with-address", "proxy-unspec", "v1-unknown"],
    )
    async def test_header_without_address_keeps_socket_peer(
        self, server_ctx, log, header
    ):
        protocol, transport, fed = _make_protocol(server_ctx, TRUSTED)
        protocol.data_received(header + b"\x16\x03\x01")
        assert not transport.closed
        assert protocol.peername == ("10.0.0.5", 40000)
        assert protocol.proxy_peername is None
        assert protocol.proxy_header is not None
        assert fed == [b"\x16\x03\x01"]
        assert len(log.named("proxy_protocol_header_without_address")) == 1

    async def test_fragmented_header(self, server_ctx, log):
        protocol, transport, fed = _make_protocol(server_ctx, TRUSTED)
        data = build_v2(family=0x2, src="2001:db8::7", dst="2001:db8::1")
        for i in range(len(data)):
            protocol.data_received(data[i : i + 1])
            assert not transport.closed
        assert protocol.peername == ("2001:db8::7", 51234, 0, 0)
        assert fed == []

    async def test_fragmented_v1_header(self, server_ctx, log):
        protocol, transport, fed = _make_protocol(server_ctx, TRUSTED)
        for i in range(len(V1_HEADER)):
            protocol.data_received(V1_HEADER[i : i + 1])
        assert protocol.peername == ("203.0.113.7", 51234)

    async def test_trailing_bytes_fed_to_tls_unchanged(self, server_ctx, log):
        protocol, transport, fed = _make_protocol(server_ctx, TRUSTED)
        trailing = b"\x16\x03\x01\x00\x05hello"
        header = build_v2()
        # Split so the second chunk completes the header and carries TLS bytes.
        protocol.data_received(header[:10])
        protocol.data_received(header[10:] + trailing)
        assert fed == [trailing]
        # Later data goes straight to TLS too.
        protocol.data_received(b"more")
        assert fed == [trailing, b"more"]

    async def test_malformed_header_closes(self, server_ctx, log):
        protocol, transport, fed = _make_protocol(server_ctx, TRUSTED)
        protocol.data_received(build_v2(command=0x7))
        assert transport.closed
        assert fed == []
        assert "command" in log.named("proxy_protocol_invalid_header")[0]["error"]

    async def test_oversized_header_closes(self, server_ctx, log):
        protocol, transport, fed = _make_protocol(server_ctx, TRUSTED)
        fixed = build_v2(payload=b"")[:14] + b"\xff\xff"
        protocol.data_received(fixed)
        assert transport.closed
        assert "too large" in log.named("proxy_protocol_invalid_header")[0]["error"]

    async def test_data_after_rejection_is_ignored(self, server_ctx, log):
        protocol, transport, fed = _make_protocol(server_ctx, TRUSTED)
        protocol.data_received(b"garbage")
        assert transport.closed
        protocol.data_received(build_v2())
        assert fed == []
        assert protocol.peername == ("10.0.0.5", 40000)

    async def test_timeout_closes_trusted_peer(self, server_ctx, log):
        config = ProxyProtocolConfig(
            trusted_sources=["10.0.0.0/8"], header_timeout=0.05
        )
        protocol, transport, _ = _make_protocol(server_ctx, config)
        protocol.data_received(build_v2()[:8])
        await asyncio.sleep(0.15)
        assert transport.closed
        assert log.named("proxy_protocol_timeout") == [
            {"proxy_ip": "10.0.0.5", "received_bytes": 8}
        ]

    async def test_timeout_cancelled_after_header(self, server_ctx, log):
        config = ProxyProtocolConfig(
            trusted_sources=["10.0.0.0/8"], header_timeout=0.05
        )
        protocol, transport, _ = _make_protocol(server_ctx, config)
        protocol.data_received(build_v2())
        await asyncio.sleep(0.15)
        assert not transport.closed
        assert log.named("proxy_protocol_timeout") == []

    async def test_timeout_cancelled_on_connection_lost(self, server_ctx, log):
        config = ProxyProtocolConfig(
            trusted_sources=["10.0.0.0/8"], header_timeout=0.05
        )
        protocol, transport, _ = _make_protocol(server_ctx, config)
        protocol.connection_lost(None)
        await asyncio.sleep(0.15)
        assert log.named("proxy_protocol_timeout") == []

    async def test_partial_header_then_disconnect_is_logged(self, server_ctx, log):
        protocol, _, _ = _make_protocol(server_ctx, TRUSTED)
        protocol.data_received(build_v2()[:20])
        protocol.connection_lost(None)
        assert log.named("proxy_protocol_incomplete_header") == [
            {"proxy_ip": "10.0.0.5", "received_bytes": 20}
        ]

    async def test_zero_byte_connection_not_logged(self, server_ctx, log):
        protocol, _, _ = _make_protocol(server_ctx, TRUSTED)
        protocol.connection_lost(None)
        assert not [e for _, e, _ in log.events if e.startswith("proxy_")]

    async def test_no_timer_for_untrusted_peer(self, server_ctx, log):
        protocol, _, _ = _make_protocol(server_ctx, UNTRUSTED)
        assert protocol._proxy_timeout_handle is None


class TestDisabledByDefault:
    async def test_default_constructor_has_proxy_disabled(self, server_ctx):
        protocol = TLSServerProtocol(lambda: asyncio.Protocol(), server_ctx)
        assert protocol.proxy_protocol is None

    async def test_header_bytes_go_straight_to_tls(self, server_ctx, log):
        protocol, transport, fed = _make_protocol(server_ctx, None)
        header = build_v2()
        protocol.data_received(header)
        # Passed to TLS untouched (which then fails the handshake).
        assert fed == [header]
        assert protocol.peername == ("10.0.0.5", 40000)
        assert protocol.proxy_header is None
        assert transport.closed
        assert len(log.named("tls_error")) == 1
        assert not any(name.startswith("proxy_") for _, name, _ in log.events)


# ---------------------------------------------------------------------------
# End-to-end: real TLS handshake over loopback behind a PROXY header.
# ---------------------------------------------------------------------------


def _client_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _tls_exchange(
    port: int,
    prefix: bytes,
    message: bytes,
    *,
    coalesce: bool,
    fragment_prefix: bool = False,
) -> bytes:
    """Run a blocking TLS client exchange preceded by raw ``prefix`` bytes.

    With ``coalesce=True`` the prefix and the ClientHello are sent in a
    single ``send()`` so the server sees the TLS bytes in the same chunk as
    the header. With ``fragment_prefix=True`` the prefix is dribbled out a
    few bytes at a time first.
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        if fragment_prefix:
            for i in range(0, len(prefix), 3):
                sock.sendall(prefix[i : i + 3])
                time.sleep(0.01)
            prefix = b""
        elif not coalesce and prefix:
            sock.sendall(prefix)
            time.sleep(0.05)
            prefix = b""

        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        tls = _client_ctx().wrap_bio(incoming, outgoing, server_side=False)

        def flush() -> None:
            nonlocal prefix
            out = outgoing.read()
            if out or prefix:
                sock.sendall(prefix + out)
                prefix = b""

        def pump() -> None:
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError("server closed connection")
            incoming.write(chunk)

        while True:
            try:
                tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                flush()
                pump()
        flush()

        tls.write(message)
        flush()

        response = b""
        while not response:
            try:
                response = tls.read(65536)
            except ssl.SSLWantReadError:
                pump()
        return response
    finally:
        sock.close()


def _raw_exchange(port: int, data: bytes) -> bytes:
    """Send raw bytes and return whatever comes back until EOF."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(data)
        received = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except ConnectionResetError:
                break
            if not chunk:
                break
            received += chunk
        return received


async def _start_server(server_ctx, proxy, sink):
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: TLSServerProtocol(lambda: RecordingProtocol(sink), server_ctx, proxy),
        "127.0.0.1",
        0,
    )
    return server, server.sockets[0].getsockname()[1]


LOOPBACK_TRUSTED = ProxyProtocolConfig(trusted_sources=["127.0.0.0/8"])


class TestEndToEnd:
    @pytest.mark.parametrize("coalesce", [True, False], ids=["coalesced", "separate"])
    async def test_v2_header_then_tls(self, server_ctx, coalesce):
        sink: list[dict[str, Any]] = []
        server, port = await _start_server(server_ctx, LOOPBACK_TRUSTED, sink)
        try:
            response = await asyncio.to_thread(
                _tls_exchange, port, build_v2(), b"hello", coalesce=coalesce
            )
            assert response == b"hello"
            assert sink[0]["peername"] == ("203.0.113.7", 51234)
            assert sink[0]["proxy_peername"][0] == "127.0.0.1"
            assert isinstance(sink[0]["proxy_header"], ProxyHeader)
        finally:
            server.close()
            await server.wait_closed()

    async def test_v2_ipv6_header_then_tls(self, server_ctx):
        sink: list[dict[str, Any]] = []
        server, port = await _start_server(server_ctx, LOOPBACK_TRUSTED, sink)
        header = build_v2(family=0x2, src="2001:db8::42", dst="2001:db8::1")
        try:
            response = await asyncio.to_thread(
                _tls_exchange, port, header, b"six", coalesce=True
            )
            assert response == b"six"
            assert sink[0]["peername"] == ("2001:db8::42", 51234, 0, 0)
        finally:
            server.close()
            await server.wait_closed()

    async def test_fragmented_v1_header_then_tls(self, server_ctx):
        sink: list[dict[str, Any]] = []
        server, port = await _start_server(server_ctx, LOOPBACK_TRUSTED, sink)
        try:
            response = await asyncio.to_thread(
                _tls_exchange,
                port,
                V1_HEADER,
                b"frag",
                coalesce=False,
                fragment_prefix=True,
            )
            assert response == b"frag"
            assert sink[0]["peername"] == ("203.0.113.7", 51234)
        finally:
            server.close()
            await server.wait_closed()

    async def test_local_header_keeps_socket_peer(self, server_ctx):
        sink: list[dict[str, Any]] = []
        server, port = await _start_server(server_ctx, LOOPBACK_TRUSTED, sink)
        header = build_v2(command=0x0, family=0x0, transport=0x0)
        try:
            response = await asyncio.to_thread(
                _tls_exchange, port, header, b"health", coalesce=True
            )
            assert response == b"health"
            assert sink[0]["peername"][0] == "127.0.0.1"
            assert sink[0]["proxy_peername"] is None
        finally:
            server.close()
            await server.wait_closed()

    async def test_trusted_peer_without_header_rejected(self, server_ctx):
        sink: list[dict[str, Any]] = []
        server, port = await _start_server(server_ctx, LOOPBACK_TRUSTED, sink)
        try:
            with pytest.raises((ConnectionError, OSError)):
                await asyncio.to_thread(_tls_exchange, port, b"", b"x", coalesce=True)
            assert sink == []
        finally:
            server.close()
            await server.wait_closed()

    async def test_untrusted_peer_with_header_rejected(self, server_ctx):
        sink: list[dict[str, Any]] = []
        untrusted = ProxyProtocolConfig(trusted_sources=["192.0.2.0/24"])
        server, port = await _start_server(server_ctx, untrusted, sink)
        try:
            with pytest.raises((ConnectionError, OSError)):
                await asyncio.to_thread(
                    _tls_exchange, port, build_v2(), b"x", coalesce=True
                )
            assert sink == []
        finally:
            server.close()
            await server.wait_closed()

    async def test_untrusted_peer_without_header_is_direct(self, server_ctx):
        sink: list[dict[str, Any]] = []
        untrusted = ProxyProtocolConfig(trusted_sources=["192.0.2.0/24"])
        server, port = await _start_server(server_ctx, untrusted, sink)
        try:
            response = await asyncio.to_thread(
                _tls_exchange, port, b"", b"direct", coalesce=True
            )
            assert response == b"direct"
            assert sink[0]["peername"][0] == "127.0.0.1"
            assert sink[0]["proxy_peername"] is None
        finally:
            server.close()
            await server.wait_closed()

    async def test_trusted_peer_silent_times_out(self, server_ctx):
        sink: list[dict[str, Any]] = []
        config = ProxyProtocolConfig(trusted_sources=["127.0.0.1"], header_timeout=0.2)
        server, port = await _start_server(server_ctx, config, sink)
        try:
            start = time.monotonic()
            received = await asyncio.to_thread(_raw_exchange, port, b"\r\n\r\n")
            elapsed = time.monotonic() - start
            assert received == b""
            assert elapsed < 3
        finally:
            server.close()
            await server.wait_closed()

    async def test_disabled_proxy_protocol_unchanged(self, server_ctx):
        sink: list[dict[str, Any]] = []
        server, port = await _start_server(server_ctx, None, sink)
        try:
            response = await asyncio.to_thread(
                _tls_exchange, port, b"", b"plain", coalesce=True
            )
            assert response == b"plain"
            assert sink[0]["peername"][0] == "127.0.0.1"
            assert sink[0]["proxy_peername"] is None
            assert sink[0]["proxy_header"] is None

            # A PROXY header is not understood when disabled: TLS fails.
            with pytest.raises((ConnectionError, OSError)):
                await asyncio.to_thread(
                    _tls_exchange, port, build_v2(), b"x", coalesce=True
                )
        finally:
            server.close()
            await server.wait_closed()
