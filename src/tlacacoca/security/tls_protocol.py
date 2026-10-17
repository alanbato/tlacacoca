"""Manual TLS layer using PyOpenSSL and MemoryBIO for asyncio integration.

This module provides a protocol wrapper that handles TLS manually using
PyOpenSSL, allowing servers to accept arbitrary self-signed client
certificates (which Python's standard ssl module rejects).

The key insight is that we accept raw TCP connections and handle TLS at
the protocol level using PyOpenSSL's memory BIO interface.
"""

import asyncio
from collections.abc import Callable
from typing import Any, cast

from OpenSSL import SSL

from ..logging.structured import get_logger
from .proxy_protocol import (
    DEFAULT_MAX_HEADER_SIZE,
    ProxyHeader,
    ProxyProtocolConfig,
    ProxyProtocolError,
    looks_like_proxy_header,
    parse_proxy_header,
)
from .pyopenssl_tls import (
    get_peer_certificate_from_connection,
    x509_to_cryptography,
)

logger = get_logger(__name__)


class TLSServerProtocol(asyncio.Protocol):
    """Wraps an inner asyncio.Protocol with manual PyOpenSSL TLS handling.

    This protocol handles TLS handshake and encryption/decryption
    manually, then passes decrypted data to the inner protocol.

    The flow is:
    1. TCP connection established (no TLS yet)
    2. This protocol receives encrypted data in data_received()
    3. We feed data to PyOpenSSL via bio_write()
    4. PyOpenSSL decrypts and we pass to inner protocol
    5. Inner protocol writes response, we encrypt and send

    PROXY protocol support (disabled by default) adds a step 1b: when the
    socket peer is one of ``proxy_protocol.trusted_sources``, a PROXY
    protocol v1/v2 header is required before the TLS ClientHello. The
    header is stripped, and the client address it carries is reported to
    the inner protocol as ``transport.get_extra_info("peername")``.

    Args:
        inner_protocol_factory: Factory for the protocol that receives
            decrypted application data.
        ssl_context: PyOpenSSL context, e.g. from
            ``create_permissive_server_context()``.
        proxy_protocol: PROXY protocol settings. ``None`` (the default)
            disables PROXY protocol handling entirely.
    """

    def __init__(
        self,
        inner_protocol_factory: Callable[[], asyncio.Protocol],
        ssl_context: SSL.Context,
        proxy_protocol: ProxyProtocolConfig | None = None,
    ) -> None:
        self.inner_protocol_factory = inner_protocol_factory
        self.ssl_context = ssl_context
        self.proxy_protocol = proxy_protocol
        self.transport: asyncio.Transport | None = None
        self.tls_conn: SSL.Connection | None = None
        self.handshake_complete = False
        self.inner_protocol: asyncio.Protocol | None = None
        # Address used for logging and reported to the inner protocol: the
        # socket peer, or the client address from a trusted PROXY header.
        self._peer_name: tuple[Any, ...] | None = None
        # The actual socket peer (the relay, when a PROXY header was used).
        self._socket_peer_name: tuple[Any, ...] | None = None
        self.proxy_header: ProxyHeader | None = None
        self._proxy_buffer = bytearray()
        self._awaiting_proxy_header = False
        self._screen_untrusted = False
        self._proxy_timeout_handle: asyncio.TimerHandle | None = None
        self._rejected = False
        self._address_from_proxy = False

    @property
    def peername(self) -> tuple[Any, ...] | None:
        """Client address: from a trusted PROXY header, else the socket peer."""
        return self._peer_name

    @property
    def proxy_peername(self) -> tuple[Any, ...] | None:
        """Socket peer (the relay) if a PROXY header supplied the client address.

        ``None`` when the connection was not proxied, or when the header
        did not override the address (``LOCAL``, ``UNKNOWN``, ``UNSPEC``).
        """
        if self._address_from_proxy:
            return self._socket_peer_name
        return None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = cast(asyncio.Transport, transport)
        self._socket_peer_name = transport.get_extra_info("peername")
        self._peer_name = self._socket_peer_name

        # Create PyOpenSSL connection in server mode with memory BIO
        self.tls_conn = SSL.Connection(self.ssl_context, None)
        self.tls_conn.set_accept_state()

        if self.proxy_protocol is not None:
            self._setup_proxy_protocol(self.proxy_protocol)

        logger.debug(
            "tls_connection_started",
            client_ip=(self._peer_name[0] if self._peer_name else "unknown"),
        )

    def _setup_proxy_protocol(self, config: ProxyProtocolConfig) -> None:
        peer_ip = self._socket_peer_name[0] if self._socket_peer_name else None
        if peer_ip is not None and config.is_trusted(peer_ip):
            self._awaiting_proxy_header = True
            loop = asyncio.get_running_loop()
            self._proxy_timeout_handle = loop.call_later(
                config.header_timeout,
                self._handle_proxy_timeout,
            )
        else:
            # Direct connection: never parse a header, but reject anything
            # that looks like one so it is logged instead of a TLS error.
            self._screen_untrusted = True

    def data_received(self, data: bytes) -> None:
        if self.tls_conn is None or self.transport is None or self._rejected:
            return

        if self._awaiting_proxy_header:
            remaining = self._consume_proxy_header(data)
            if not remaining:
                return
            data = remaining
        elif self._screen_untrusted:
            self._screen_untrusted = False
            if looks_like_proxy_header(data):
                self._reject(
                    "proxy_protocol_untrusted_source",
                    client_ip=self._client_ip_for_log(self._socket_peer_name),
                )
                return

        try:
            self.tls_conn.bio_write(data)

            if not self.handshake_complete:
                self._do_handshake()
            else:
                self._process_application_data()

        except SSL.Error as e:
            self._close_with_error(f"TLS error: {e}")

    def _do_handshake(self) -> None:
        if self.tls_conn is None:
            return

        try:
            self.tls_conn.do_handshake()
            self.handshake_complete = True

            logger.debug(
                "tls_handshake_complete",
                client_ip=(self._peer_name[0] if self._peer_name else "unknown"),
            )

            self._initialize_inner_protocol()

        except SSL.WantReadError:
            self._flush_outgoing()
        except SSL.Error as e:
            self._close_with_error(f"Handshake failed: {e}")

    def _process_pending_after_handshake(self) -> None:
        """Process application data that arrived with the final
        handshake message."""
        if self.tls_conn is None or self.inner_protocol is None:
            return

        try:
            while True:
                decrypted = self.tls_conn.recv(8192)
                if decrypted:
                    self.inner_protocol.data_received(decrypted)
                else:
                    break
        except SSL.WantReadError:
            pass
        except SSL.ZeroReturnError:
            self._handle_close()

        self._flush_outgoing()

    def _initialize_inner_protocol(self) -> None:
        if self.tls_conn is None:
            return

        self.inner_protocol = self.inner_protocol_factory()
        inner_transport = TLSTransportWrapper(self)

        peer_cert = get_peer_certificate_from_connection(self.tls_conn)
        if peer_cert:
            inner_transport.peer_certificate = x509_to_cryptography(
                peer_cert,
            )
            logger.debug(
                "client_certificate_received",
                client_ip=(self._peer_name[0] if self._peer_name else "unknown"),
            )

        self.inner_protocol.connection_made(
            cast(asyncio.BaseTransport, inner_transport),
        )
        self._flush_outgoing()
        self._process_pending_after_handshake()

    def _process_application_data(self) -> None:
        if self.tls_conn is None:
            return

        try:
            while True:
                decrypted = self.tls_conn.recv(8192)
                if decrypted and self.inner_protocol:
                    self.inner_protocol.data_received(decrypted)
        except SSL.WantReadError:
            pass
        except SSL.ZeroReturnError:
            self._handle_close()

        self._flush_outgoing()

    def _flush_outgoing(self) -> None:
        if self.transport is None or self.tls_conn is None:
            return

        try:
            while True:
                pending = self.tls_conn.bio_read(8192)
                if not pending:
                    break
                self.transport.write(pending)
        except SSL.WantReadError:
            pass
        except SSL.Error:
            pass

    def _consume_proxy_header(self, data: bytes) -> bytes | None:
        """Buffer and parse the PROXY header; return bytes that follow it.

        Returns ``None`` while the header is incomplete or after the
        connection was rejected.
        """
        max_header_size = (
            self.proxy_protocol.max_header_size
            if self.proxy_protocol is not None
            else DEFAULT_MAX_HEADER_SIZE
        )
        self._proxy_buffer.extend(data)
        try:
            header = parse_proxy_header(
                bytes(self._proxy_buffer),
                max_header_size=max_header_size,
            )
        except ProxyProtocolError as e:
            self._reject(
                "proxy_protocol_invalid_header",
                proxy_ip=self._client_ip_for_log(self._socket_peer_name),
                error=str(e),
            )
            return None

        if header is None:
            return None

        remaining = bytes(self._proxy_buffer[header.length :])
        self._proxy_buffer = bytearray()
        self._awaiting_proxy_header = False
        self._cancel_proxy_timeout()
        self.proxy_header = header

        if header.source is not None:
            self._peer_name = _make_peername(header.source)
            self._address_from_proxy = True
            logger.debug(
                "proxy_protocol_header_received",
                client_ip=header.source[0],
                proxy_ip=self._client_ip_for_log(self._socket_peer_name),
                version=header.version,
            )
        else:
            logger.debug(
                "proxy_protocol_header_without_address",
                proxy_ip=self._client_ip_for_log(self._socket_peer_name),
                version=header.version,
                command=header.command,
                family=header.family,
            )
        return remaining

    def _handle_proxy_timeout(self) -> None:
        self._proxy_timeout_handle = None
        if self._awaiting_proxy_header:
            self._reject(
                "proxy_protocol_timeout",
                proxy_ip=self._client_ip_for_log(self._socket_peer_name),
                received_bytes=len(self._proxy_buffer),
            )

    def _cancel_proxy_timeout(self) -> None:
        if self._proxy_timeout_handle is not None:
            self._proxy_timeout_handle.cancel()
            self._proxy_timeout_handle = None

    def _reject(self, event: str, **fields: Any) -> None:
        """Log a PROXY protocol failure and drop the connection."""
        self._rejected = True
        self._awaiting_proxy_header = False
        self._proxy_buffer = bytearray()
        self._cancel_proxy_timeout()
        logger.warning(event, **fields)
        if self.transport:
            self.transport.close()

    @staticmethod
    def _client_ip_for_log(peer: tuple[Any, ...] | None) -> str:
        return str(peer[0]) if peer else "unknown"

    def _close_with_error(self, message: str) -> None:
        logger.warning(
            "tls_error",
            client_ip=(self._peer_name[0] if self._peer_name else "unknown"),
            error=message,
        )
        if self.transport:
            self.transport.close()

    def _handle_close(self) -> None:
        if self.inner_protocol:
            self.inner_protocol.connection_lost(None)
        if self.transport:
            self.transport.close()

    def connection_lost(self, exc: Exception | None) -> None:
        self._cancel_proxy_timeout()
        if self._awaiting_proxy_header and self._proxy_buffer:
            # Zero-byte connections (e.g. TCP health checks) are not logged.
            logger.warning(
                "proxy_protocol_incomplete_header",
                proxy_ip=self._client_ip_for_log(self._socket_peer_name),
                received_bytes=len(self._proxy_buffer),
            )
        if self.inner_protocol:
            self.inner_protocol.connection_lost(exc)


def _make_peername(address: tuple[str, int]) -> tuple[Any, ...]:
    """Build a peername tuple shaped like asyncio's for the address family.

    IPv4 peers are ``(host, port)``; IPv6 peers are
    ``(host, port, flowinfo, scope_id)``.
    """
    host, port = address
    if ":" in host:
        return (host, port, 0, 0)
    return (host, port)


class TLSTransportWrapper:
    """Wrapper that makes a TLS connection look like a regular transport.

    This allows the inner protocol to use standard asyncio transport
    methods (write, close, get_extra_info) without knowing about TLS.
    """

    def __init__(self, tls_protocol: TLSServerProtocol) -> None:
        self.tls_protocol = tls_protocol
        self.peer_certificate: Any = None
        self._close_scheduled = False

    def write(self, data: bytes) -> None:
        if self.tls_protocol.tls_conn:
            self.tls_protocol.tls_conn.send(data)
            self.tls_protocol._flush_outgoing()

    def close(self) -> None:
        """Initiate TLS shutdown and close with a small delay.

        The 0.1s delay allows async clients to receive the final
        response before the connection is closed.
        """
        if self._close_scheduled:
            return
        self._close_scheduled = True

        if self.tls_protocol.tls_conn:
            try:
                self.tls_protocol.tls_conn.shutdown()
                self.tls_protocol._flush_outgoing()
            except SSL.Error:
                pass

        if self.tls_protocol.transport:
            try:
                loop = asyncio.get_running_loop()
                loop.call_later(0.1, self._do_close)
            except RuntimeError:
                self._do_close()

    def _do_close(self) -> None:
        if self.tls_protocol.transport:
            self.tls_protocol.transport.close()

    def get_extra_info(
        self,
        name: str,
        default: Any = None,
    ) -> Any:
        if name == "peername":
            if self.tls_protocol.transport is None:
                return None
            if self.tls_protocol.proxy_peername is not None:
                return self.tls_protocol.peername
            return self.tls_protocol.transport.get_extra_info(
                "peername",
            )
        if name == "proxy_peername":
            return self.tls_protocol.proxy_peername
        if name == "proxy_header":
            return self.tls_protocol.proxy_header
        if name == "ssl_object":
            return _SSLObjectWrapper(self.peer_certificate)
        return default

    def is_closing(self) -> bool:
        if self.tls_protocol.transport:
            return self.tls_protocol.transport.is_closing()
        return True


class _SSLObjectWrapper:
    """Wrapper to provide getpeercert() interface.

    This allows existing code that calls
    ``transport.get_extra_info("ssl_object").getpeercert(binary_form=True)``
    to work with PyOpenSSL-based connections.
    """

    def __init__(self, cert: Any) -> None:
        self._cert = cert

    def getpeercert(
        self,
        binary_form: bool = False,
    ) -> bytes | dict[str, Any] | None:
        if self._cert is None:
            return None
        if binary_form:
            from cryptography.hazmat.primitives import serialization

            return self._cert.public_bytes(serialization.Encoding.DER)
        return {}
