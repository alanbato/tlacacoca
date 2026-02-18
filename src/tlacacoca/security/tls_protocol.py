"""Manual TLS layer using PyOpenSSL and MemoryBIO for asyncio integration.

This module provides a protocol wrapper that handles TLS manually using
PyOpenSSL, allowing servers to accept arbitrary self-signed client
certificates (which Python's standard ssl module rejects).

The key insight is that we accept raw TCP connections and handle TLS at
the protocol level using PyOpenSSL's memory BIO interface.
"""

import asyncio
from collections.abc import Callable
from typing import Any

from OpenSSL import SSL

from .pyopenssl_tls import (
    get_peer_certificate_from_connection,
    x509_to_cryptography,
)
from ..logging.structured import get_logger

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
    """

    def __init__(
        self,
        inner_protocol_factory: Callable[[], asyncio.Protocol],
        ssl_context: SSL.Context,
    ) -> None:
        self.inner_protocol_factory = inner_protocol_factory
        self.ssl_context = ssl_context
        self.transport: asyncio.Transport | None = None
        self.tls_conn: SSL.Connection | None = None
        self.handshake_complete = False
        self.inner_protocol: asyncio.Protocol | None = None
        self._peer_name: tuple[str, int] | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        self._peer_name = self.transport.get_extra_info("peername")

        # Create PyOpenSSL connection in server mode with memory BIO
        self.tls_conn = SSL.Connection(self.ssl_context, None)
        self.tls_conn.set_accept_state()

        logger.debug(
            "tls_connection_started",
            client_ip=(self._peer_name[0] if self._peer_name else "unknown"),
        )

    def data_received(self, data: bytes) -> None:
        if self.tls_conn is None or self.transport is None:
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

        self.inner_protocol.connection_made(inner_transport)
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
        if self.inner_protocol:
            self.inner_protocol.connection_lost(exc)


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
            if self.tls_protocol.transport:
                return self.tls_protocol.transport.get_extra_info(
                    "peername",
                )
            return None
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
