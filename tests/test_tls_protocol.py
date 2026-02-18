"""Integration tests for TLSServerProtocol with self-signed client certs.

These tests verify that the PyOpenSSL TLS layer correctly accepts
arbitrary self-signed client certificates — the key feature that
Python's standard ssl module fails to provide.

Uses a minimal echo protocol as the inner protocol to keep tests
protocol-agnostic.
"""

import asyncio
import ssl

import pytest

from tlacacoca.security.certificates import generate_self_signed_cert
from tlacacoca.security.pyopenssl_tls import create_permissive_server_context
from tlacacoca.security.tls_protocol import TLSServerProtocol


class EchoProtocol(asyncio.Protocol):
    """Minimal echo protocol for testing TLSServerProtocol."""

    def __init__(self) -> None:
        self.transport = None
        self.data_received_chunks: list[bytes] = []

    def connection_made(self, transport) -> None:
        self.transport = transport

    def data_received(self, data: bytes) -> None:
        self.data_received_chunks.append(data)
        if self.transport:
            self.transport.write(data)
            self.transport.close()

    def connection_lost(self, exc) -> None:
        pass


@pytest.fixture
def server_certs(tmp_path):
    """Generate server certificate and key files."""
    cert_pem, key_pem = generate_self_signed_cert("localhost", "Test")
    cert_file = tmp_path / "server.pem"
    key_file = tmp_path / "server.key"
    cert_file.write_bytes(cert_pem)
    key_file.write_bytes(key_pem)
    return str(cert_file), str(key_file)


@pytest.fixture
def client_certs(tmp_path):
    """Generate client certificate and key files."""
    cert_pem, key_pem = generate_self_signed_cert("client", "Test")
    cert_file = tmp_path / "client.pem"
    key_file = tmp_path / "client.key"
    cert_file.write_bytes(cert_pem)
    key_file.write_bytes(key_pem)
    return str(cert_file), str(key_file)


def _create_client_ssl_context(
    client_cert: str | None = None,
    client_key: str | None = None,
) -> ssl.SSLContext:
    """Create a stdlib SSL context for the client side of tests."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if client_cert and client_key:
        ctx.load_cert_chain(client_cert, client_key)
    return ctx


@pytest.mark.asyncio
async def test_self_signed_client_cert_accepted(
    server_certs,
    client_certs,
):
    """Self-signed client cert is accepted via TLSServerProtocol."""
    cert_file, key_file = server_certs
    client_cert, client_key = client_certs

    pyopenssl_ctx = create_permissive_server_context(
        cert_file,
        key_file,
        request_client_cert=True,
    )

    received = asyncio.Future()

    def protocol_factory():
        proto = EchoProtocol()
        original_data_received = proto.data_received

        def capturing_data_received(data):
            if not received.done():
                received.set_result(data)
            original_data_received(data)

        proto.data_received = capturing_data_received
        return proto

    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: TLSServerProtocol(protocol_factory, pyopenssl_ctx),
        "127.0.0.1",
        0,
    )

    port = server.sockets[0].getsockname()[1]
    try:
        client_ctx = _create_client_ssl_context(client_cert, client_key)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            port,
            ssl=client_ctx,
        )
        writer.write(b"hello")
        await writer.drain()

        response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
        assert response == b"hello"
        writer.close()
        await writer.wait_closed()

        data = await asyncio.wait_for(received, timeout=2.0)
        assert data == b"hello"
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_connection_without_client_cert(server_certs):
    """Connection works without a client cert when not required."""
    cert_file, key_file = server_certs

    pyopenssl_ctx = create_permissive_server_context(
        cert_file,
        key_file,
        request_client_cert=False,
    )

    received = asyncio.Future()

    def protocol_factory():
        proto = EchoProtocol()
        original_data_received = proto.data_received

        def capturing_data_received(data):
            if not received.done():
                received.set_result(data)
            original_data_received(data)

        proto.data_received = capturing_data_received
        return proto

    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: TLSServerProtocol(protocol_factory, pyopenssl_ctx),
        "127.0.0.1",
        0,
    )

    port = server.sockets[0].getsockname()[1]
    try:
        client_ctx = _create_client_ssl_context()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            port,
            ssl=client_ctx,
        )
        writer.write(b"no cert")
        await writer.drain()

        response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
        assert response == b"no cert"
        writer.close()
        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_multiple_different_client_certs(server_certs, tmp_path):
    """Multiple different self-signed client certs are all accepted."""
    cert_file, key_file = server_certs

    pyopenssl_ctx = create_permissive_server_context(
        cert_file,
        key_file,
        request_client_cert=True,
    )

    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: TLSServerProtocol(EchoProtocol, pyopenssl_ctx),
        "127.0.0.1",
        0,
    )

    port = server.sockets[0].getsockname()[1]
    try:
        for i in range(3):
            c_pem, k_pem = generate_self_signed_cert(f"client-{i}", "Test")
            c_file = tmp_path / f"client{i}.pem"
            k_file = tmp_path / f"client{i}.key"
            c_file.write_bytes(c_pem)
            k_file.write_bytes(k_pem)

            client_ctx = _create_client_ssl_context(
                str(c_file),
                str(k_file),
            )
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                port,
                ssl=client_ctx,
            )
            msg = f"hello from client {i}".encode()
            writer.write(msg)
            await writer.drain()

            response = await asyncio.wait_for(
                reader.read(1024),
                timeout=2.0,
            )
            assert response == msg, f"Client {i} should get echo"
            writer.close()
            await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_transport_wrapper_exposes_peer_certificate(
    server_certs,
    client_certs,
):
    """TLSTransportWrapper exposes peer_certificate after handshake."""
    cert_file, key_file = server_certs
    client_cert, client_key = client_certs

    pyopenssl_ctx = create_permissive_server_context(
        cert_file,
        key_file,
        request_client_cert=True,
    )

    cert_future = asyncio.Future()

    def protocol_factory():
        proto = EchoProtocol()
        original_connection_made = proto.connection_made

        def capturing_connection_made(transport):
            peer_cert = transport.peer_certificate
            if not cert_future.done():
                cert_future.set_result(peer_cert)
            original_connection_made(transport)

        proto.connection_made = capturing_connection_made
        return proto

    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: TLSServerProtocol(protocol_factory, pyopenssl_ctx),
        "127.0.0.1",
        0,
    )

    port = server.sockets[0].getsockname()[1]
    try:
        client_ctx = _create_client_ssl_context(client_cert, client_key)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            port,
            ssl=client_ctx,
        )
        writer.write(b"test")
        await writer.drain()

        peer_cert = await asyncio.wait_for(cert_future, timeout=2.0)
        assert peer_cert is not None

        from cryptography import x509

        assert isinstance(peer_cert, x509.Certificate)
        cn = peer_cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME,
        )[0].value
        assert cn == "client"

        writer.close()
        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()
