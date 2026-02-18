"""Tests for PyOpenSSL TLS integration."""

import pytest
from OpenSSL import SSL

from tlacacoca.security.certificates import generate_self_signed_cert
from tlacacoca.security.pyopenssl_tls import (
    create_permissive_server_context,
    get_peer_certificate_from_connection,
    verify_callback,
    x509_to_cryptography,
)


class TestVerifyCallback:
    """Tests for the verify callback function."""

    def test_verify_callback_accepts_valid_cert(self):
        assert verify_callback(None, None, 0, 0, True) is True

    def test_verify_callback_accepts_invalid_cert(self):
        # ok=False indicates OpenSSL rejected the cert, but we accept
        assert verify_callback(None, None, 0, 0, False) is True

    def test_verify_callback_accepts_self_signed_error(self):
        # Error 18 is X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
        assert verify_callback(None, None, 18, 0, False) is True

    def test_verify_callback_accepts_any_error_number(self):
        for errnum in [0, 10, 18, 19, 20, 21, 100]:
            assert verify_callback(None, None, errnum, 0, False) is True


class TestCreatePermissiveServerContext:
    """Tests for permissive server context creation."""

    def test_create_context_basic(self, tmp_path):
        cert_pem, key_pem = generate_self_signed_cert("localhost", "Test")
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_bytes(cert_pem)
        key_file.write_bytes(key_pem)

        ctx = create_permissive_server_context(
            str(cert_file),
            str(key_file),
            request_client_cert=False,
        )
        assert isinstance(ctx, SSL.Context)

    def test_create_context_with_client_cert_request(self, tmp_path):
        cert_pem, key_pem = generate_self_signed_cert("localhost", "Test")
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_bytes(cert_pem)
        key_file.write_bytes(key_pem)

        ctx = create_permissive_server_context(
            str(cert_file),
            str(key_file),
            request_client_cert=True,
        )
        assert isinstance(ctx, SSL.Context)

    def test_create_context_with_session_id(self, tmp_path):
        cert_pem, key_pem = generate_self_signed_cert("localhost", "Test")
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_bytes(cert_pem)
        key_file.write_bytes(key_pem)

        ctx = create_permissive_server_context(
            str(cert_file),
            str(key_file),
            session_id=b"test-session",
        )
        assert isinstance(ctx, SSL.Context)

    def test_create_context_invalid_cert_file(self, tmp_path):
        key_pem = generate_self_signed_cert("localhost", "Test")[1]
        key_file = tmp_path / "key.pem"
        key_file.write_bytes(key_pem)

        with pytest.raises(SSL.Error):
            create_permissive_server_context(
                str(tmp_path / "nonexistent.pem"),
                str(key_file),
            )

    def test_create_context_invalid_key_file(self, tmp_path):
        cert_pem = generate_self_signed_cert("localhost", "Test")[0]
        cert_file = tmp_path / "cert.pem"
        cert_file.write_bytes(cert_pem)

        with pytest.raises(SSL.Error):
            create_permissive_server_context(
                str(cert_file),
                str(tmp_path / "nonexistent.key"),
            )


class TestGetPeerCertificateFromConnection:
    """Tests for peer certificate extraction."""

    def test_get_peer_certificate_returns_none_on_error(self):
        result = get_peer_certificate_from_connection(None)
        assert result is None


class TestX509ToCryptography:
    """Tests for X509 to cryptography conversion."""

    def test_convert_certificate(self):
        from cryptography import x509
        from OpenSSL import crypto

        cert_pem, _ = generate_self_signed_cert("localhost", "Test")
        pyopenssl_cert = crypto.load_certificate(
            crypto.FILETYPE_PEM,
            cert_pem,
        )
        crypto_cert = x509_to_cryptography(pyopenssl_cert)

        assert isinstance(crypto_cert, x509.Certificate)

        subject_cn = crypto_cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME,
        )[0].value
        assert subject_cn == "localhost"
