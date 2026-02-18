"""Security module for TLS, certificates, and TOFU validation."""

from .certificates import (
    generate_self_signed_cert,
    get_certificate_fingerprint,
    get_certificate_fingerprint_from_path,
    get_certificate_info,
    is_certificate_expired,
    is_certificate_valid_for_hostname,
    load_certificate,
    validate_certificate_file,
)
from .pyopenssl_tls import (
    create_permissive_server_context,
    get_peer_certificate_from_connection,
    x509_to_cryptography,
)
from .tls import create_client_context, create_server_context
from .tls_protocol import TLSServerProtocol, TLSTransportWrapper
from .tofu import CertificateChangedError, TOFUDatabase

__all__ = [
    # TLS
    "create_client_context",
    "create_server_context",
    # PyOpenSSL TLS
    "create_permissive_server_context",
    "get_peer_certificate_from_connection",
    "x509_to_cryptography",
    "TLSServerProtocol",
    "TLSTransportWrapper",
    # Certificates
    "generate_self_signed_cert",
    "load_certificate",
    "get_certificate_fingerprint",
    "get_certificate_fingerprint_from_path",
    "is_certificate_expired",
    "is_certificate_valid_for_hostname",
    "get_certificate_info",
    "validate_certificate_file",
    # TOFU
    "TOFUDatabase",
    "CertificateChangedError",
]
