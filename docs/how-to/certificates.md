# Manage TLS Certificates

This guide shows you how to generate, load, inspect, and validate TLS certificates using Tlacacoca's certificate utilities.

## Prerequisites

- Tlacacoca installed (see [Installation](../installation.md))
- Basic understanding of TLS certificates

## Generate Self-Signed Certificates

Self-signed certificates are useful for development, testing, and protocols that use TOFU validation.

### Basic Generation

```python
from pathlib import Path
from tlacacoca import generate_self_signed_cert

# Generate certificate for localhost
cert_pem, key_pem = generate_self_signed_cert("localhost")

# Save to files
Path("cert.pem").write_bytes(cert_pem)
Path("key.pem").write_bytes(key_pem)
```

### Custom Options

```python
cert_pem, key_pem = generate_self_signed_cert(
    hostname="example.com",
    key_size=4096,          # RSA key size (default: 2048)
    valid_days=365,         # Validity period (default: 365)
    organization="My Org",  # Organization name
)
```

### For Server Use

```python
from tlacacoca import generate_self_signed_cert, create_server_context

# Generate certificate
cert_pem, key_pem = generate_self_signed_cert("myserver.local")

# Save with appropriate permissions
cert_path = Path("server.pem")
key_path = Path("server.key")

cert_path.write_bytes(cert_pem)
key_path.write_bytes(key_pem)
key_path.chmod(0o600)  # Restrict key file permissions

# Use in server context
ssl_context = create_server_context(
    certfile=str(cert_path),
    keyfile=str(key_path)
)
```

### For Client Authentication

```python
# Generate client identity certificate
cert_pem, key_pem = generate_self_signed_cert(
    hostname="client-identity",
    organization="My Identity",
    valid_days=730  # 2 years
)

Path("client.pem").write_bytes(cert_pem)
Path("client.key").write_bytes(key_pem)
```

## Load and Inspect Certificates

### Load Certificate from File

```python
from tlacacoca import load_certificate

cert = load_certificate(Path("cert.pem"))
```

### Get Certificate Fingerprint

Fingerprints are used for TOFU validation:

```python
from tlacacoca import load_certificate, get_certificate_fingerprint

cert = load_certificate(Path("cert.pem"))
fingerprint = get_certificate_fingerprint(cert)
print(f"SHA-256: {fingerprint}")
# Output: sha256:a1b2c3d4e5f6789012345678901234567890abcdef...
```

### Get Fingerprint from File Path

```python
from tlacacoca import get_certificate_fingerprint_from_path

fingerprint = get_certificate_fingerprint_from_path(Path("cert.pem"))
```

### Get Certificate Information

```python
from tlacacoca import load_certificate, get_certificate_info

cert = load_certificate(Path("cert.pem"))
info = get_certificate_info(cert)

print(f"Subject: {info['subject']}")
print(f"Issuer: {info['issuer']}")
print(f"Serial: {info['serial_number']}")
print(f"Not Before: {info['not_before']}")
print(f"Not After: {info['not_after']}")
print(f"Fingerprint (SHA-256): {info['fingerprint_sha256']}")
print(f"Fingerprint (SHA-1): {info['fingerprint_sha1']}")
```

## Validate Certificates

### Check Expiration

```python
from tlacacoca import load_certificate, is_certificate_expired

cert = load_certificate(Path("cert.pem"))

if is_certificate_expired(cert):
    print("Certificate has expired!")
else:
    print("Certificate is still valid")
```

### Check Hostname Validity

```python
from tlacacoca import load_certificate, is_certificate_valid_for_hostname

cert = load_certificate(Path("cert.pem"))

if is_certificate_valid_for_hostname(cert, "example.com"):
    print("Certificate is valid for example.com")
else:
    print("Certificate is NOT valid for example.com")
```

### Validate Certificate File

```python
from tlacacoca import validate_certificate_file

is_valid, error_message = validate_certificate_file(Path("cert.pem"))

if is_valid:
    print("Certificate file is valid")
else:
    print(f"Certificate file invalid: {error_message}")
```

## Use External Certificates

You can use certificates from external sources like Let's Encrypt or your own CA.

### Requirements

Certificates must be:

- In PEM format (text files with `-----BEGIN CERTIFICATE-----`)
- Valid for your server's hostname (CN or SAN must match)
- Accompanied by the private key (also in PEM format)

### Using Let's Encrypt Certificates

```python
from tlacacoca import create_server_context

# Let's Encrypt certificates are typically stored at:
# /etc/letsencrypt/live/yourdomain.com/

ssl_context = create_server_context(
    certfile="/etc/letsencrypt/live/example.com/fullchain.pem",
    keyfile="/etc/letsencrypt/live/example.com/privkey.pem"
)
```

## Set Correct File Permissions

TLS private keys must be protected from unauthorized access.

### Secure Private Key Permissions

```python
from pathlib import Path

key_path = Path("server.key")

# Set secure permissions (owner read/write only)
key_path.chmod(0o600)

# Verify permissions
import stat
mode = key_path.stat().st_mode
if mode & (stat.S_IRGRP | stat.S_IROTH):
    print("WARNING: Private key is readable by others!")
```

### Recommended Permissions

```
-rw------- (0600)  server.key   # Private key - owner only
-rw-r--r-- (0644)  server.pem   # Certificate - publicly readable
```

## Certificate Renewal

Certificates have expiration dates. Plan for renewal.

### Check Expiration Date

```python
from tlacacoca import load_certificate, get_certificate_info
from datetime import datetime, timezone

cert = load_certificate(Path("cert.pem"))
info = get_certificate_info(cert)

not_after = info['not_after']
days_remaining = (not_after - datetime.now(timezone.utc)).days

if days_remaining < 30:
    print(f"WARNING: Certificate expires in {days_remaining} days!")
elif days_remaining < 90:
    print(f"Certificate expires in {days_remaining} days - consider renewal")
else:
    print(f"Certificate valid for {days_remaining} more days")
```

### Regenerate Self-Signed Certificate

```python
from tlacacoca import generate_self_signed_cert

# Generate new certificate
cert_pem, key_pem = generate_self_signed_cert(
    hostname="example.com",
    valid_days=365
)

# Save (overwrites old files)
Path("cert.pem").write_bytes(cert_pem)
Path("key.pem").write_bytes(key_pem)

print("Certificate renewed - clients using TOFU will need to accept new fingerprint")
```

## Compare Certificates

### Check if Two Certificates Match

```python
from tlacacoca import load_certificate, get_certificate_fingerprint

cert1 = load_certificate(Path("cert1.pem"))
cert2 = load_certificate(Path("cert2.pem"))

fp1 = get_certificate_fingerprint(cert1)
fp2 = get_certificate_fingerprint(cert2)

if fp1 == fp2:
    print("Certificates are identical")
else:
    print("Certificates are different")
```

## Troubleshooting

### Certificate Not Valid for Hostname

**Problem:** Server hostname doesn't match certificate CN/SAN.

**Solution:** Generate a certificate with the correct hostname:

```python
cert_pem, key_pem = generate_self_signed_cert("correct-hostname.com")
```

### Certificate Expired

**Problem:** Certificate has passed its expiration date.

**Solution:** Generate a new certificate with longer validity:

```python
cert_pem, key_pem = generate_self_signed_cert(
    hostname="example.com",
    valid_days=730  # 2 years
)
```

### Private Key Doesn't Match Certificate

**Problem:** Certificate and private key are from different pairs.

**Solution:** Generate a new matching pair:

```python
cert_pem, key_pem = generate_self_signed_cert("example.com")
# Use these together - they are a matched pair
```

### Permission Denied

**Problem:** Can't read private key file.

**Solution:** Check file ownership and permissions:

```python
from pathlib import Path
import os

key_path = Path("server.key")
print(f"Owner: {key_path.owner()}")
print(f"Mode: {oct(key_path.stat().st_mode)}")

# Fix ownership if needed (requires appropriate privileges)
# os.chown(str(key_path), uid, gid)
```

## See Also

- [TOFU Configuration](tofu.md) - Using certificates with TOFU
- [Client Certificates](client-certificates.md) - Client authentication
- [API Reference](../reference/api/security.md) - Certificate functions documentation
- [Security Model](../explanation/security-model.md) - Understanding TLS and TOFU
