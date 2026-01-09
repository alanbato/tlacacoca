# Configure TOFU Certificate Validation

This guide shows you how to implement Trust-On-First-Use (TOFU) certificate validation using Tlacacoca's `TOFUDatabase` class.

TOFU is the recommended security model for many lightweight protocols. Instead of relying on Certificate Authorities, clients trust certificates on first use and verify them on subsequent connections.

## Prerequisites

- Tlacacoca installed (see [Installation](../installation.md))
- Understanding of TLS certificates and fingerprints

## Basic TOFU Setup

### Create a TOFU Database

```python
from tlacacoca import TOFUDatabase

# Create database with app-specific location
# Database stored at ~/.myapp/tofu.db
async with TOFUDatabase(app_name="myapp") as tofu:
    # Use TOFU database
    pass

# Or with custom path
from pathlib import Path
async with TOFUDatabase(db_path=Path("/var/lib/myapp/tofu.db")) as tofu:
    pass
```

### Verify or Trust Certificates

```python
from tlacacoca import TOFUDatabase, CertificateChangedError

async def verify_server(hostname: str, port: int, fingerprint: str):
    """Verify a server's certificate using TOFU."""
    async with TOFUDatabase(app_name="myapp") as tofu:
        # Check if we know this host
        if await tofu.is_known(hostname, port):
            # Verify fingerprint matches
            stored = await tofu.get_fingerprint(hostname, port)
            if stored != fingerprint:
                raise CertificateChangedError(
                    hostname, port, stored, fingerprint
                )
            print(f"Certificate verified for {hostname}:{port}")
        else:
            # First connection - trust and store
            await tofu.trust(hostname, port, fingerprint)
            print(f"First connection - certificate trusted")
```

## Manage Known Hosts

### List All Known Hosts

```python
async with TOFUDatabase(app_name="myapp") as tofu:
    hosts = await tofu.list_hosts()
    for host in hosts:
        print(f"{host['hostname']}:{host['port']}")
        print(f"  Fingerprint: {host['fingerprint'][:32]}...")
        print(f"  First seen: {host['first_seen']}")
        print(f"  Last seen: {host['last_seen']}")
```

### Get Host Information

```python
async with TOFUDatabase(app_name="myapp") as tofu:
    info = await tofu.get_host_info("example.com", 1965)
    if info:
        print(f"Fingerprint: {info['fingerprint']}")
        print(f"First seen: {info['first_seen']}")
        print(f"Last seen: {info['last_seen']}")
    else:
        print("Host not in database")
```

### Revoke Trust

```python
async with TOFUDatabase(app_name="myapp") as tofu:
    # Remove a specific host
    await tofu.revoke("old-server.com", 1965)

    # Clear all hosts
    await tofu.clear()
```

## Handle Certificate Changes

When a server's certificate changes, you should alert the user:

```python
from tlacacoca import TOFUDatabase, CertificateChangedError

async def connect_with_tofu(hostname: str, port: int, current_fingerprint: str):
    try:
        async with TOFUDatabase(app_name="myapp") as tofu:
            if await tofu.is_known(hostname, port):
                stored = await tofu.get_fingerprint(hostname, port)
                if stored != current_fingerprint:
                    raise CertificateChangedError(
                        hostname, port, stored, current_fingerprint
                    )
            else:
                # First connection
                await tofu.trust(hostname, port, current_fingerprint)

            # Update last seen
            await tofu.update_last_seen(hostname, port)

    except CertificateChangedError as e:
        print(f"WARNING: Certificate changed for {e.hostname}:{e.port}!")
        print(f"Old fingerprint: {e.old_fingerprint}")
        print(f"New fingerprint: {e.new_fingerprint}")
        print()
        print("This could indicate:")
        print("  1. A man-in-the-middle attack")
        print("  2. Legitimate certificate renewal")
        print()

        # Ask user what to do
        response = input("Trust the new certificate? [y/N]: ")
        if response.lower() == 'y':
            async with TOFUDatabase(app_name="myapp") as tofu:
                await tofu.revoke(e.hostname, e.port)
                await tofu.trust(e.hostname, e.port, e.new_fingerprint)
            print("New certificate trusted")
        else:
            print("Connection aborted")
            raise
```

## Export and Import

### Export TOFU Database

Back up your known hosts to a TOML file:

```python
from pathlib import Path

async with TOFUDatabase(app_name="myapp") as tofu:
    count = await tofu.export_toml(Path("tofu-backup.toml"))
    print(f"Exported {count} hosts")
```

The exported file looks like:

```toml
[_metadata]
exported_at = "2025-01-09T12:00:00+00:00"
version = "1.0"

[hosts."example.com:1965"]
hostname = "example.com"
port = 1965
fingerprint = "sha256:abc123..."
first_seen = "2025-01-15T10:30:00+00:00"
last_seen = "2025-01-09T11:45:00+00:00"
```

### Import TOFU Database

Restore from a backup or transfer from another machine:

```python
from pathlib import Path

async with TOFUDatabase(app_name="myapp") as tofu:
    # Merge with existing (default)
    result = await tofu.import_toml(Path("tofu-backup.toml"), merge=True)
    print(f"Added: {result['added']}, Updated: {result['updated']}, Skipped: {result['skipped']}")

    # Or replace entire database
    result = await tofu.import_toml(Path("tofu-backup.toml"), replace=True)
```

### Handle Import Conflicts

When a host exists with a different fingerprint:

```python
async def on_conflict(hostname, port, old_fp, new_fp):
    """Handle fingerprint conflict during import."""
    print(f"Conflict for {hostname}:{port}")
    print(f"Current: {old_fp[:32]}...")
    print(f"Import:  {new_fp[:32]}...")
    response = input("Use imported fingerprint? [y/N]: ")
    return response.lower() == 'y'

async with TOFUDatabase(app_name="myapp") as tofu:
    result = await tofu.import_toml(
        Path("tofu-backup.toml"),
        merge=True,
        on_conflict=on_conflict
    )
```

## TOFU Database Location

### Default Location

By default, the TOFU database is stored at:

- `~/.{app_name}/tofu.db`

For example, with `app_name="myapp"`:

- **Linux/macOS**: `/home/username/.myapp/tofu.db`
- **Windows**: `C:\Users\username\.myapp\tofu.db`

### Custom Location

```python
from pathlib import Path

# Use custom path
tofu = TOFUDatabase(db_path=Path("/var/lib/myapp/tofu.db"))

# Use in-memory database (for testing)
tofu = TOFUDatabase(db_path=":memory:")
```

## Integration with TLS

Complete example integrating TOFU with TLS connections:

```python
import asyncio
import ssl
from tlacacoca import (
    create_client_context,
    TOFUDatabase,
    CertificateChangedError,
    get_certificate_fingerprint,
)

async def fetch_with_tofu(hostname: str, port: int, path: str):
    """Fetch a resource with TOFU certificate validation."""

    # Create TLS context (we'll do our own verification)
    ssl_context = create_client_context(
        verify_mode=ssl.CERT_NONE,
        check_hostname=False
    )

    # Connect
    reader, writer = await asyncio.open_connection(
        hostname, port, ssl=ssl_context
    )

    try:
        # Get peer certificate
        ssl_object = writer.get_extra_info('ssl_object')
        cert_der = ssl_object.getpeercert(binary_form=True)

        # Get fingerprint
        from cryptography import x509
        cert = x509.load_der_x509_certificate(cert_der)
        fingerprint = get_certificate_fingerprint(cert)

        # TOFU verification
        async with TOFUDatabase(app_name="myapp") as tofu:
            if await tofu.is_known(hostname, port):
                stored = await tofu.get_fingerprint(hostname, port)
                if stored != fingerprint:
                    raise CertificateChangedError(
                        hostname, port, stored, fingerprint
                    )
                await tofu.update_last_seen(hostname, port)
            else:
                # Prompt user for first-time trust
                print(f"First connection to {hostname}:{port}")
                print(f"Fingerprint: {fingerprint}")
                response = input("Trust this certificate? [y/N]: ")
                if response.lower() != 'y':
                    raise ValueError("Certificate not trusted")
                await tofu.trust(hostname, port, fingerprint)

        # Send request
        request = f"protocol://{hostname}:{port}{path}\r\n"
        writer.write(request.encode())
        await writer.drain()

        # Read response
        response = await reader.read()
        return response.decode('utf-8')

    finally:
        writer.close()
        await writer.wait_closed()
```

## Best Practices

### For Users

1. **Verify first connections carefully** - The first connection is the most vulnerable
2. **Be suspicious of unexpected changes** - Certificate changes could indicate attacks
3. **Back up your TOFU database** - Export regularly
4. **Verify through secondary channels** - Contact server operators about changes

### For Developers

1. **Always prompt on first use** - Don't silently trust
2. **Show fingerprints** - Let users verify via secondary channels
3. **Handle errors gracefully** - Explain what certificate changes mean
4. **Support export/import** - Let users back up and transfer trust

## See Also

- [Security Model](../explanation/security-model.md) - Understanding TOFU vs CA
- [Certificate Management](certificates.md) - Working with certificates
- [API Reference](../reference/api/security.md) - TOFUDatabase class documentation
