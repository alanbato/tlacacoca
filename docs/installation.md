# Installation

This guide will help you install Tlacacoca in your project. Choose the installation method that best fits your needs.

## Prerequisites

Before installing Tlacacoca, ensure you have:

- **Python 3.10 or higher** installed on your system
- **pip** (included with Python) or **uv** (recommended for faster installations)

!!! tip "Why uv?"
    [uv](https://docs.astral.sh/uv/) is a modern, extremely fast Python package manager written in Rust. It's 10-100x faster than pip and provides better dependency resolution. We recommend using uv for the best experience.

### Checking Your Python Version

```bash
python --version
```

You should see Python 3.10.x or higher. If not, download the latest version from [python.org](https://www.python.org/downloads/).

### Installing uv (Recommended)

=== "Linux/macOS"

    ```bash
    curl -LsSf https://astral.sh/uv/install.sh | sh
    ```

=== "Windows"

    ```powershell
    powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
    ```

=== "Using pip"

    ```bash
    pip install uv
    ```

## Installation Methods

### Method 1: Add to Your Project (Recommended)

This is the recommended method for using Tlacacoca in your Python projects.

=== "Using uv (New Project)"

    ```bash
    # Create a new project
    uv init my-protocol-server
    cd my-protocol-server

    # Add tlacacoca as a dependency
    uv add tlacacoca
    ```

=== "Using uv (Existing Project)"

    ```bash
    # Add to your existing project
    uv add tlacacoca
    ```

=== "Using pip"

    ```bash
    # In a virtual environment (recommended)
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    pip install tlacacoca
    ```

### Method 2: Install from Source (Development)

This method is for developers who want to contribute to Tlacacoca or test the latest unreleased features.

```bash
# Clone the repository
git clone https://github.com/alanbato/tlacacoca.git
cd tlacacoca

# Install with development dependencies
uv sync
```

!!! warning "Development Installation"
    Installing from source gives you the latest development version, which may be unstable. For production use, install from PyPI using Method 1.

## Verifying Your Installation

After installation, verify that Tlacacoca is working correctly:

### Check the Import

```python
# In a Python shell or script
import tlacacoca

# Check available components
print(dir(tlacacoca))
```

Expected output includes: `create_client_context`, `create_server_context`, `TOFUDatabase`, `RateLimiter`, `AccessControl`, etc.

### Run a Quick Test

```python
from tlacacoca import (
    create_client_context,
    generate_self_signed_cert,
    get_certificate_fingerprint,
    load_certificate,
)
from pathlib import Path
import tempfile

# Generate a test certificate
cert_pem, key_pem = generate_self_signed_cert("localhost")
print(f"Generated certificate: {len(cert_pem)} bytes")

# Save and load certificate
with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
    f.write(cert_pem)
    cert_path = Path(f.name)

cert = load_certificate(cert_path)
fingerprint = get_certificate_fingerprint(cert)
print(f"Certificate fingerprint: {fingerprint[:32]}...")

# Create TLS context
context = create_client_context()
print(f"TLS context created: {context.minimum_version}")
```

If this runs without errors, Tlacacoca is installed correctly.

## Dependencies

Tlacacoca has minimal runtime dependencies:

| Dependency | Purpose |
|------------|---------|
| `cryptography` | Certificate generation and manipulation |
| `structlog` | Structured logging |
| `tomli` | TOML parsing (Python < 3.11) |
| `tomli-w` | TOML writing (for TOFU export) |

All dependencies are automatically installed when you install Tlacacoca.

## Development Setup

If you're planning to contribute to Tlacacoca or develop with the source code, follow these additional steps:

### 1. Clone and Install

```bash
# Clone the repository
git clone https://github.com/alanbato/tlacacoca.git
cd tlacacoca

# Install with development dependencies
uv sync
```

### 2. Verify the Test Suite

Run the test suite to ensure everything is working:

```bash
uv run pytest
```

Expected output:
```
================================ test session starts ================================
...
================================ XX passed in X.XXs =================================
```

### 3. Run Code Quality Checks

```bash
# Run linting
uv run ruff check src/ tests/

# Run type checking
uv run ty check src/

# Run tests with coverage
uv run pytest --cov=src/tlacacoca --cov-report=html
```

### 4. Pre-commit Hooks (Optional)

Install pre-commit hooks to automatically run checks before each commit:

```bash
uv run pre-commit install
```

## Troubleshooting

### Import Errors

**Problem**: `ModuleNotFoundError: No module named 'tlacacoca'`

**Solution**: Ensure you've installed tlacacoca in your current Python environment:

```bash
# Check if tlacacoca is installed
pip list | grep tlacacoca

# If not found, install it
uv add tlacacoca  # or: pip install tlacacoca
```

### Cryptography Build Errors

**Problem**: Build errors when installing the `cryptography` dependency

**Solution**: Install build dependencies for your system:

=== "Debian/Ubuntu"

    ```bash
    sudo apt-get install build-essential libssl-dev libffi-dev python3-dev
    ```

=== "Fedora/RHEL"

    ```bash
    sudo dnf install gcc openssl-devel libffi-devel python3-devel
    ```

=== "macOS"

    ```bash
    brew install openssl
    ```

### Permission Errors

**Problem**: Permission denied errors during installation

**Solution**:

- **Don't use sudo with pip** - Use a virtual environment instead
- **For uv** - No sudo needed, installs to user directory
- **If you must install system-wide** - Consider using your OS package manager

## Upgrading Tlacacoca

To upgrade to the latest version:

=== "Using uv"

    ```bash
    uv add tlacacoca --upgrade
    ```

=== "Using pip"

    ```bash
    pip install --upgrade tlacacoca
    ```

=== "From source"

    ```bash
    cd tlacacoca
    git pull origin main
    uv sync
    ```

## Uninstalling

If you need to remove Tlacacoca:

=== "Using pip"

    ```bash
    pip uninstall tlacacoca
    ```

=== "From source"

    Simply delete the cloned repository directory:
    ```bash
    rm -rf tlacacoca
    ```

## Next Steps

Now that you have Tlacacoca installed, you can:

- **[Quickstart Guide](quickstart.md)** - Get started with security and middleware
- **[TOFU Guide](how-to/tofu.md)** - Set up certificate validation
- **[Rate Limiting Guide](how-to/rate-limiting.md)** - Protect against DoS attacks
- **[Security Model](explanation/security-model.md)** - Understand the security design

## See Also

- [PyPI Package](https://pypi.org/project/tlacacoca/) - Official package on PyPI
- [GitHub Repository](https://github.com/alanbato/tlacacoca) - Source code and issues
- [uv Documentation](https://docs.astral.sh/uv/) - Learn more about uv
