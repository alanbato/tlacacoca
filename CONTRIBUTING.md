# Contributing to Tlacacoca

Thank you for your interest in contributing to Tlacacoca! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Testing Guidelines](#testing-guidelines)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)
- [Getting Help](#getting-help)

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- **Python 3.10 or higher**
- **uv** - Fast Python package installer and resolver ([installation instructions](https://github.com/astral-sh/uv))
- **Git** for version control

### Finding Something to Work On

- Check the [issue tracker](https://github.com/alanbato/tlacacoca/issues) for open issues
- Look for issues labeled `good first issue` for newcomer-friendly tasks
- Issues labeled `help wanted` are especially open to external contributions
- Feel free to propose new features or improvements by opening an issue first

## Development Setup

1. **Fork and clone the repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/tlacacoca.git
   cd tlacacoca
   ```

2. **Install dependencies**:
   ```bash
   # Install all dependencies including dev dependencies
   uv sync
   ```

3. **Install pre-commit hooks**:
   ```bash
   # Set up pre-commit hooks for automatic code quality checks
   uv run pre-commit install
   ```

4. **Verify your setup**:
   ```bash
   # Run the test suite
   uv run pytest

   # Run linting
   uv run ruff check src/ tests/

   # Run type checking
   uv run ty check src/
   ```

## Development Workflow

### Creating a Branch

Create a descriptive branch name following these conventions:

- `feat/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation changes
- `test/description` - Test additions or changes
- `refactor/description` - Code refactoring

Example:
```bash
git checkout -b feat/add-url-parser
```

### Making Changes

1. **Write your code** following our [code standards](#code-standards)
2. **Add tests** for any new functionality
3. **Update documentation** if you're changing behavior or adding features
4. **Run the test suite** to ensure everything passes
5. **Commit your changes** using [conventional commit messages](#commit-messages)

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage report
uv run pytest --cov=src/tlacacoca --cov-report=html

# Run specific test categories
uv run pytest -m unit          # Only unit tests
uv run pytest -m integration   # Only integration tests
uv run pytest -m "not slow"    # Exclude slow tests

# Run a specific test file
uv run pytest tests/test_security/test_tofu.py

# Run a specific test function
uv run pytest tests/test_middleware/test_rate_limit.py::test_token_bucket

# Run tests in parallel (faster)
uv run pytest -n auto
```

### Code Quality Checks

Our pre-commit hooks will run automatically, but you can also run them manually:

```bash
# Run all pre-commit hooks
uv run pre-commit run --all-files

# Run linting
uv run ruff check src/ tests/

# Auto-fix linting issues
uv run ruff check --fix src/ tests/

# Run type checking
uv run ty check src/
```

## Code Standards

### Python Style

- Follow **PEP 8** style guidelines (enforced by Ruff)
- Use **type hints** for all function signatures
- Maximum line length: **90 characters**
- Use **double quotes** for strings
- Import sorting follows isort conventions (enforced by Ruff)

### Type Hints

All functions must have complete type hints:

```python
# Good
def get_fingerprint(cert: bytes, algorithm: str = "sha256") -> str:
    ...

# Bad - missing type hints
def get_fingerprint(cert, algorithm="sha256"):
    ...
```

### Docstrings

All public classes, methods, and functions must have docstrings following **Google style**:

```python
def verify_certificate(
    hostname: str,
    port: int,
    fingerprint: str,
) -> bool:
    """Verify a certificate fingerprint against stored value.

    Args:
        hostname: The server hostname.
        port: The server port.
        fingerprint: SHA-256 fingerprint to verify.

    Returns:
        True if fingerprint matches stored value, False otherwise.

    Raises:
        CertificateChangedError: If fingerprint doesn't match stored value.

    Example:
        >>> db = TOFUDatabase()
        >>> db.verify_certificate("example.com", 1965, fingerprint)
        True
    """
    ...
```

### Protocol-Agnostic Design

Since tlacacoca is a shared library for multiple protocol implementations:

- **Never hardcode protocol-specific values** (status codes, port numbers, URL schemes)
- **Use abstract return types** that protocols can map to their specific responses
- **Make configuration flexible** with sensible defaults
- **Document how protocol implementations should use components**

Example:
```python
# Good - protocol-agnostic
class MiddlewareResult:
    allowed: bool
    denial_reason: str | None  # "rate_limit", "access_denied", etc.
    retry_after: int | None

# Bad - protocol-specific
def process_request(...) -> str:
    return "44 SLOW DOWN\r\n"  # Gemini-specific response
```

### Security Considerations

When contributing, be mindful of security:

- **Never commit secrets, API keys, or credentials**
- **Validate all user inputs** to prevent injection attacks
- **Use Path.resolve()** and validate paths to prevent directory traversal
- **Enforce size limits** on inputs
- **Follow the principle of least privilege**

See [SECURITY.md](SECURITY.md) for detailed security guidelines.

## Testing Guidelines

### Test Requirements

- All new features **must** include tests
- Bug fixes **should** include regression tests
- Aim for **≥80% code coverage**
- Tests should be **fast and isolated** (use mocks for external dependencies)

### Test Organization

- `tests/test_security/` - Security module tests (TLS, TOFU, certificates)
- `tests/test_middleware/` - Middleware tests (rate limiting, access control)
- `tests/test_logging/` - Logging tests

### Writing Tests

Use pytest conventions and markers:

```python
import pytest
from tlacacoca import TokenBucket, RateLimitConfig

@pytest.mark.unit
def test_token_bucket_allows_within_capacity():
    """Test that requests within capacity are allowed."""
    bucket = TokenBucket(capacity=10, refill_rate=1.0)
    for _ in range(10):
        assert bucket.consume() is True

@pytest.mark.unit
def test_token_bucket_denies_over_capacity():
    """Test that requests over capacity are denied."""
    bucket = TokenBucket(capacity=1, refill_rate=0.0)
    bucket.consume()  # Use the one token
    assert bucket.consume() is False

@pytest.mark.asyncio
async def test_tofu_database_stores_certificate():
    """Test that TOFU database stores certificates."""
    async with TOFUDatabase(":memory:") as db:
        await db.trust("example.com", 1965, "fingerprint123")
        assert await db.is_known("example.com", 1965)
```

### Test Markers

- `@pytest.mark.unit` - Fast, isolated unit tests
- `@pytest.mark.integration` - Tests with real I/O operations
- `@pytest.mark.slow` - Long-running tests (>1 second)

## Submitting Changes

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test additions or changes
- `refactor:` - Code refactoring without behavior changes
- `perf:` - Performance improvements
- `chore:` - Build process or auxiliary tool changes

**Examples**:
```
feat(middleware): add configurable cleanup interval for rate limiter

Allow users to configure how often idle rate limiters are cleaned up,
reducing memory usage for high-traffic servers.

Closes #123
```

```
fix(tofu): handle database locked errors gracefully

Add retry logic when SQLite database is locked by another process.

Fixes #456
```

### Pull Request Process

1. **Ensure all tests pass** and code quality checks succeed
2. **Update documentation** if you're changing behavior
3. **Create a pull request** with a clear title and description
4. **Link related issues** using keywords like "Closes #123" or "Fixes #456"
5. **Respond to review feedback** in a timely manner

### Pull Request Template

When creating a PR, include:

```markdown
## Description
Brief description of what this PR does

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update

## Testing
Describe the tests you added or how you tested your changes

## Checklist
- [ ] My code follows the project's code style
- [ ] I have added tests that prove my fix/feature works
- [ ] All tests pass locally
- [ ] I have updated the documentation accordingly
- [ ] My changes generate no new warnings
```

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

- **Clear description** of the issue
- **Steps to reproduce** the problem
- **Expected behavior** vs. actual behavior
- **Environment details** (Python version, OS, tlacacoca version)
- **Relevant logs or error messages**
- **Minimal code example** if applicable

### Feature Requests

When requesting features, please include:

- **Use case**: Why is this feature needed?
- **Proposed solution**: How should it work?
- **Alternatives considered**: What other approaches did you consider?
- **Additional context**: Any other relevant information

## Getting Help

- **Documentation**: Check the [README](README.md) and [SECURITY.md](SECURITY.md)
- **Issues**: Search existing issues before creating a new one
- **Discussions**: Use GitHub Discussions for questions and general discussion
- **Email**: For sensitive matters, contact alanvelasco.a@gmail.com

## Resources

### Python asyncio Resources

- [asyncio Documentation](https://docs.python.org/3/library/asyncio.html)
- [asyncio Protocol/Transport Pattern](https://docs.python.org/3/library/asyncio-protocol.html)

### TLS/Security Resources

- [Python ssl Module](https://docs.python.org/3/library/ssl.html)
- [TLS Best Practices](https://wiki.mozilla.org/Security/Server_Side_TLS)

## Recognition

Contributors are recognized in several ways:

- Listed in the project's contributors page
- Mentioned in release notes for significant contributions
- Added to a CONTRIBUTORS file (if created)

Thank you for contributing to Tlacacoca!
