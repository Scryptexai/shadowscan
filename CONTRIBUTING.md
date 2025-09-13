# Contributing to ShadowScan

Thank you for your interest in contributing to ShadowScan! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment (recommended)

### Development Setup

1. **Fork the repository**
   ```bash
   git clone https://github.com/yourusername/shadowscan.git
   cd shadowscan
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install development dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

5. **Run tests to ensure everything works**
   ```bash
   pytest
   ```

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/yourusername/shadowscan/issues)
2. If not, create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (Python version, OS, etc.)
   - Error messages or logs

### Suggesting Features

1. Check existing [Issues](https://github.com/yourusername/shadowscan/issues) and [Discussions](https://github.com/yourusername/shadowscan/discussions)
2. Create a new issue with:
   - Clear description of the feature
   - Use case and benefits
   - Possible implementation approach

### Contributing Code

1. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b bugfix/your-bug-fix
   ```

2. **Make your changes**
   - Write clean, readable code
   - Follow existing code style
   - Add tests for new functionality
   - Update documentation if needed

3. **Test your changes**
   ```bash
   # Run all tests
   pytest
   
   # Run with coverage
   pytest --cov=shadowscan
   
   # Run linting
   flake8 shadowscan
   black --check shadowscan
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add new scanning module for XYZ"
   ```

## Pull Request Process

1. **Ensure your PR**:
   - Has a clear, descriptive title
   - References related issues (e.g., "Fixes #123")
   - Includes tests for new functionality
   - Updates documentation if needed
   - Passes all CI checks

2. **PR Description should include**:
   - What changes were made and why
   - How to test the changes
   - Any breaking changes
   - Screenshots (for UI changes)

3. **Review Process**:
   - Maintainers will review your PR
   - Address any feedback or requested changes
   - Once approved, your PR will be merged

## Coding Standards

### Style Guidelines

- **Python**: Follow PEP 8
- **Line length**: Maximum 88 characters (Black formatter)
- **Import order**: Use isort
- **Type hints**: Use type hints for function parameters and return values

### Code Quality Tools

We use the following tools to maintain code quality:

```bash
# Auto-formatting
black shadowscan/
isort shadowscan/

# Linting
flake8 shadowscan/
mypy shadowscan/

# Security scanning
bandit -r shadowscan/
```

### Commit Messages

Use conventional commit format:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `style:` - Code style changes
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

Example: `feat: add Ethereum smart contract vulnerability scanner`

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=shadowscan --cov-report=html

# Run specific test file
pytest tests/test_scanner.py

# Run tests matching pattern
pytest -k "test_web"
```

### Writing Tests

- Write tests for all new functionality
- Use descriptive test names
- Include both positive and negative test cases
- Mock external dependencies
- Aim for >90% code coverage

### Test Structure

```python
def test_should_return_expected_result_when_valid_input():
    # Arrange
    scanner = WebScanner()
    url = "https://example.com"
    
    # Act
    result = scanner.scan(url)
    
    # Assert
    assert result.status == "completed"
    assert len(result.vulnerabilities) > 0
```

## Documentation

### Types of Documentation

1. **Code Documentation**
   - Docstrings for all public functions and classes
   - Inline comments for complex logic
   - Type hints

2. **API Documentation**
   - Auto-generated from docstrings
   - Examples for each endpoint/function

3. **User Documentation**
   - README.md
   - Configuration guides
   - Tutorials and examples

### Documentation Style

```python
def scan_contract(address: str, network: str = "mainnet") -> ScanResult:
    """
    Scan a smart contract for vulnerabilities.
    
    Args:
        address: The contract address to scan
        network: The blockchain network (default: "mainnet")
        
    Returns:
        ScanResult containing vulnerability findings
        
    Raises:
        ValueError: If address is invalid
        NetworkError: If network is unreachable
        
    Example:
        >>> scanner = ContractScanner()
        >>> result = scanner.scan_contract("0x123...")
        >>> print(result.summary())
    """
```

## Getting Help

- **Documentation**: Check the [docs](docs/) directory
- **Issues**: Browse existing [issues](https://github.com/yourusername/shadowscan/issues)
- **Discussions**: Join [GitHub Discussions](https://github.com/yourusername/shadowscan/discussions)
- **Email**: Contact us at team@shadowscan.dev

## Recognition

All contributors will be:
- Listed in the [AUTHORS.md](AUTHORS.md) file
- Mentioned in release notes for their contributions
- Credited in relevant documentation

Thank you for contributing to ShadowScan! 🔒✨
