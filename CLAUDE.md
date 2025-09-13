# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ShadowScan is a comprehensive security scanning platform designed for blockchain, web applications, and network infrastructure testing. It's built with a modular architecture supporting multi-vector analysis, AI-powered heuristics, and professional vulnerability assessment.

## Common Development Commands

### Environment Setup
```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
make install              # Basic installation
make dev                  # Full development setup with dev dependencies
```

### Testing and Quality Assurance
```bash
# Run tests
make test                 # Run all tests with coverage
pytest tests/             # Alternative test command

# Code quality
make lint                 # Run all linters (black, isort, flake8, mypy)
make format               # Format code with black and isort
make security             # Run security checks (bandit, safety)
```

### Building and Packaging
```bash
# Build package
python -m build
twine check dist/*

# Clean build artifacts
make clean
```

### Multi-environment Testing
```bash
# Test across multiple Python versions
tox                       # Run all configured environments
tox -e py310              # Test specific Python version
```

## Architecture Overview

### Core Components

**Engine System** (`shadowscan/core/`):
- `engine.py` - Main orchestrator that coordinates all modules
- `professional_engine.py` - Advanced engine with AI screening capabilities
- `pipeline/` - Screening and execution pipeline components
- `blockchain_scanner.py` - Specialized blockchain scanning engine

**Modular Design** (`shadowscan/modules/`):
- `blockchain/` - Smart contract vulnerability detectors (reentrancy, ERC20, miner reward manipulation)
- `web/` - Web application security modules (SQL injection, XSS, CSRF)
- `base/` - Base module classes and interfaces
- Each module implements `BaseModule` interface for consistency

**Detection System** (`shadowscan/detectors/`):
- `evm/` - EVM-specific vulnerability detectors (oracle manipulation, generic patterns)
- Pattern recognition and vulnerability classification

**Verification System** (`shadowscan/verifiers/`):
- EVM exploit verification and validation
- Automated testing of discovered vulnerabilities

**Data Collection** (`shadowscan/collectors/`):
- `evm/` - Blockchain data collection (ABI fetching, contract intelligence, DEX discovery)
- Transaction and state fetching utilities

**Command Interface** (`shadowscan/commands/`):
- CLI commands for different scanning operations
- `screen.py` - AI-powered screening engine
- `ai.py` - AI integration and analysis
- `attack.py` - Attack simulation and testing

### Configuration Management

**Configuration** (`shadowscan/config/`):
- `config_loader.py` - Centralized configuration loading
- `schemas.py` - Configuration validation with strict rules
- `loader.py` - Additional configuration utilities

**Environment Variables** (from `.env`):
- `TARGET_TYPE` - Target type: 'blockchain', 'web', or 'network'
- `TARGET_CONTRACT` - Smart contract address (for blockchain targets)
- `TARGET_URL` - Target URL (for web targets)
- `TENDERLY_RPC` - Tenderly simulation RPC endpoint
- `ETHERSCAN_API_KEY` - Etherscan API key for blockchain analysis
- `ATTACKER_ADDRESS` - Attacker address for simulation

### Key Dependencies

**Core Libraries**:
- `web3>=6.0.0` - Ethereum blockchain interaction
- `click>=8.1.0` - CLI framework
- `rich>=13.0.0` - Rich terminal output
- `pydantic>=2.0.0` - Data validation
- `aiohttp>=3.8.0` - Async HTTP client

**Security Tools**:
- `bandit>=1.7.5` - Security linter
- `safety>=2.3.0` - Dependency vulnerability scanner
- `slither-analyzer>=0.9.0` - Smart contract analyzer
- `semgrep>=1.45.0` - Static analysis

**Blockchain-specific**:
- `eth-abi>=4.0.0` - Ethereum ABI utilities
- `eth-utils>=2.3.0` - Ethereum utility functions
- `py-solc-x>=1.12.0` - Solidity compiler

## Development Guidelines

### Code Style
- Line length: 88 characters (Black configuration)
- Use `make format` to auto-format code
- Type hints are enforced with mypy
- Follow existing module patterns when creating new detectors

### Testing Strategy
- Tests are organized in `tests/` directory (currently empty but expected)
- Use pytest with coverage reporting
- Integration tests should validate end-to-end scanning workflows
- Mock external API calls in tests

### Security Considerations
- Never commit API keys or credentials
- Use environment variables for sensitive configuration
- All security scans are defensive/ethical hacking only
- Validate all external inputs and configurations
- Follow responsible disclosure practices

### Module Development
1. Create new modules in appropriate category under `shadowscan/modules/`
2. Extend `BaseModule` class for consistency
3. Add configuration validation in `shadowscan/config/schemas.py`
4. Include comprehensive docstrings and type hints
5. Write tests for all new functionality

## Build System

The project uses modern Python packaging with:
- `pyproject.toml` - Build configuration and dependencies
- `Makefile` - Common development tasks
- `tox.ini` - Multi-environment testing
- `.pre-commit-config.yaml` - Pre-commit hooks for code quality

## Common Issues and Solutions

- **Import errors**: Ensure virtual environment is activated and dependencies installed
- **Configuration validation**: Check `.env` file matches schema requirements
- **Blockchain RPC issues**: Verify Tenderly RPC endpoint and API keys
- **Permission errors**: Ensure proper file permissions for configuration files