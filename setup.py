#!/usr/bin/env python3
"""
GhostScan Setup Script
Installation and configuration for GhostScan framework
"""

import os
import sys
import json
import toml
from pathlib import Path

def setup_ghostscan():
    """Setup GhostScan environment"""
    print("🔐 Setting up GhostScan Vulnerability Scanner...")
    print("=" * 50)

    # Create project structure
    directories = [
        'config',
        'core',
        'scanners',
        'exploits',
        'chains',
        'database',
        'logs',
        'reports'
    ]

    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created directory: {directory}")

    # Copy configuration files if they don't exist
    config_files = ['chains.toml', 'scanners.toml', 'exploits.toml']
    config_dir = Path('config')

    for config_file in config_files:
        config_path = config_dir / config_file
        if not config_path.exists():
            # Create default configuration
            if config_file == 'chains.toml':
                default_config = """# Blockchain Configuration File for GhostScan
# Dynamic chain management system

[tenderly]
name = "Tenderly Virtual Testnet"
type = "virtual"
supported_scanners = ["static", "dynamic", "reentrancy", "overflow", "access_control", "gas_optimization", "supply_manipulation"]
supported_exploits = ["reentrancy", "overflow", "access_control", "supply_manipulation"]
description = "Tenderly virtual testnet for safe vulnerability testing"

[mainnet]
name = "Real Mainnet"
type = "real"
supported_scanners = ["static", "dynamic", "reentrancy", "overflow", "access_control", "gas_optimization", "supply_manipulation", "flash_loan", "dex_analysis"]
supported_exploits = ["reentrancy", "overflow", "access_control", "supply_manipulation", "flash_loan", "dex_manipulation"]
description = "Real blockchain execution for actual vulnerability testing"

[hardhat]
name = "Hardhat Local"
type = "local"
supported_scanners = ["static", "dynamic", "reentrancy", "overflow", "access_control", "gas_optimization", "supply_manipulation", "unit_testing"]
supported_exploits = ["reentrancy", "overflow", "access_control", "supply_manipulation", "unit_testing"]
description = "Local Hardhat development environment"

# Pre-configured chains
[[chains]]
name = "Story Protocol"
environment = "tenderly"
rpc_url = "https://virtual.story.eu.rpc.tenderly.co/b685a445-4451-4750-bfc8-906d4b809144"
explorer_url = "https://mainnet.storyrpc.io"
blockscout_api = "ce358ed1-ba20-41f9-8351-554d9b2aa9cd"
chain_id = 1511
currency = "STORY"
is_default = true

[[chains]]
name = "Ethereum Mainnet"
environment = "mainnet"
rpc_url = "https://eth.public-rpc.com"
explorer_url = "https://etherscan.io"
chain_id = 1
currency = "ETH"
is_default = true

# Default attacker configuration
[attacker]
default_private_key = ""
default_address = ""
gas_limit = 300000
gas_price_gwei = 20
timeout_seconds = 120
"""
            elif config_file == 'scanners.toml':
                default_config = """# Scanner Configuration for GhostScan
# Comprehensive vulnerability scanning methodologies

[static_analysis]
enabled = true
timeout = 30
depth = 5
check_reentrancy = true
check_overflow = true
check_underflow = true
check_access_control = true

[dynamic_analysis]
enabled = true
timeout = 60
runtime_tests = true
coverage_threshold = 80

[reentrancy_scanner]
enabled = true
timeout = 45
max_call_depth = 5

[overflow_scanner]
enabled = true
timeout = 30
uint256_overflow = true
uint256_underflow = true
"""
            elif config_file == 'exploits.toml':
                default_config = """# Exploit Configuration for GhostScan
# Real exploitation framework for verified vulnerabilities

[reentrancy_exploit]
enabled = true
timeout = 120
classic_reentrancy = true
cross_contract_reentrancy = true

[overflow_exploit]
enabled = true
timeout = 90
uint256_overflow = true
uint256_underflow = true

[access_control_exploit]
enabled = true
timeout = 100
privilege_escalation = true
unauthorized_access = true

# Real transaction execution configuration
[execution]
real_transaction_execution = true
gas_limit_multiplier = 1.5
max_gas_price_gwei = 100
confirmations_required = 1

# Security and safety
[safety]
dry_run_first = true
simulation_required = true
manual_confirmation = true
damage_assessment = true
"""

            with open(config_path, 'w') as f:
                f.write(default_config)
            print(f"✅ Created default configuration: {config_file}")

    # Create .env file if it doesn't exist
    env_path = Path('.env')
    if not env_path.exists():
        default_env = """# GhostScan Environment Configuration
# Configure your blockchain connections and security settings

# Tenderly Configuration
TENDERLY_RPC=https://virtual.mainnet.eu.rpc.tenderly.co/17266b31-1ba8-484f-9e46-c5b5016fefaf
TENDERLY_ACCOUNT_SLUG=ghost-attacker-v1
TENDERLY_PROJECT_SLUG=project
API_TENDERLY=Y5Y23t-VwxJB08YWcTm8JvTl7A3QZwmn

# Blockchain RPC URLs
MAINNET_RPC=https://eth.public-rpc.com
BS_RPC=https://bsc-dataseed.binance.org
POLYGON_RPC=https://polygon-rpc.com

# Security Configuration
PRIVATE_KEY=b4c323449c07eae101f238a9b8af42a563c76fbc3f268f973e5b56b51533e706
ADDRESS_ATTACKER=0x609748df45d43c99298F5C0A0E46b57340d06E90

# Scanner Configuration
SCAN_TIMEOUT=60
MAX_GAS_PRICE=100
ENABLE_REAL_EXECUTION=false

# Exploit Configuration
ENABLE_EXPLOITS=false
MAX_LOSS_ETH=1.0
DAMAGE_ASSESSMENT=true
"""

        with open(env_path, 'w') as f:
            f.write(default_env)
        print("✅ Created default .env file")

    # Create README.md
    readme_path = Path('README.md')
    if not readme_path.exists():
        readme_content = """# GhostScan - Comprehensive Blockchain Vulnerability Scanner

🔐 GhostScan is a powerful, modular blockchain vulnerability scanner that provides enterprise-grade security analysis for smart contracts across multiple blockchain networks.

## Features

### 🔍 Multi-Chain Support
- **Tenderly Virtual Testnet**: Safe vulnerability testing in forked environments
- **Mainnet**: Real blockchain execution for actual vulnerability testing
- **Hardhat**: Local development environment testing

### 🛡️ Comprehensive Scanning
- **Static Analysis**: Code-level vulnerability detection
- **Dynamic Analysis**: Runtime behavior testing
- **Reentrancy Detection**: Classic and cross-contract reentrancy
- **Overflow/Underflow**: Integer arithmetic vulnerability detection
- **Access Control**: Permission and privilege analysis
- **Supply Manipulation**: Token integrity verification
- **Gas Optimization**: Efficiency and cost analysis
- **Hidden Function Discovery**: Undocumented functionality detection

### 💣 Exploitation Framework
- **Real Transaction Execution**: Actual blockchain exploits
- **Targeted Exploits**: Based on specific vulnerabilities
- **Damage Assessment**: Real impact calculation
- **Safety Controls**: Emergency stop and simulation features

### 🗃️ Database Management
- **Persistent Storage**: JSON-based database
- **Dynamic Configuration**: Runtime configuration updates
- **Report Generation**: Comprehensive vulnerability reports
- **Multi-Target Management**: Contract and chain organization

## Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Setup
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd ghostscan
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Initialize configuration:
   ```bash
   python main.py --init-config
   ```

4. Configure your environment:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

## Usage

### Command Line Interface
```bash
# Run the interactive CLI
python main.py

# Install dependencies
python main.py --install

# Show version
python main.py --version
```

### Interactive Menus
GhostScan provides a comprehensive menu system with three main environments:

1. **Tenderly Mode**: Virtual testnet for safe testing
2. **Mainnet Mode**: Real blockchain execution
3. **Hardhat Mode**: Local development environment

Each environment provides:
- Chain management
- Contract management
- Vulnerability scanning
- Exploitation testing
- Report viewing

## Configuration

### Environment Setup
Edit `.env` file with your configuration:
```env
TENDERLY_RPC=https://your-tenderly-rpc-url
PRIVATE_KEY=your-private-key
ADDRESS_ATTACKER=your-attacker-address
```

### Chain Configuration
Edit `config/chains.toml` to add custom chains:
```toml
[[chains]]
name = "Custom Chain"
environment = "mainnet"
rpc_url = "https://your-chain-rpc"
chain_id = 999
currency = "CUSTOM"
```

## Security Notice

⚠️ **WARNING**: GhostScan is designed for security research and penetration testing. Only use it on contracts you own or have explicit permission to test. Unauthorized testing may be illegal.

### Best Practices
1. **Always test in Tenderly first** for safety
2. **Use minimal private keys** for testing
3. **Implement proper safety controls** before real execution
4. **Review all transactions** before execution
5. **Start with low-value tests** before high-value targets

## Architecture

```
ghostscan/
├── config/          # Configuration files
├── core/           # Core modules
├── scanners/       # Vulnerability scanners
├── exploits/       # Exploitation modules
├── chains/         # Chain-specific modules
├── database/       # JSON database
└── main.py         # Entry point
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

For issues and questions:
- Create an issue on GitHub
- Check the documentation
- Review the configuration files

---

**GhostScan** - Advanced blockchain security research tool
"""
        with open(readme_path, 'w') as f:
            f.write(readme_content)
        print("✅ Created README.md")

    print("\n🎉 GhostScan setup completed successfully!")
    print("\nNext steps:")
    print("1. Edit .env file with your configuration")
    print("2. Run 'python main.py --install' to install dependencies")
    print("3. Run 'python main.py' to start the interactive CLI")
    print("\n📚 For more information, see README.md")

def install_dependencies():
    """Install required dependencies"""
    print("🔧 Installing dependencies...")
    print("This may take a few minutes...")
    print()

    import subprocess
    import sys

    try:
        # Install requirements
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✅ Dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Setup GhostScan framework')
    parser.add_argument('--install', action='store_true', help='Install dependencies')
    parser.add_argument('--setup', action='store_true', help='Setup GhostScan environment')

    args = parser.parse_args()

    if args.install:
        success = install_dependencies()
        sys.exit(0 if success else 1)
    elif args.setup:
        setup_ghostscan()
    else:
        setup_ghostscan()