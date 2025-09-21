# GhostScan - Comprehensive Blockchain Vulnerability Scanner

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
