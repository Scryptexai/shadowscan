# ShadowScan Quick Start Guide

## Installation

### Prerequisites
- Python 3.8+
- pip package manager
- Ethereum RPC endpoint (Infura, Alchemy, or local node)

### Step 1: Clone and Install
```bash
git clone <repository-url>
cd shadowscan
pip install -r requirements.txt
```

### Step 2: Configure Environment
```bash
cp .env.example .env
# Edit .env with your RPC endpoint
export SHADOWSCAN_RPC_URL="https://virtual.mainnet.eu.rpc.tenderly.co/eeffdb55-4da5-4241-a9eb-bb6ac3ef16e8"
```

## Quick Start Commands

### 1. Basic Contract Scan
```bash
# Quick scan (500 blocks)
python -m shadowscan.cli screen 0x1234567890123456789012345678901234567890

# Deep scan (2000 blocks)
python -m shadowscan.cli screen 0x1234567890123456789012345678901234567890 --depth full
```

### 2. Custom Chain Scan
```bash
# Scan on different chains
python -m shadowscan.cli screen 0x1234567890123456789012345678901234567890 --chain polygon
python -m shadowscan.cli screen 0x1234567890123456789012345678901234567890 --chain arbitrum
```

### 3. Run Examples
```bash
# Run comprehensive examples
python examples/shadowscan_examples.py
```

## Python API Usage

### Basic Scan
```python
import asyncio
from shadowscan.core.pipeline.screening_engine import ScreeningEngine

async def scan_contract():
    engine = ScreeningEngine()
    results = await engine.screen_contract(
        target_address="0x1234567890123456789012345678901234567890",
        chain="ethereum",
        depth="full"
    )
    print(f"Found {len(results['findings'])} vulnerabilities")

asyncio.run(scan_contract())
```

### DEX Analysis
```python
from shadowscan.collectors.evm.dex_discovery import DexDiscovery
from web3 import Web3

web3 = Web3(Web3.HTTPProvider('https://virtual.mainnet.eu.rpc.tenderly.co/eeffdb55-4da5-4241-a9eb-bb6ac3ef16e8'))
dex_discovery = DexDiscovery(web3)

relationships = await dex_discovery.discover_dex_relations(
    "0x6B175474E89094C44Da98b954EedeAC495271d0F",  # DAI
    web3
)
print(f"Found {len(relationships)} DEX pairs")
```

### Custom Detection
```python
from shadowscan.detectors.evm.defi_detectors import ComprehensiveVulnerabilityScanner
from shadowscan.adapters.evm.provider import EVMProvider

provider = EVMProvider()
scanner = ComprehensiveVulnerabilityScanner(provider)

results = await scanner.comprehensive_scan("0x1234567890123456789012345678901234567890")
print(f"Total findings: {results['total_findings']}")
```

## Configuration

### Environment Variables
```bash
SHADOWSCAN_RPC_URL=          # Primary RPC endpoint
SHADOWSCAN_FALLBACK_URLS=    # Backup RPC URLs (comma-separated)
SHADOWSCAN_MAX_WORKERS=8     # Concurrent workers
SHADOWSCAN_TIMEOUT=30000     # Request timeout (ms)
SHADOWSCAN_DATA_DIR=./data   # Data directory
```

### Key Features to Try

1. **20 Vulnerability Detectors**: Automatically scans for reentrancy, flash loans, oracle manipulation, and more
2. **DEX Discovery**: Analyzes token relationships across multiple DEXes
3. **Contract Registry**: Manages screening sessions and discovered contracts
4. **Robust Data Collection**: Handles chunking, retries, and provider fallback
5. **Comprehensive Testing**: Extensive test coverage for all components

## Common Use Cases

### 1. Smart Contract Auditing
```bash
# Audit a new DeFi protocol
python -m shadowscan.cli screen 0xNewProtocolAddress --depth full
```

### 2. Token Security Analysis
```python
# Analyze token's DEX relationships
# See examples/shadowscan_examples.py for implementation
```

### 3. Batch Security Assessment
```python
# Scan multiple contracts
# See examples/shadowscan_examples.py for batch analysis example
```

### 4. Custom Security Rules
```python
# Implement custom detection logic
# See examples/shadowscan_examples.py for custom detector example
```

## Next Steps

1. **Read Documentation**: Check `DOCUMENTATION.md` for detailed API reference
2. **Run Tests**: Execute `pytest tests/` to verify installation
3. **Explore Examples**: Run `python examples/shadowscan_examples.py` to see capabilities
4. **Contribute**: Report issues or contribute to the project

## Support

- **Documentation**: `DOCUMENTATION.md`
- **Examples**: `examples/shadowscan_examples.py`
- **Issues**: GitHub Issues
- **Community**: Discord/Telegram (project-specific)

## Troubleshooting

### RPC Issues
```bash
# Test RPC connection
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  https://virtual.mainnet.eu.rpc.tenderly.co/eeffdb55-4da5-4241-a9eb-bb6ac3ef16e8
```

### Common Errors
- **Connection Timeout**: Increase `SHADOWSCAN_TIMEOUT`
- **Rate Limiting**: Add fallback RPC URLs
- **Memory Issues**: Reduce `SHADOWSCAN_MAX_WORKERS`

Happy scanning! 🌑