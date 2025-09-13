# ShadowScan Documentation

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Vulnerability Detectors](#vulnerability-detectors)
4. [Usage Guide](#usage-guide)
5. [API Reference](#api-reference)
6. [Configuration](#configuration)
7. [Testing](#testing)
8. [Examples](#examples)

## Overview

ShadowScan is an advanced smart contract security scanning platform that provides comprehensive vulnerability detection for EVM-based smart contracts. The platform combines robust data collection, sophisticated pattern recognition, and extensive vulnerability coverage to deliver professional-grade security analysis.

### Key Capabilities

- **20 Comprehensive Vulnerability Detectors**: Covering reentrancy, flash loans, oracle manipulation, and more
- **Robust Data Collection**: Enhanced transaction fetching with chunking, concurrency, and provider fallback
- **DEX Relationship Discovery**: Factory log scanning and pair analysis for DeFi security assessment
- **Thread-Safe Storage**: Persistent contract registry with session management
- **Two-Stage Screening**: Discovery phase followed by detailed analysis

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ShadowScan CLI                           │
├─────────────────────────────────────────────────────────────┤
│  Screening Engine  │  Contract Registry  │  Data Collectors │
├─────────────────────────────────────────────────────────────┤
│  Vulnerability Detectors (20 types)                        │
├─────────────────────────────────────────────────────────────┤
│  EVM Provider  │  DEX Discovery  │  Transaction Fetcher   │
├─────────────────────────────────────────────────────────────┤
│                    RPC Providers                            │
└─────────────────────────────────────────────────────────────┘
```

### Core Components

#### Screening Engine
The screening engine orchestrates the entire scanning process, coordinating between data collectors, vulnerability detectors, and the contract registry.

#### Contract Registry
A thread-safe, persistent storage system that manages:
- Screening sessions
- Discovered contracts
- Contract metadata and relationships
- Session statistics and cleanup

#### Vulnerability Detectors
20 specialized detectors covering various attack vectors:
- Core vulnerabilities (reentrancy, flash loans, access control)
- Additional vulnerabilities (unchecked calls, front-running, time manipulation)
- Specialized vulnerabilities (proxy misuse, upgrade mechanisms)
- DeFi-specific vulnerabilities (fee manipulation, slippage protection)

## Vulnerability Detectors

ShadowScan includes 20 comprehensive vulnerability detectors:

### 1. Reentrancy Detector
Detects reentrancy attack patterns including:
- Call before update patterns
- Missing reentrancy guards
- Multiple external calls in single functions

**Severity**: HIGH to CRITICAL

### 2. Flash Loan Detector
Identifies flash loan manipulation vulnerabilities:
- Unvalidated price operations
- Missing TWAP protection
- Insufficient collateral validation

**Severity**: HIGH to CRITICAL

### 3. Access Control Detector
Finds access control issues:
- Missing owner-only controls
- Uninitialized ownership
- Public sensitive functions

**Severity**: MEDIUM to CRITICAL

### 4. Integer Overflow Detector
Detects arithmetic vulnerabilities:
- Unsafe arithmetic operations
- Array length manipulation
- Unchecked increment/decrement

**Severity**: MEDIUM to HIGH

### 5. Unchecked Calls Detector
Identifies unvalidated external calls:
- Unchecked `.call()` operations
- Unchecked `.send()` operations
- Transfer operations in loops

**Severity**: MEDIUM

### 6. Front Running Detector
Detects front-running opportunities:
- Public pending transactions
- Vulnerable price oracles
- MEV extraction opportunities

**Severity**: MEDIUM

### 7. Time Manipulation Detector
Finds timestamp dependence issues:
- Timestamp dependence
- Insufficient time delays
- Time-based race conditions

**Severity**: MEDIUM

### 8. Token Approval Detector
Identifies token approval vulnerabilities:
- Unsafe approval patterns
- Unlimited approvals
- Approval front-running

**Severity**: MEDIUM to HIGH

### 9. DelegateCall Misuse Detector
Detects dangerous delegatecall usage:
- User-controlled delegatecall
- Unvalidated delegatecall
- Storage collision risks

**Severity**: HIGH to CRITICAL

### 10. Selfdestruct Misuse Detector
Finds improper selfdestruct usage:
- Public selfdestruct functions
- Unvalidated selfdestruct calls
- Selfdestruct with remaining funds

**Severity**: HIGH to CRITICAL

### 11. Proxy Misuse Detector
Detects proxy-related vulnerabilities:
- Uninitialized proxy contracts
- Storage layout conflicts
- Transparent proxy bypass

**Severity**: HIGH

### 12. Upgrade Mechanism Detector
Identifies upgrade mechanism issues:
- Unlimited upgrade authority
- Missing upgrade delays
- Unvalidated upgrades

**Severity**: MEDIUM to HIGH

### 13. Multicall Exploit Detector
Finds multicall-related vulnerabilities:
- State manipulation in multicall
- Reentrancy in multicall operations
- Unchecked multicall results

**Severity**: MEDIUM to HIGH

### 14. Signature Replay Detector
Detects signature replay attacks:
- Missing nonce management
- Domain separation issues
- Chain replay vulnerabilities

**Severity**: MEDIUM to HIGH

### 15. Storage Collision Detector
Identifies storage layout conflicts:
- Inheritance storage collision
- Unmanaged storage slots
- Dynamic storage collision

**Severity**: MEDIUM to HIGH

### 16. Gas Limitation Detector
Finds gas exhaustion vulnerabilities:
- Unbounded loops
- Expensive operations in loops
- Storage operations in loops

**Severity**: MEDIUM to HIGH

### 17. Fee Manipulation Detector
Detects fee manipulation vulnerabilities:
- Insufficient fee validation
- Fee front-running
- Dynamic fee manipulation

**Severity**: MEDIUM to HIGH

### 18. Slippage Protection Detector
Identifies missing slippage controls:
- Missing slippage tolerance
- Insufficient price validation
- Slippage front-running

**Severity**: MEDIUM

### 19. Pause Mechanism Detector
Finds pause mechanism issues:
- Missing pause controls
- Improper pause authority
- Incomplete pause coverage

**Severity**: LOW to MEDIUM

### 20. Oracle Manipulation Detector
Detects price oracle vulnerabilities:
- Single point of failure oracles
- Manipulatable DEX-based price feeds
- TWAP vulnerabilities
- Flash loan attack surfaces

**Severity**: HIGH to CRITICAL

## Usage Guide

### Basic Usage

#### Command Line Interface

```bash
# Quick scan (shallow - 500 blocks)
shadowscan screen 0x1234567890123456789012345678901234567890

# Deep scan (full - 2000 blocks)
shadowscan screen 0x1234567890123456789012345678901234567890 --depth full

# Scan with custom chain
shadowscan screen 0x1234567890123456789012345678901234567890 --chain polygon

# Include transaction traces
shadowscan screen 0x1234567890123456789012345678901234567890 --include-traces
```

#### Python API

```python
from shadowscan.core.pipeline.screening_engine import ScreeningEngine
from shadowscan.adapters.evm.provider import EVMProvider

async def scan_contract():
    # Initialize components
    provider = EVMProvider()
    engine = ScreeningEngine()
    
    # Run screening
    results = await engine.screen_contract(
        target_address="0x1234567890123456789012345678901234567890",
        chain="ethereum",
        depth="full"
    )
    
    # Process results
    print(f"Found {len(results['findings'])} vulnerabilities")
    for finding in results['findings']:
        print(f"- {finding['title']} ({finding['severity']})")
        print(f"  {finding['description']}")
```

### Advanced Usage

#### Custom Detector Selection

```python
from shadowscan.detectors.evm.defi_detectors import ComprehensiveVulnerabilityScanner

async def custom_scan():
    provider = EVMProvider()
    scanner = ComprehensiveVulnerabilityScanner(provider)
    
    # Run comprehensive scan with all detectors
    results = await scanner.comprehensive_scan(
        "0x1234567890123456789012345678901234567890"
    )
    
    # Analyze results by detector
    for detector_name, detector_result in results['detector_results'].items():
        if 'findings' in detector_result:
            print(f"{detector_name}: {detector_result['findings_count']} findings")
```

#### DEX Relationship Analysis

```python
from shadowscan.collectors.evm.dex_discovery import DexDiscovery
from web3 import Web3

async def analyze_dex_relationships():
    web3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/YOUR_PROJECT_ID'))
    dex_discovery = DexDiscovery(web3, max_workers=4)
    
    # Discover DEX relationships
    relationships = await dex_discovery.discover_dex_relations(
        "0x6B175474E89094C44Da98b954EedeAC495271d0F",  # DAI
        web3,
        chain="ethereum"
    )
    
    for rel in relationships:
        print(f"DEX: {rel.dex_name}")
        print(f"Pair: {rel.pair}")
        print(f"Liquidity: ${rel.liquidity_usd:,.2f}")
        print(f"Depth Score: {rel.depth_score:.2f}")
```

#### Contract Registry Management

```python
from shadowscan.data.contracts import ContractRegistry

async def manage_registry():
    registry = ContractRegistry()
    
    # Create screening session
    session = registry.create_session(
        target="0x1234567890123456789012345678901234567890",
        chain="ethereum",
        session_id="security-audit-001"
    )
    
    # Add discovered contracts
    registry.add_contract(
        target="0x1234567890123456789012345678901234567890",
        chain="ethereum",
        address="0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        role="token",
        metadata={"symbol": "TEST", "decimals": 18}
    )
    
    # Get session statistics
    stats = registry.get_statistics()
    print(f"Total contracts: {stats['total_contracts']}")
    print(f"Active sessions: {stats['active_sessions']}")
    
    # Load existing session
    loaded_session = registry.load(
        "0x1234567890123456789012345678901234567890",
        "ethereum"
    )
```

## API Reference

### ScreeningEngine

```python
class ScreeningEngine:
    async def screen_contract(
        self,
        target_address: str,
        chain: str = "ethereum",
        depth: str = "shallow",
        include_traces: bool = True
    ) -> Dict[str, Any]
```

**Parameters:**
- `target_address`: Contract address to screen
- `chain`: Blockchain network (default: "ethereum")
- `depth`: Screening depth ("shallow" or "full")
- `include_traces`: Whether to include transaction traces

**Returns:**
Dictionary containing scan results, findings, and metadata.

### ContractRegistry

```python
class ContractRegistry:
    def create_session(
        self,
        target: str,
        chain: str,
        session_id: str
    ) -> TargetSession
    
    def add_contract(
        self,
        target: str,
        chain: str,
        address: str,
        role: str,
        metadata: Dict[str, Any]
    ) -> ContractInfo
    
    def get_contracts_for_target(
        self,
        target: str,
        chain: str
    ) -> List[ContractInfo]
    
    def get_statistics(self) -> Dict[str, Any]
```

### ComprehensiveVulnerabilityScanner

```python
class ComprehensiveVulnerabilityScanner:
    async def comprehensive_scan(
        self,
        target_contract: str
    ) -> Dict[str, Any]
```

**Returns:**
Comprehensive scan results with findings from all 20 detectors.

## Configuration

### Environment Variables

```bash
# Primary RPC endpoint
SHADOWSCAN_RPC_URL=https://mainnet.infura.io/v3/YOUR_PROJECT_ID

# Fallback RPC endpoints (comma-separated)
SHADOWSCAN_FALLBACK_URLS=https://rpc.ankr.com/eth,https://eth.public-rpc.com

# Data directory
SHADOWSCAN_DATA_DIR=./shadowscan/data

# Maximum concurrent workers
SHADOWSCAN_MAX_WORKERS=8

# Request timeout (milliseconds)
SHADOWSCAN_TIMEOUT=30000

# Default screening depth
SHADOWSCAN_DEFAULT_DEPTH=shallow
```

### Configuration File

Create a `config.py` file:

```python
CONFIG = {
    "providers": {
        "primary": "https://mainnet.infura.io/v3/YOUR_PROJECT_ID",
        "fallbacks": [
            "https://rpc.ankr.com/eth",
            "https://eth.public-rpc.com"
        ]
    },
    "screening": {
        "default_depth": "shallow",
        "shallow_blocks": 500,
        "full_blocks": 2000,
        "chunk_size": 100,
        "max_workers": 8
    },
    "detectors": {
        "enabled": [
            "reentrancy",
            "flashloan",
            "access_control",
            "oracle_manipulation"
        ],
        "severity_threshold": "MEDIUM"
    },
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    }
}
```

## Testing

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test category
pytest tests/test_vulnerability_detectors.py
pytest tests/test_contract_registry.py
pytest tests/test_dex_discovery.py

# Run with coverage
pytest --cov=shadowscan tests/

# Run with verbose output
pytest -v tests/
```

### Test Coverage

The test suite provides comprehensive coverage for:

- **ContractRegistry**: Threading, persistence, session management
- **TxFetcher**: Chunking, retries, provider fallback, error handling
- **DEX Discovery**: Factory scanning, pair calculation, liquidity analysis
- **Vulnerability Detectors**: All 20 detectors with various test cases
- **Error Handling**: Edge cases, malformed inputs, provider failures

### Test Structure

```
tests/
├── conftest.py              # Test configuration and fixtures
├── test_contract_registry.py # Contract registry tests
├── test_tx_fetcher.py       # Transaction fetcher tests
├── test_dex_discovery.py    # DEX discovery tests
└── test_vulnerability_detectors.py # Vulnerability detector tests
```

## Examples

### Example 1: Basic Security Audit

```python
import asyncio
from shadowscan.core.pipeline.screening_engine import ScreeningEngine

async def basic_audit():
    """Perform a basic security audit of a contract."""
    engine = ScreeningEngine()
    
    # Target contract (example: Uniswap V2 Router)
    target = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
    
    print(f"🔍 Starting security audit for {target}")
    
    results = await engine.screen_contract(
        target_address=target,
        chain="ethereum",
        depth="full"
    )
    
    # Print summary
    print(f"\n📊 Audit Summary:")
    print(f"   Total Findings: {len(results['findings'])}")
    print(f"   Severity Distribution: {results['severity_distribution']}")
    
    # Print detailed findings
    print(f"\n🚨 Security Findings:")
    for finding in results['findings']:
        print(f"   • {finding['title']}")
        print(f"     Severity: {finding['severity']}")
        print(f"     Description: {finding['description']}")
        print(f"     Confidence: {finding['confidence']:.1%}")
        print(f"     Impact: {finding['impact_score']:.1%}")
        print()

if __name__ == "__main__":
    asyncio.run(basic_audit())
```

### Example 2: DeFi Protocol Analysis

```python
import asyncio
from shadowscan.collectors.evm.dex_discovery import DexDiscovery
from shadowscan.detectors.evm.defi_detectors import ComprehensiveVulnerabilityScanner
from web3 import Web3

async def defi_analysis():
    """Analyze a DeFi protocol for security risks."""
    web3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/YOUR_PROJECT_ID'))
    
    # Target DeFi protocol (example: Aave)
    target = "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9"
    
    print(f"🏦 Analyzing DeFi protocol: {target}")
    
    # Discover DEX relationships
    dex_discovery = DexDiscovery(web3)
    dex_relationships = await dex_discovery.discover_dex_relations(target, web3)
    
    print(f"\n💱 DEX Relationships:")
    for rel in dex_relationships[:5]:  # Show top 5
        print(f"   • {rel.dex_name}: {rel.pair} (${rel.liquidity_usd:,.0f})")
    
    # Comprehensive vulnerability scan
    scanner = ComprehensiveVulnerabilityScanner(web3)
    scan_results = await scanner.comprehensive_scan(target)
    
    print(f"\n🔍 Vulnerability Scan Results:")
    print(f"   Total Detectors: {scan_results['scan_metadata']['detectors_used']}")
    print(f"   Successful Scans: {scan_results['scan_metadata']['successful_detectors']}")
    print(f"   Total Findings: {scan_results['total_findings']}")
    
    # Group findings by severity
    by_severity = scan_results['severity_distribution']
    print(f"\n📈 Findings by Severity:")
    for severity, count in by_severity.items():
        print(f"   {severity}: {count}")

if __name__ == "__main__":
    asyncio.run(defi_analysis())
```

### Example 3: Custom Security Rules

```python
import asyncio
from shadowscan.detectors.evm.vulnerability_detectors import BaseVulnerabilityDetector, VulnerabilityType
from shadowscan.adapters.evm.provider import EVMProvider

class CustomSecurityDetector(BaseVulnerabilityDetector):
    """Custom security detector for specific patterns."""
    
    async def screen(self, target_contract: str) -> list:
        """Implement custom detection logic."""
        findings = []
        
        try:
            contract_info = await self.provider.get_contract_info(target_contract)
            
            if not contract_info or not contract_info.source_code:
                return findings
            
            # Custom detection logic here
            source_code = contract_info.source_code.lower()
            
            # Example: Detect hardcoded addresses
            hardcoded_addresses = self._detect_hardcoded_addresses(source_code)
            
            for address in hardcoded_addresses:
                finding = type('Finding', (), {
                    'vulnerability_type': 'HARDCODED_ADDRESS',
                    'severity': 'MEDIUM',
                    'title': 'Hardcoded Address Detected',
                    'description': f'Contract contains hardcoded address: {address}',
                    'affected_functions': ['constructor'],
                    'confidence': 0.9,
                    'exploitability_score': 0.3,
                    'impact_score': 0.4,
                    'evidence': {'hardcoded_address': address},
                    'remediation': 'Use configurable addresses instead of hardcoded values',
                    'references': []
                })()
                findings.append(finding)
                
        except Exception as e:
            print(f"Error in custom detector: {e}")
        
        return findings
    
    def _detect_hardcoded_addresses(self, source_code: str) -> list:
        """Detect hardcoded Ethereum addresses."""
        import re
        
        # Pattern for Ethereum addresses
        address_pattern = r'0x[a-fA-F0-9]{40}'
        addresses = re.findall(address_pattern, source_code)
        
        # Filter out common non-sensitive addresses
        sensitive_addresses = []
        for addr in addresses:
            if not any(common in addr.lower() for common in [
                '0000000000000000000000000000000000000000',  # Zero address
                'dead000000000000000000000000000000000000',   # Dead address
                '1111111111111111111111111111111111111111',  # Common test address
            ]):
                sensitive_addresses.append(addr)
        
        return sensitive_addresses

async def custom_security_scan():
    """Run custom security scan."""
    provider = EVMProvider()
    detector = CustomSecurityDetector(provider)
    
    target = "0x1234567890123456789012345678901234567890"
    findings = await detector.screen(target)
    
    print(f"🔍 Custom Security Scan Results:")
    for finding in findings:
        print(f"   • {finding.title}")
        print(f"     {finding.description}")

if __name__ == "__main__":
    asyncio.run(custom_security_scan())
```

### Example 4: Batch Contract Analysis

```python
import asyncio
from shadowscan.core.pipeline.screening_engine import ScreeningEngine

async def batch_analysis():
    """Analyze multiple contracts in batch."""
    engine = ScreeningEngine()
    
    # List of contracts to analyze
    contracts = [
        "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",  # Uniswap V2 Router
        "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9",  # Aave
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  # WETH
        "0x6B175474E89094C44Da98b954EedeAC495271d0F",  # DAI
    ]
    
    print(f"📊 Starting batch analysis of {len(contracts)} contracts")
    
    results = {}
    for contract in contracts:
        print(f"\n🔍 Analyzing {contract}")
        try:
            result = await engine.screen_contract(
                target_address=contract,
                chain="ethereum",
                depth="shallow"  # Use shallow for faster batch processing
            )
            results[contract] = result
            print(f"   ✓ Found {len(result['findings'])} vulnerabilities")
        except Exception as e:
            print(f"   ✗ Error: {e}")
            results[contract] = {'error': str(e)}
    
    # Generate summary report
    print(f"\n📋 Batch Analysis Summary:")
    total_findings = sum(len(r.get('findings', [])) for r in results.values() if 'findings' in r)
    print(f"   Total Contracts: {len(contracts)}")
    print(f"   Total Findings: {total_findings}")
    print(f"   Average Findings per Contract: {total_findings / len(contracts):.1f}")
    
    # Most vulnerable contracts
    contract_scores = []
    for contract, result in results.items():
        if 'findings' in result:
            high_severity = len([f for f in result['findings'] if f.get('severity') in ['HIGH', 'CRITICAL']])
            score = high_severity * 3 + len(result['findings']) - high_severity
            contract_scores.append((contract, score))
    
    contract_scores.sort(key=lambda x: x[1], reverse=True)
    
    print(f"\n🚨 Most Vulnerable Contracts:")
    for contract, score in contract_scores[:3]:
        print(f"   {contract}: Risk Score {score}")

if __name__ == "__main__":
    asyncio.run(batch_analysis())
```

These examples demonstrate the flexibility and power of ShadowScan for various security analysis scenarios, from simple contract scans to complex DeFi protocol analysis and custom security rule implementation.