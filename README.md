# 🔍 ShadowScan - Advanced Blockchain Security Platform

![Version](https://img.shields.io/badge/version-3.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)

**ShadowScan** adalah platform keamanan blockchain tingkat lanjut yang dirancang untuk analisis vulnerability smart contract, eksekusi attack validation, dan comprehensive security screening dengan kemampuan enhanced detection.

## 📋 Table of Contents

- [🎯 Overview](#-overview)
- [🏗️ System Architecture](#-system-architecture)
- [🚀 Quick Start](#-quick-start)
- [📁 Directory Structure](#-directory-structure)
- [⚙️ Configuration](#️-configuration)
- [🔧 Installation](#-installation)
- [💻 Usage & Commands](#-usage--commands)
- [🔍 Core Modules](#-core-modules)
- [🛡️ Enhanced Screening](#️-enhanced-screening)
- [⚔️ Attack Framework](#️-attack-framework)
- [📊 Reporting](#-reporting)
- [🧪 Testing](#-testing)
- [🔄 Development Workflow](#-development-workflow)
- [📈 Roadmap](#-roadmap)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

## 🎯 Overview

ShadowScan adalah comprehensive security platform yang terdiri dari tiga modul utama:

### 🔍 Module 1: Screening & Ecosystem Tracking
- **Smart Contract Analysis**: Analisis mendalam terhadap kontrak target
- **Ecosystem Discovery**: Tracking interaksi dengan DEX, DApps, dan protokol terkait
- **Vulnerability Detection**: Identifikasi 22+ jenis vulnerability dengan multiple detection methods
- **Multi-Chain Support**: Ethereum, Polygon, BSC, Arbitrum

### 🔬 Module 2: Verification & Data Processing  
- **Finding Validation**: Verifikasi temuan vulnerability dengan analisis mendalam
- **Data Processing**: Pengolahan hasil screening untuk persiapan attack
- **Risk Assessment**: Evaluasi dampak ekonomis dan feasibility exploit
- **Evidence Collection**: Pengumpulan bukti blockchain untuk validasi

### ⚔️ Module 3: Attack Execution & Validation
- **Attack Simulation**: Simulasi attack di fork environment untuk validasi
- **Mainnet Proof**: Pembuktian attack di mainnet environment
- **Financial Impact**: Analisis dampak finansial dan ROI calculation
- **Attack Reporting**: Dokumentasi lengkap dengan bukti blockchain

## 🏗️ System Architecture

```
📦 ShadowScan v3.0.0
├── 🏗️ Core Architecture
│   ├── 📊 Screening Engine (Module 1)
│   ├── 🔍 Verification System (Module 2)
│   └── ⚔️ Attack Framework (Module 3)
├── 🛡️ Enhanced Screening Layer
│   ├── 🔬 Deep Scan Engine
│   ├── 🎯 Enhanced Detector
│   └── 🌐 Ecosystem Analyzer
├── 📈 Reporting & Analytics
│   ├── 📋 Report Generator
│   ├── 📊 Dashboard
│   └── 📈 Metrics Collector
└── 🔧 Infrastructure
    ├── ⚙️ Configuration Manager
    ├── 📝 Logger System
    └── 🔄 Session Manager
```

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Node.js 16+
- Docker (optional)
- API Keys (Etherscan, Tenderly, Infura)

### 1. Clone & Install
```bash
git clone https://github.com/yourusername/shadowscan.git
cd shadowscan
pip install -r requirements.txt
```

### 2. Configuration
```bash
cp .env.example .env
# Edit .env with your API keys and configurations
```

### 3. Basic Usage
```bash
# System status check
shadowscan status

# Quick vulnerability scan
shadowscan screen -t 0xYourContractAddress

# Enhanced deep scan
shadowscan enhanced scan -t 0xYourContractAddress -d deep

# Attack validation
shadowscan attack execute -t 0xTarget -m reentrancy --environment fork
```

## 📁 Directory Structure

```
shadowscan/
├── 📄 shadowscan.py                 # Main entry point
├── 📄 shadowscan-standalone.py      # Standalone runner
├── 📄 setup.py                      # Package setup
├── 📄 requirements.txt              # Dependencies
├── 📄 .env                          # Environment variables
│
├── 📁 shadowscan/                   # Core package
│   ├── 📁 cli/                      # CLI interface
│   │   ├── main.py                  # Main CLI entry
│   │   └── commands/                # Command modules
│   │
│   ├── 📁 core/                     # Core engine
│   │   ├── 📁 attack/               # Attack framework
│   │   ├── 📁 pipeline/             # Screening pipeline
│   │   └── engine.py               # Main engine
│   │
│   ├── 📁 commands/                # CLI commands
│   │   ├── attack_commands.py      # Attack operations
│   │   ├── screen.py              # Screening commands
│   │   └── verify.py              # Verification commands
│   │
│   ├── 📁 collectors/              # Data collectors
│   │   └── 📁 evm/                 # EVM collectors
│   │
│   ├── 📁 detectors/               # Vulnerability detectors
│   │   └── 📁 evm/                 # EVM detectors
│   │
│   ├── 📁 config/                  # Configuration
│   │   ├── networks.json          # Network configs
│   │   ├── attack_modes.json      # Attack modes
│   │   └── schemas.py             # Config schemas
│   │
│   ├── 📁 enhanced_screening/     # Enhanced screening
│   │   ├── 📁 detectors/          # Enhanced detectors
│   │   ├── 📁 deep_scans/        # Deep scan engines
│   │   ├── 📁 commands/          # Enhanced commands
│   │   └── 📁 config/            # Enhanced config
│   │
│   ├── 📁 contracts/              # Contract templates
│   │   ├── 📁 attacks/            # Attack contracts
│   │   └── 📁 vulnerable/         # Vulnerable contracts
│   │
│   ├── 📁 reports/                 # Report system
│   ├── 📁 trackers/               # Graph trackers
│   ├── 📁 utils/                  # Utility functions
│   └── 📁 integrations/           # External integrations
│
├── 📁 enhanced_screening/         # Standalone enhanced screening
├── 📁 examples/                   # Usage examples
├── 📁 tests/                      # Test suite
├── 📁 reports/                    # Generated reports
├── 📁 logs/                       # Application logs
└── 📁 docs/                       # Documentation
```

## ⚙️ Configuration

### Environment Variables
```bash
# 🔍 Target Configuration
TARGET_TYPE=blockchain              # blockchain | web | network
TARGET_CONTRACT=0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3

# 🌐 Blockchain Configuration
CHAIN_ID=1                         # Ethereum Mainnet
TENDERLY_RPC=https://virtual.mainnet.eu.rpc.tenderly.co/...
ETHERSCAN_API_KEY=your_etherscan_key
INFURA_API_KEY=your_infura_key

# ⚔️ Attacker Configuration
PRIVATE_KEY=0xyour_private_key
ATTACKER_ADDRESS=0xyour_address

# ⚙️ Engine Configuration
MAX_THREADS=10
RATE_LIMIT_DELAY=1.5
TIMEOUT=30
STEALTH_MODE=true

# 📊 Reporting Configuration
REPORT_FORMAT=pdf                  # pdf | html | json
REPORT_DIR=reports
```

### Network Configuration
```json
// shadowscan/config/networks.json
{
  "mainnet": {
    "ethereum": {
      "name": "Ethereum Mainnet",
      "rpc_url": "https://virtual.mainnet.eu.rpc.tenderly.co/...",
      "chain_id": 1,
      "explorer": "https://etherscan.io"
    },
    "polygon": {
      "name": "Polygon Mainnet", 
      "rpc_url": "https://virtual.mainnet.eu.rpc.tenderly.co/...",
      "chain_id": 137,
      "explorer": "https://polygonscan.com"
    }
  },
  "fork": {
    "ethereum": {
      "name": "Ethereum Fork",
      "rpc_url": "https://virtual.mainnet.eu.rpc.tenderly.co/...",
      "chain_id": 1,
      "fork_mode": true
    }
  }
}
```

## 🔧 Installation

### Standard Installation
```bash
# Clone repository
git clone https://github.com/yourusername/shadowscan.git
cd shadowscan

# Install dependencies
pip install -r requirements.txt

# Install package
pip install -e .

# Configure environment
cp .env.example .env
# Edit .env with your configurations
```

### Standalone Installation (No venv)
```bash
# Run standalone installer
chmod +x install-standalone.sh
./install-standalone.sh

# Or manually
pip3 install --user -r requirements.txt
python3 shadowscan-standalone.py setup
```

### Development Installation
```bash
# Development dependencies
pip install -r requirements-dev.txt

# Install in development mode
pip install -e .

# Install pre-commit hooks
pre-commit install
```

## 💻 Usage & Commands

### Main CLI Commands

```bash
# System status and health check
shadowscan status

# Show help
shadowscan --help
shadowscan [command] --help

# Configuration management
shadowscan config show
shadowscan config validate
```

### 🔍 Screening Commands (Module 1)

```bash
# Basic vulnerability screening
shadowscan screen -t 0xContractAddress -c ethereum

# Full ecosystem screening
shadowscan screen -t 0xContractAddress -d full --ecosystem

# Target specific vulnerabilities
shadowscan screen -t 0xContractAddress -v reentrancy -v flashloan

# Multi-chain screening
shadowscan screen -t 0xContractAddress -c polygon -b arbitrum
```

### 🔬 Enhanced Screening Commands

```bash
# List all vulnerability types (22 types)
shadowscan enhanced vulns -t 0xContractAddress

# Basic enhanced scan
shadowscan enhanced scan -t 0xContractAddress -d basic

# Deep enhanced scan
shadowscan enhanced scan -t 0xContractAddress -d deep -v reentrancy

# Deep dive analysis
shadowscan enhanced deep -t 0xContractAddress -v flashloan -m symbolic_execution

# Ecosystem analysis
shadowscan enhanced ecosystem -t 0xContractAddress -e comprehensive
```

### 🔍 Verification Commands (Module 2)

```bash
# Verify screening findings
shadowscan verify -t 0xContractAddress -s session_id

# Process findings for attack preparation
shadowscan verify process -t 0xContractAddress -o attack_data.json

# Risk assessment
shadowscan verify risk -t 0xContractAddress --economic-analysis

# Evidence collection
shadowscan verify evidence -t 0xContractAddress -v vulnerability_id
```

### ⚔️ Attack Commands (Module 3)

```bash
# Execute attack on fork environment
shadowscan attack execute -t 0xTarget -m reentrancy --environment fork

# Analyze attack feasibility
shadowscan attack analyze -t 0xTarget -m flashloan --dry-run

# Validate attack results
shadowscan attack validate -t 0xTarget -a attack_id

# Generate attack reports
shadowscan attack reports -t 0xTarget -f html

# Attack status monitoring
shadowscan attack status -a attack_id

# Deploy attack contracts
shadowscan attack templates -m reentrancy -d deploy
```

### 📊 Reporting Commands

```bash
# Generate comprehensive report
shadowscan report generate -t 0xContractAddress -f pdf

# Export findings
shadowscan report export -t 0xContractAddress -f json -o findings.json

# Compare multiple scans
shadowscan report compare -s session1 -s session2

# Dashboard view
shadowscan report dashboard -t 0xContractAddress
```

## 🔍 Core Modules

### Module 1: Screening Engine
```python
from shadowscan.core.pipeline.screening_engine import ScreeningEngine

# Initialize screening engine
engine = ScreeningEngine(rpc_url, etherscan_key)

# Run comprehensive screening
result = engine.run_screening(
    target="0xContractAddress",
    chain="ethereum", 
    mode="fork",
    depth="full",
    opts={"ecosystem_analysis": True}
)
```

**Features:**
- Multi-chain smart contract analysis
- DEX and protocol discovery
- Transaction pattern analysis
- Event log processing
- State snapshot analysis
- Ecosystem relationship mapping

### Module 2: Verification System
```python
from shadowscan.verifiers.evm.verifier import EVMVerifier

# Initialize verifier
verifier = EVMVerifier(web3_instance)

# Verify vulnerability findings
verification_result = await verifier.verify_vulnerability(
    contract_address="0xContractAddress",
    vulnerability_type="reentrancy",
    evidence=evidence_data
)
```

**Features:**
- Vulnerability validation
- Static analysis verification
- Dynamic testing
- Risk assessment
- Economic impact analysis
- Evidence collection

### Module 3: Attack Framework
```python
from shadowscan.core.attack.attack_framework import AttackFramework

# Initialize attack framework
framework = AttackFramework()

# Plan and execute attack
attack_plan = await framework.plan_attack(
    target="0xTargetAddress",
    vulnerability_type="reentrancy",
    environment="fork"
)

result = await framework.execute_attack(attack_plan.attack_id)
```

**Features:**
- Attack planning and preparation
- Contract deployment
- Attack execution
- Result validation
- Financial impact analysis
- Mainnet proof generation

## 🛡️ Enhanced Screening

### Enhanced Vulnerability Detection
ShadowScan mendeteksi 22+ jenis vulnerability dengan 6 metode deteksi:

#### 🏦 Financial Vulnerabilities (5 types)
- **Reentrancy Attack** (CRITICAL)
- **Flash Loan Attack** (CRITICAL) 
- **Integer Overflow/Underflow** (HIGH)
- **Timestamp Dependency** (MEDIUM)
- **Front Running** (HIGH)

#### 🔐 Access Control Vulnerabilities (4 types)
- **Ownership Hijacking** (CRITICAL)
- **Access Control Bypass** (HIGH)
- **Unprotected Critical Function** (MEDIUM)
- **Delegatecall Injection** (CRITICAL)

#### 🧠 Logical Vulnerabilities (4 types)
- **Oracle Manipulation** (HIGH)
- **Gas Limit Griefing** (MEDIUM)
- **Denial of Service** (MEDIUM)
- **Race Condition** (HIGH)

#### 🔐 Cryptographic Vulnerabilities (3 types)
- **Weak Randomness** (MEDIUM)
- **Signature Malleability** (HIGH)
- **Hardcoded Secrets** (CRITICAL)

#### 💰 Economic Vulnerabilities (3 types)
- **Arbitrage Opportunity** (MEDIUM)
- **Sandwich Attack** (MEDIUM)
- **MEV Extraction** (HIGH)

#### 🔗 Protocol Vulnerabilities (3 types)
- **Proxy Collision** (CRITICAL)
- **Upgrade Vulnerability** (HIGH)
- **Initialization Vulnerability** (HIGH)

### Detection Methods
1. **Pattern Matching** - Deteksi signature vulnerability yang diketahui
2. **Symbolic Execution** - Analisis eksekusi simbolik untuk path exploration
3. **Taint Analysis** - Tracking data flow untuk identifikasi contamination
4. **Constraint Solving** - Solving constraint untuk condition analysis
5. **Formal Verification** - Mathematical proof untuk property verification
6. **Dynamic Analysis** - Runtime analysis melalui transaction simulation

### Enhanced Screening Usage
```python
from enhanced_screening.enhanced_engine import EnhancedScreeningEngine

# Initialize enhanced engine
engine = EnhancedScreeningEngine(rpc_url, etherscan_key)

# Run enhanced screening
result = await engine.run_enhanced_screening(
    target="0xContractAddress",
    scan_depth="deep",
    vulnerability_types=["reentrancy", "flashloan"],
    intensity="deep",
    opts={
        "with_ecosystem": True,
        "with_economic": True,
        "with_exploitation": True
    }
)
```

## ⚔️ Attack Framework

### Attack Modes
ShadowScan mendukung 5 mode attack utama:

#### 1. Reentrancy Attack
```bash
# Execute reentrancy attack
shadowscan attack execute -t 0xTarget -m reentrancy --value 1.5 --environment fork

# Analyze reentrancy feasibility
shadowscan attack analyze -t 0xTarget -m reentrancy --dry-run
```

#### 2. Flash Loan Attack
```bash
# Execute flash loan attack
shadowscan attack execute -t 0xTarget -m flashloan --loan-amount 1000 --environment fork

# Multi-target flash loan
shadowscan attack execute -t 0xTarget -m flashloan --targets 0xDex1,0xDex2
```

#### 3. Oracle Manipulation
```bash
# Oracle manipulation attack
shadowscan attack execute -t 0xTarget -m oracle_manipulation --oracle 0xOracleAddress

# Price manipulation analysis
shadowscan attack analyze -t 0xTarget -m oracle_manipulation --impact-analysis
```

#### 4. Access Control Bypass
```bash
# Access control attack
shadowscan attack execute -t 0xTarget -m access_control_bypass --target-function withdraw

# Privilege escalation
shadowscan attack execute -t 0xTarget -m ownership_hijack
```

#### 5. Integer Overflow/Underflow
```bash
# Integer overflow attack
shadowscan attack execute -t 0xTarget -m integer_overflow --target-function mint

# Underflow exploitation
shadowscan attack execute -t 0xTarget -m integer_overflow --exploitation-type underflow
```

### Attack Environment Support
- **Fork Environment**: Safe testing dengan real blockchain state
- **Mainnet Environment**: Real attack untuk proof generation
- **Local Environment**: Development dan debugging

## 📊 Reporting

### Report Types
1. **Vulnerability Report**: Detil vulnerability findings
2. **Attack Report**: Attack execution results dan proof
3. **Ecosystem Report**: Analisis ekosistem dan dependencies
4. **Compliance Report**: Security compliance assessment
5. **Executive Summary**: High-level overview untuk stakeholders

### Report Formats
- **PDF**: Professional formatted reports
- **HTML**: Interactive web reports
- **JSON**: Machine-readable data
- **Markdown**: Documentation format

### Report Generation
```python
from shadowscan.reports.generator import ReportGenerator

# Generate comprehensive report
generator = ReportGenerator()
report = generator.generate_report(
    target="0xContractAddress",
    session_id="session_id",
    format="pdf",
    include_charts=True,
    include_recommendations=True
)
```

## 🧪 Testing

### Test Suite
```bash
# Run all tests
pytest

# Run specific test modules
pytest tests/test_screening_engine.py
pytest tests/test_attack_framework.py
pytest tests/test_enhanced_screening.py

# Run with coverage
pytest --cov=shadowscan

# Integration tests
python test_modules_workflow.py
python test_complete_attack_system.py
```

### Test Coverage
- **Unit Tests**: Individual component testing
- **Integration Tests**: Module interaction testing
- **End-to-End Tests**: Complete workflow testing
- **Performance Tests**: Scalability and speed testing

### Test Data
```bash
# Test with sample contracts
python test_enhanced_screening.py

# Workflow validation
python test_modules_workflow.py

# Attack system validation
python test_complete_attack_system.py
```

## 🔄 Development Workflow

### 1. Setup Development Environment
```bash
# Clone and setup
git clone https://github.com/yourusername/shadowscan.git
cd shadowscan
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements-dev.txt
pip install -e .
```

### 2. Code Standards
```bash
# Linting
flake8 shadowscan/
black shadowscan/
isort shadowscan/

# Type checking
mypy shadowscan/

# Security scanning
bandit -r shadowscan/
```

### 3. Testing Workflow
```bash
# Run tests before commit
pytest

# Run specific test category
pytest tests/collectors/
pytest tests/detectors/

# Performance testing
pytest --benchmark-only
```

### 4. Git Workflow
```bash
# Create feature branch
git checkout -b feature/enhanced-screening

# Make changes and test
# ... development work ...

# Commit changes
git add .
git commit -m "feat: add enhanced screening capabilities"

# Push and create PR
git push origin feature/enhanced-screening
```

## 📈 Roadmap

### ✅ Phase 1: Core Infrastructure (Completed)
- [x] Basic screening engine
- [x] CLI framework
- [x] Configuration system
- [x] Data collection modules
- [x] Basic vulnerability detection

### ✅ Phase 2: Enhanced Detection (Completed)
- [x] Enhanced screening engine
- [x] 22+ vulnerability types
- [x] Multiple detection methods
- [x] Ecosystem analysis
- [x] Deep scanning capabilities

### ✅ Phase 3: Attack Framework (Completed)
- [x] Attack planning and execution
- [x] Fork and mainnet environments
- [x] Financial impact analysis
- [x] Attack validation and proof
- [x] Comprehensive reporting

### 🚧 Phase 4: Advanced Features (In Progress)
- [ ] AI-powered vulnerability detection
- [ ] Real-time monitoring system
- [ ] Advanced threat intelligence
- [ ] Multi-chain orchestration
- [ ] Cloud deployment options

### 📋 Phase 5: Enterprise Features (Planned)
- [ ] Team collaboration features
- [ ] Advanced API gateway
- [ ] Enterprise dashboard
- [ ] Custom integrations
- [ ] Compliance automation

### 🔮 Future Enhancements
- **Machine Learning**: ML-based vulnerability prediction
- **Cross-Chain Analysis**: Interoperability vulnerability detection
- **DeFi Protocol Analysis**: Specialized DeFi security assessment
- **Real-time Threat Detection**: Live monitoring and alerting
- **Mobile App**: On-the-go security assessment

## 🤝 Contributing

### Contribution Guidelines
1. **Fork the Repository**
2. **Create Feature Branch** (`git checkout -b feature/amazing-feature`)
3. **Follow Code Standards** (Black, Flake8, MyPy)
4. **Write Tests** for new functionality
5. **Update Documentation** as needed
6. **Submit Pull Request** with detailed description

### Development Requirements
- Python 3.10+
- Follow PEP 8 standards
- Include type hints
- Write comprehensive tests
- Update documentation

### Reporting Issues
- Use GitHub Issues with detailed description
- Include steps to reproduce
- Provide environment details
- Attach relevant logs/output

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Etherscan API** - Blockchain data provider
- **Tenderly** - Fork environment and simulation
- **Web3.py** - Ethereum Python interface
- **OpenZeppelin** - Security best practices
- **Security Community** - Vulnerability research and disclosure

## 📞 Support

- **Documentation**: [docs/](docs/) directory
- **Issues**: [GitHub Issues](https://github.com/yourusername/shadowscan/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/shadowscan/discussions)
- **Email**: support@shadowscan.security

---

<div align="center">

**🔍 ShadowScan - Advanced Blockchain Security Platform**

Built with ❤️ by ShadowScan Security Team

[![Website](https://img.shields.io/badge/website-shadowscan.security-blue)](https://shadowscan.security)
[![Twitter](https://img.shields.io/badge/twitter-@shadowscan-blue)](https://twitter.com/shadowscan)
[![Discord](https://img.shields.io/badge/discord-join-blue)](https://discord.gg/shadowscan)

</div>