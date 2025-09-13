# 🔍 ShadowScan - Advanced Blockchain Security Platform

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)
![Version](https://img.shields.io/pypi/v/shadowscan)

**ShadowScan** is a comprehensive blockchain security platform with integrated attack validation framework. Designed to discover, verify, and prove smart contract vulnerabilities through controlled exploit simulations.

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/shadowscan/shadowscan.git
cd shadowscan

# Install dependencies
pip install -r requirements.txt

# Install ShadowScan CLI
pip install -e .

# Verify installation
shadowscan --help
```

## 🔄 COMPLETE 3-MODULE WORKFLOW

### **MODULE 1: Main Contract Screening + Ecosystem Tracking**
*Screen main contract and discover related DEX/DApp ecosystem*

```bash
# Comprehensive screening with ecosystem tracking
shadowscan screen -t 0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3 \
  -c ethereum -m fork -d full \
  -g -e -S -o reports/screening

# Shorthand version
shadowscan s -t 0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3 \
  -c ethereum -m f -d f \
  -g -e -S -o reports/screening
```

**Output:**
- Main contract vulnerability analysis (20 vulnerability types)
- Ecosystem interaction graph (DEX/DApp discovery)
- Related contract identification through transaction analysis
- Oracle intelligence gathering
- Relationship mapping and visualization

### **MODULE 2: Verification & Data Processing for Attack**
*Verify findings and prepare attack scenarios*

```bash
# Attack feasibility analysis based on Module 1 findings
shadowscan attack analyze -t 0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3 \
  -c ethereum \
  -v reentrancy -v flashloan -v access_control \
  --value 10.0

# Verify vulnerabilities from ecosystem contracts
shadowscan attack analyze -t 0xDiscoveredContractAddress \
  -c ethereum \
  -v reentrancy -v oracle_manipulation
```

**Output:**
- Verified vulnerability assessment
- Attack scenario preparation
- Feasibility scoring and ROI calculation
- Contract-specific attack vectors

### **MODULE 3: Attack Execution with Processed Data**
*Execute controlled attacks using verified data*

```bash
# Execute reentrancy attack in fork environment (safe testing)
shadowscan attack execute -t 0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3 \
  -c ethereum -m reentrancy -e fork \
  --dry-run -o reports/attacks

# Execute flashloan attack on DEX contract
shadowscan attack execute -t 0xDiscoveredDEXContract \
  -c ethereum -m flashloan -e fork \
  --value 5.0 --dry-run

# Multiple vulnerability testing
shadowscan attack execute -t 0xTargetContract \
  -c ethereum -m reentrancy -e fork \
  -v reentrancy -v flashloan -v access_control
```

**Output:**
- Controlled exploit execution in fork environment
- Attack transaction validation
- Financial impact analysis
- Professional evidence documentation

## 🎯 Complete Workflow Command Sequence

```bash
# Step 1: Complete ecosystem screening (Module 1)
shadowscan s -t 0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3 \
  -c ethereum -m f -d f \
  -g -e -S -o workflow/module1

# Step 2: Attack feasibility analysis (Module 2)  
shadowscan attack analyze -t 0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3 \
  -c ethereum \
  -v reentrancy -v flashloan -v access_control \
  --value 10.0

# Step 3: Safe attack execution (Module 3)
shadowscan attack execute -t 0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3 \
  -c ethereum -m reentrancy -e fork \
  --dry-run -o workflow/module3

# Alternative: Complete workflow test
python3 test_modules_workflow.py
```

## 🧰 Advanced Usage

### Testing Different Attack Types

```bash
# Reentrancy attack testing
shadowscan attack execute -t 0xTarget -m reentrancy -e fork --dry-run

# Flash loan attack simulation
shadowscan attack execute -t 0xTarget -m flashloan -e fork --value 10.0

# Oracle manipulation attack
shadowscan attack execute -t 0xTarget -m oracle_manipulation -e fork

# Access control bypass
shadowscan attack execute -t 0xTarget -m access_control -e fork

# Integer overflow testing
shadowscan attack execute -t 0xTarget -m integer_overflow -e fork
```

### Environment Configuration

```bash
# Fork environment (safe testing)
shadowscan attack execute -t 0xTarget -m reentrancy -e fork

# Mainnet environment (real validation)
shadowscan attack execute -t 0xTarget -m reentrancy -e mainnet

# Custom RPC configuration
shadowscan s -t 0xTarget --rpc-url https://custom-rpc-url
```

## 🎯 Key Features

### Phase 1: Screening Framework
- Multi-vector vulnerability detection
- AI-powered pattern recognition  
- Stealth mode operations
- Comprehensive contract analysis

### Phase 2: Verification System
- Automated vulnerability confirmation
- False positive reduction
- Risk assessment scoring
- Detailed validation reports

### Phase 3: Attack Framework ⭐
- **5 Attack Modes**: Reentrancy, Flashloan, Oracle Manipulation, Access Control, Integer Overflow
- **Dual Environments**: Fork (safe testing) and Mainnet (real validation)
- **Controlled Exploits**: Safe simulation with real blockchain evidence
- **Financial Impact Analysis**: Profit calculation and ROI assessment
- **Professional Reporting**: JSON and HTML report formats

## 🧰 Use Cases

### Smart Contract Auditing
```bash
# Comprehensive audit
shadowscan analyze -t 0xContractAddress -m comprehensive
shadowscan attack analyze -t 0xContractAddress -c ethereum -v reentrancy -v flashloan
shadowscan attack execute -t 0xContractAddress -m reentrancy -e fork --dry-run
```

### DeFi Security Assessment
```bash
# Multi-vulnerability testing
shadowscan attack execute -t 0xDefiProtocol -m reentrancy -e fork -v reentrancy -v flashloan
shadowscan attack execute -t 0xDefiProtocol -m access_control -e fork
```

### Security Research
```bash
# Research and analysis
shadowscan attack templates
shadowscan attack execute -t 0xResearchTarget -m oracle_manipulation -e fork
shadowscan attack reports --output research/findings
```

### Compliance Validation
```bash
# Regulatory compliance
for mode in reentrancy flashloan oracle_manipulation access_control integer_overflow; do
    shadowscan attack execute -t 0xComplianceTarget -m $mode -e fork --dry-run
done
## 📋 Command Reference

### Quick Start Commands

```bash
# Basic screening
shadowscan s -t 0xTarget -c ethereum

# Attack analysis
shadowscan attack analyze -t 0xTarget -c ethereum

# Attack execution (safe)
shadowscan attack execute -t 0xTarget -m reentrancy -e fork --dry-run

# Complete workflow test
python3 test_modules_workflow.py
```

### Core Commands

#### Screening Commands (Module 1)
```bash
# Full ecosystem screening
shadowscan screen -t 0xTarget -c ethereum -m fork -d full -g -e -S

# Shorthand screening
shadowscan s -t 0xTarget -c eth -m f -d f -g -e -S

# Quick scan (shallow depth)
shadowscan s -t 0xTarget -c eth -m f -d s

# Without graph building
shadowscan s -t 0xTarget -c eth -m f -d f -ng
```

#### Attack Analysis Commands (Module 2)
```bash
# Basic feasibility analysis
shadowscan attack analyze -t 0xTarget -c ethereum

# Multiple vulnerability analysis
shadowscan attack analyze -t 0xTarget -c ethereum -v reentrancy -v flashloan

# With custom value assessment
shadowscan attack analyze -t 0xTarget -c ethereum --value 10.0

# Comprehensive attack planning
shadowscan attack analyze -t 0xTarget -c ethereum \
  -v reentrancy -v flashloan -v access_control -v oracle_manipulation
```

#### Attack Execution Commands (Module 3)
```bash
# Safe fork execution (dry run)
shadowscan attack execute -t 0xTarget -m reentrancy -e fork --dry-run

# Execute with specific parameters
shadowscan attack execute -t 0xTarget -m flashloan -e fork --value 5.0

# Multiple vulnerability testing
shadowscan attack execute -t 0xTarget -m reentrancy -e fork \
  -v reentrancy -v flashloan -v access_control

# Custom output directory
shadowscan attack execute -t 0xTarget -m reentrancy -e fork \
  --output reports/attacks
```

### Attack Template Management

```bash
# List all attack templates
shadowscan attack templates

# Check specific attack status
shadowscan attack status --attack-id attack_id_here

# Validate attack results
shadowscan attack validate --attack-id attack_id_here --environment fork

# List attack reports
shadowscan attack reports

# Export attack results
shadowscan attack reports --output reports/attacks --format json
```

### System Configuration

```bash
# View system status
shadowscan status

# Show configuration
shadowscan config show

# Set API keys
shadowscan config set --key ETHERSCAN_API_KEY --value "your_key"
shadowscan config set --key TENDERLY_RPC --value "your_rpc_url"

# Set blockchain settings
shadowscan config set --key CHAIN_ID --value "1" --section blockchain
```

### Report Management

```bash
# List all reports
shadowscan reports list

# Filter by report type
shadowscan reports list --type screening
shadowscan reports list --type attack
shadowscan reports list --type verification

# Export reports
shadowscan reports list --format json
shadowscan reports list --format html

# List reports from custom directory
shadowscan reports list --output custom_reports
```

## 🔧 Advanced Usage

### Environment Variables
```bash
export ETHERSCAN_API_KEY="your_key"
export TENDERLY_RPC="your_rpc"
export CHAIN_ID="1"
export ATTACKER_ADDRESS="0xYourAddress"

# Use custom env file
shadowscan --env-file .custom.env attack execute -t 0xTarget -m reentrancy -e fork
```

### Configuration Files
```bash
# Use custom config
shadowscan --config /path/to/config.json attack execute -t 0xTarget -m reentrancy -e fork
```

### Verbose Output
```bash
# Verbose mode for debugging
shadowscan -v attack execute -t 0xTarget -m reentrancy -e fork

# Quiet mode for minimal output
shadowscan -q attack execute -t 0xTarget -m reentrancy -e fork
```

## 🎯 Attack Modes Available

### Reentrancy Attack
- **Severity:** CRITICAL
- **Command:** `shadowscan attack execute -m reentrancy`
- **Description:** Exploits external calls before state updates to drain funds

### Flash Loan Attack
- **Severity:** HIGH
- **Command:** `shadowscan attack execute -m flashloan`
- **Description:** Uses flash loans for price manipulation attacks

### Oracle Manipulation
- **Severity:** HIGH
- **Command:** `shadowscan attack execute -m oracle_manipulation`
- **Description:** Manipulates oracle prices for profit

### Access Control Bypass
- **Severity:** MEDIUM
- **Command:** `shadowscan attack execute -m access_control`
- **Description:** Bypasses access controls for privilege escalation

### Integer Overflow
- **Severity:** MEDIUM
- **Command:** `shadowscan attack execute -m integer_overflow`
- **Description:** Exploits arithmetic overflow vulnerabilities

## 🛡️ Safety Features

- **Fork Environment Testing:** All attacks run on safe fork environment
- **Dry Run Mode:** Plan attacks without execution
- **Controlled Execution:** All transactions are recorded and traceable
- **Professional Reporting:** Comprehensive documentation and evidence

## 🚨 Important Notes

1. **Legal Compliance:** Designed for ethical security testing only
2. **Environment Safety:** Always use fork environment for testing
3. **Permission Required:** Only test contracts you own or have permission to test
4. **Documentation:** Save all reports for compliance and auditing

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## 🔗 Links

- **Documentation:** https://docs.shadowscan.dev
- **GitHub:** https://github.com/shadowscan/shadowscan
- **Issues:** https://github.com/shadowscan/shadowscan/issues

---

**Built with ❤️ by ShadowScan Security Team**