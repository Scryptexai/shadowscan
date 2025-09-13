# 🔍 ShadowScan Standalone Edition
## Cross-Platform Backup Framework

**Version**: 2.0-Standalone
**License**: MIT

**ShadowScan Standalone** adalah versi backup yang dapat dijalankan di berbagai device tanpa memerlukan virtual environment (venv). Dirancang untuk kemudahan deployment dan portabilitas.

## 🚀 Quick Start - Instalasi di Device Baru

### **Metode 1: Script Installer (Recommended)**

```bash
# Download dan jalankan installer
wget https://raw.githubusercontent.com/shadowscan/shadowscan/main/install-standalone.sh
chmod +x install-standalone.sh
./install-standalone.sh
```

### **Metode 2: Manual Installation**

```bash
# 1. Download/copy repository
git clone https://github.com/shadowscan/shadowscan.git
cd shadowscan

# 2. Install dependencies (tanpa venv)
pip3 install --user -r requirements.txt

# 3. Buat konfigurasi
cp .env.example .env
# Edit .env dengan API keys anda

# 4. Test instalasi
python3 shadowscan-standalone.py status
```

## 🖥️ **Platform Support**

### **Linux (Ubuntu/Debian/CentOS)**
```bash
# System requirements
sudo apt update
sudo apt install -y python3 python3-pip git build-essential libssl-dev

# Run installer
./install-standalone.sh

# Atau manual
pip3 install --user -r requirements.txt
python3 shadowscan-standalone.py status
```

### **Windows 10/11**
```cmd
# System requirements
- Python 3.8+ dari python.org
- Git untuk Windows (optional)

# Install Python packages
pip install --user -r requirements.txt

# Jalankan via batch file
shadowscan-windows.bat status

# Atau via Python
python shadowscan-standalone.py status
```

### **macOS**
```bash
# System requirements
brew install python3 git

# Install packages
pip3 install --user -r requirements.txt

# Run
python3 shadowscan-standalone.py status
```

## ⚙️ **Configuration Setup**

### **Edit .env file**
```bash
# Copy template
cp .env.example .env

# Edit dengan editor anda
nano .env
# atau
vim .env
```

### **Minimum Configuration Required:**
```env
# Target contract
TARGET_CONTRACT=0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3

# RPC Configuration
TENDERLY_RPC=https://virtual.mainnet.eu.rpc.tenderly.co/your_rpc_here
ETHERSCAN_API_KEY=your_etherscan_api_key_here

# Attack simulation (optional)
PRIVATE_KEY=your_private_key_here
ATTACKER_ADDRESS=your_attacker_address_here
```

## 🎮 **Usage Commands**

### **Quick Start Commands**
```bash
# Check system status
python3 shadowscan-standalone.py status

# Run complete workflow test
python3 shadowscan-standalone.py workflow

# Quick screening
python3 shadowscan-standalone.py screen -t 0xTarget -c eth

# Attack analysis
python3 shadowscan-standalone.py attack analyze -t 0xTarget -c eth
```

### **Complete Module Workflow**

#### **Module 1: Contract Screening + Ecosystem**
```bash
# Full ecosystem screening
python3 shadowscan-standalone.py screen \
  -t 0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3 \
  -c ethereum -m fork -d full \
  -g -e -S

# Quick screening
python3 shadowscan-standalone.py s \
  -t 0xTarget -c eth -m f -d f
```

#### **Module 2: Attack Analysis**
```bash
# Basic feasibility analysis
python3 shadowscan-standalone.py attack analyze \
  -t 0xTarget -c ethereum

# Multiple vulnerabilities
python3 shadowscan-standalone.py attack analyze \
  -t 0xTarget -c ethereum \
  -v reentrancy -v flashloan -v access_control
```

#### **Module 3: Attack Execution**
```bash
# Safe fork execution
python3 shadowscan-standalone.py attack execute \
  -t 0xTarget -m reentrancy -e fork --dry-run

# Flashloan simulation
python3 shadowscan-standalone.py attack execute \
  -t 0xTarget -m flashloan -e fork --value 5.0
```

## 📱 **Device-Specific Integration**

### **Linux Desktop Integration**
```bash
# Set up desktop shortcut
./install-linux-desktop

# Creates menu entry and desktop icon
# Launchable from application menu
```

### **Windows Integration**
```bash
# Set up batch file
./install-windows

# Creates shadowscan.bat for easy execution
# Can be run from any directory
```

### **macOS Integration**
```bash
# Set up shell alias
./install-macos

# Add to ~/.bash_profile or ~/.zshrc
# Enables 'shadowscan' command from anywhere
```

## 🔧 **Troubleshooting**

### **Common Issues**

#### **Python Import Errors**
```bash
# Check Python path
python3 -c "import sys; print(sys.path)"

# Add current directory to Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

#### **Permission Issues**
```bash
# Linux/macOS - make scripts executable
chmod +x shadowscan-standalone.py
chmod +x install-standalone.sh

# Windows - run as administrator if needed
# Right-click cmd -> Run as administrator
```

#### **Missing Dependencies**
```bash
# Install missing packages
pip3 install --user web3 click eth_account requests aiohttp

# Or install all requirements
pip3 install --user -r requirements.txt
```

#### **Configuration Issues**
```bash
# Validate .env file
python3 -c "
import os
from pathlib import Path
env_file = Path('.env')
if env_file.exists():
    with open(env_file, 'r') as f:
        print('✅ .env file found')
else:
    print('❌ .env file missing')
"
```

### **Platform-Specific Solutions**

#### **Linux - No pip3**
```bash
# Ubuntu/Debian
sudo apt install python3-pip

# CentOS/RHEL
sudo yum install python3-pip

# Fedora
sudo dnf install python3-pip
```

#### **Windows - Python not in PATH**
```cmd
# Add Python to PATH (Windows 10/11)
# Settings > System > About > Advanced system settings
# Environment Variables > Path > Edit > Add Python path
```

#### **macOS - Python version conflicts**
```bash
# Use python3 explicitly instead of python
# Or install via Homebrew for consistent version
brew install python3
```

## 📁 **Directory Structure**

```
shadowscan-standalone/
├── shadowscan/                 # Core framework
│   ├── core/                  # Core modules
│   ├── commands/              # CLI commands
│   ├── collectors/            # Data collectors
│   ├── detectors/            # Vulnerability detectors
│   └── utils/                 # Utility functions
├── config/                    # Configuration files
├── test_modules_workflow.py   # Complete workflow test
├── shadowscan-standalone.py   # Main runner script
├── shadowscan-windows.bat     # Windows batch file
├── install-standalone.sh      # Installer script
├── requirements.txt           # Python dependencies
├── .env                      # Configuration (create this)
└── README_STANDALONE.md       # This file
```

## 🚨 **Important Notes**

### **Security Considerations**
- 🔒 Keep your private keys secure in .env file
- 🔒 Don't commit .env to version control
- 🔒 Use fork environment for testing (`-e fork`)
- 🔒 Enable `--dry-run` for safe simulation

### **Performance Tips**
- 💡 Use `-d shallow` for quick scans
- 💡 Limit concurrent threads with `--concurrency 4`
- 💇 Clear cache with `--no-cache` if issues arise
- 💡 Monitor system resources during large scans

### **Network Requirements**
- 🌐 Stable internet connection for RPC calls
- 🌐 API keys for Etherscan and blockchain RPC
- 🌐 Minimum 1GB RAM for smooth operation
- 🌐 2GB+ disk space for reports and data

## 📞 **Support**

### **Getting Help**
```bash
# Get help for specific command
python3 shadowscan-standalone.py screen --help
python3 shadowscan-standalone.py attack --help

# Check system status for diagnostics
python3 shadowscan-standalone.py status

# Run quick test
python3 quick-test
```

### **Community Support**
- 📧 Email: support@shadowscan.dev
- 💬 Discord: [ShadowScan Community](https://discord.gg/shadowscan)
- 🐛 Issues: [GitHub Issues](https://github.com/shadowscan/shadowscan/issues)
- 📖 Docs: [Documentation](https://docs.shadowscan.dev)

### **Reporting Issues**
When reporting issues, please include:
1. Operating System and version
2. Python version (`python3 --version`)
3. Error messages (full output)
4. Steps to reproduce the issue
5. Your .env configuration (sensitive info removed)

---

**Built with ❤️ by ShadowScan Security Team**

*Standalone Edition - Run anywhere, anytime!*