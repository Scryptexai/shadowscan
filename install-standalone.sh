#!/bin/bash
# ShadowScan Backup Framework - Standalone Installer
# For deployment on different devices without venv

set -e

echo "🔍 ShadowScan Standalone Installer"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     MACHINE=Linux;;
    Darwin*)    MACHINE=Mac;;
    CYGWIN*)    MACHINE=Cygwin;;
    MINGW*)     MACHINE=MinGw;;
    MSYS_NT*)   MACHINE=Git;;
    *)          MACHINE="UNKNOWN:${OS}"
esac

echo "🖥️  Detected OS: ${MACHINE}"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python3 not found! Please install Python 3.8+ first${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "🐍 Python version: ${PYTHON_VERSION}"

if ! python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)'; then
    echo -e "${RED}❌ Python 3.8+ required. Found: ${PYTHON_VERSION}${NC}"
    exit 1
fi

# Check pip
if ! command -v pip3 &> /dev/null; then
    echo -e "${YELLOW}⚠️  pip3 not found, attempting to install...${NC}"
    if [[ "${MACHINE}" == "Linux" ]]; then
        # Try common package managers
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y python3-pip
        elif command -v yum &> /dev/null; then
            sudo yum install -y python3-pip
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y python3-pip
        else
            echo -e "${RED}❌ Please install pip3 manually${NC}"
            exit 1
        fi
    elif [[ "${MACHINE}" == "Mac" ]]; then
        if command -v brew &> /dev/null; then
            brew install python3
        else
            echo -e "${RED}❌ Please install pip3 manually${NC}"
            exit 1
        fi
    fi
fi

# Create installation directory
INSTALL_DIR="${HOME}/shadowscan-standalone"
echo "📁 Installation directory: ${INSTALL_DIR}"

if [ -d "${INSTALL_DIR}" ]; then
    echo -e "${YELLOW}⚠️  Directory exists, backing up...${NC}"
    mv "${INSTALL_DIR}" "${INSTALL_DIR}-backup-$(date +%Y%m%d_%H%M%S)"
fi

mkdir -p "${INSTALL_DIR}"
cd "${INSTALL_DIR}"

echo "📦 Downloading ShadowScan framework..."

# Download or copy files (prioritize local source)
if [ -f "../shadowscan" ]; then
    echo "📋 Copying from local source..."
    cp -r "../shadowscan" ./
elif [ -f "../shadowscan-standalone.py" ]; then
    echo "📋 Copying from current directory..."
    cp -r ../* ./
    # Remove duplicate files if any
    rm -rf shadowscan-standalone 2>/dev/null || true
else
    echo "🌐 Downloading from repository..."
    # Try GitHub CLI first
    if command -v gh &> /dev/null; then
        gh repo clone shadowscan/shadowscan
        mv shadowscan/* ./
        rm -rf shadowscan
    else
        # Try direct download without authentication
        echo "⬇️  Downloading via curl..."
        curl -L -o master.zip "https://github.com/shadowscan/shadowscan/archive/refs/heads/main.zip"
        if [ $? -eq 0 ]; then
            unzip master.zip
            mv shadowscan-main/* ./
            rm -rf shadowscan-main master.zip
        else
            echo "❌ Cannot download from GitHub. Please copy files manually."
            echo "💡 Alternative: Copy the entire shadowscan folder to this directory."
            exit 1
        fi
    fi
fi

echo "🔧 Installing dependencies without venv..."

# Install system dependencies
if [[ "${MACHINE}" == "Linux" ]]; then
    echo "📦 Installing system dependencies..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            libssl-dev \
            libffi-dev \
            python3-dev \
            git
    elif command -v yum &> /dev/null; then
        sudo yum groupinstall -y "Development Tools"
        sudo yum install -y \
            openssl-devel \
            libffi-devel \
            python3-devel \
            git
    fi
fi

# Install Python dependencies
echo "📦 Installing Python packages..."
pip3 install --user -r requirements.txt

# Create configuration
echo "⚙️  Creating configuration..."
cat > .env << EOF
# ======================================
# SHADOWSCAN CONFIGURATION
# ======================================

# 🔍 Target Configuration
TARGET_TYPE=blockchain
TARGET_URL=https://portaltobitcoin.com/
TARGET_CONTRACT=0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3

# 🌐 Blockchain Configuration
CHAIN_ID=1
# Add your RPC URLs here
TENDERLY_RPC=your_tenderly_rpc_here
ETHERSCAN_API_KEY=your_etherscan_key_here

# 🕵️‍♂️ Attacker Configuration (for simulation)
PRIVATE_KEY=your_private_key_here
ATTACKER_ADDRESS=your_attacker_address_here

# ⚙️ Engine Configuration
MAX_THREADS=10
RATE_LIMIT_DELAY=1.5
TIMEOUT=30
STEALTH_MODE=true

# 📊 Reporting Configuration
REPORT_FORMAT=json
REPORT_DIR=reports
EOF

# Create standalone scripts
echo "📜 Creating standalone scripts..."

# Main runner script
cat > shadowscan-run << 'EOF'
#!/bin/bash
# ShadowScan Standalone Runner

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="${SCRIPT_DIR}:${PYTHONPATH}"

cd "${SCRIPT_DIR}"

echo "🔍 ShadowScan Standalone Runner"
echo "=============================="

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "❌ .env file not found! Please run installer first."
    exit 1
fi

# Load environment
set -a
source .env
set +a

# Run command
case "${1:-help}" in
    "screen"|"s")
        echo "🔍 Running screening..."
        python3 -m shadowscan.commands.screen "${@:2}"
        ;;
    "attack")
        echo "⚔️  Running attack analysis..."
        python3 -m shadowscan.commands.attack_commands "${@:2}"
        ;;
    "workflow")
        echo "🔄 Running complete workflow test..."
        python3 test_modules_workflow.py
        ;;
    "status")
        echo "📊 System status..."
        python3 -c "
import sys
sys.path.insert(0, '.')
try:
    from shadowscan.core.pipeline.screening_engine import ScreeningEngine
    from shadowscan.core.attack.attack_framework import AttackFramework
    print('✅ All modules imported successfully')
    print('✅ System ready for operation')
except ImportError as e:
    print(f'❌ Import error: {e}')
    print('Please check installation')
"
        ;;
    "help"|*)
        echo "Usage: $0 {screen|attack|workflow|status|help}"
        echo ""
        echo "Commands:"
        echo "  screen|s    - Run contract screening"
        echo "  attack      - Run attack analysis/execution"
        echo "  workflow    - Run complete workflow test"
        echo "  status      - Check system status"
        echo "  help        - Show this help"
        ;;
esac
EOF

chmod +x shadowscan-run

# Quick test script
cat > quick-test << 'EOF'
#!/bin/bash
# Quick System Test

echo "🧪 Running Quick System Test..."
echo "============================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Test Python imports
echo "🐍 Testing Python imports..."
python3 -c "
import sys
sys.path.insert(0, '.')
try:
    from shadowscan.core.pipeline.screening_engine import ScreeningEngine
    from shadowscan.core.attack.attack_framework import AttackFramework
    from shadowscan.commands.screen import screen
    from shadowscan.commands.attack_commands import attack_commands
    print('✅ All imports successful')
except ImportError as e:
    print(f'❌ Import failed: {e}')
    sys.exit(1)
"

# Test basic functionality
echo "🔧 Testing basic functionality..."
python3 -c "
import sys
sys.path.insert(0, '.')
try:
    from shadowscan.utils.helpers import generate_session_id
    session_id = generate_session_id('0xTest')
    print(f'✅ Session ID generation: {session_id}')
    
    from shadowscan.utils.schema import RiskLevel
    print(f'✅ Schema import: {RiskLevel.CRITICAL}')
    
    print('✅ Basic functionality test passed')
except Exception as e:
    print(f'❌ Basic test failed: {e}')
    sys.exit(1)
"

echo "✅ Quick test completed successfully!"
EOF

chmod +x quick-test

# Create device-specific configuration
echo "📱 Creating device configuration..."

# Linux desktop
if [[ "${MACHINE}" == "Linux" ]]; then
    cat > install-linux-desktop << 'EOF'
#!/bin/bash
# Linux Desktop Installation

echo "🐧 Setting up Linux desktop integration..."

# Create desktop entry
cat > ~/.local/share/applications/shadowscan.desktop << EOE
[Desktop Entry]
Version=1.0
Type=Application
Name=ShadowScan
Comment=Advanced Blockchain Security Platform
Exec=$(pwd)/shadowscan-run
Icon=$(pwd)/docs/icon.png
Terminal=true
Categories=Security;Development;
EOE

chmod +x ~/.local/share/applications/shadowscan.desktop
echo "✅ Desktop integration completed"
EOF
    chmod +x install-linux-desktop
fi

# Windows (via Git Bash/WSL)
if [[ "${MACHINE}" == "MINGW" ]] || [[ "${MACHINE}" == "MSYS_NT" ]] || [[ "${MACHINE}" == "CYGWIN" ]]; then
    cat > install-windows << 'EOF'
#!/bin/bash
# Windows Installation

echo "🪟 Setting up Windows integration..."

# Create batch file wrapper
cat > shadowscan.bat << EOB
@echo off
cd /d "%~dp0"
bash shadowscan-run %*
EOB

echo "✅ Windows batch file created: shadowscan.bat"
EOF
    chmod +x install-windows
fi

# macOS
if [[ "${MACHINE}" == "Mac" ]]; then
    cat > install-macos << 'EOF'
#!/bin/bash
# macOS Installation

echo "🍎 Setting up macOS integration..."

# Create alias for bash profile
echo "" >> ~/.bash_profile
echo "# ShadowScan alias" >> ~/.bash_profile
echo "alias shadowscan='$(pwd)/shadowscan-run'" >> ~/.bash_profile

echo "✅ macOS alias created. Run 'source ~/.bash_profile' to activate."
EOF
    chmod +x install-macos
fi

echo ""
echo -e "${GREEN}✅ Installation completed successfully!${NC}"
echo ""
echo "🎯 Next steps:"
echo "1. Edit ${INSTALL_DIR}/.env with your API keys"
echo "2. Run './quick-test' to verify installation"
echo "3. Use './shadowscan-run [command]' to operate"
echo ""
echo "📱 Device-specific setup:"
if [[ "${MACHINE}" == "Linux" ]]; then
    echo "   Run './install-linux-desktop' for desktop integration"
elif [[ "${MACHINE}" == "Mac" ]]; then
    echo "   Run './install-macos' for shell alias"
elif [[ "${MACHINE}" == "MINGW" ]] || [[ "${MACHINE}" == "MSYS_NT" ]] || [[ "${MACHINE}" == "CYGWIN" ]]; then
    echo "   Run './install-windows' for batch file"
fi
echo ""
echo "📖 Usage examples:"
echo "  ./shadowscan-run screen -t 0xTarget -c eth"
echo "  ./shadowscan-run attack analyze -t 0xTarget -c eth"
echo "  ./shadowscan-run workflow"
echo "  ./shadowscan-run status"
echo ""
echo -e "${BLUE}🔍 ShadowScan is ready!${NC}"