#!/bin/bash
# ShadowScan Local Backup Installer
# For creating standalone backup from current installation

set -e

echo "🔍 ShadowScan Local Backup Creator"
echo "================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get current directory
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${HOME}/shadowscan-backup-$(date +%Y%m%d_%H%M%S)"
ARCHIVE_NAME="shadowscan-standalone-$(date +%Y%m%d).tar.gz"

echo "📁 Source directory: ${SOURCE_DIR}"
echo "📦 Backup directory: ${BACKUP_DIR}"
echo "📜 Archive name: ${ARCHIVE_NAME}"

# Check if we're in shadowscan directory
if [ ! -f "${SOURCE_DIR}/shadowscan/core/pipeline/screening_engine.py" ]; then
    echo -e "${RED}❌ Not in ShadowScan directory! Please run from shadowscan root directory.${NC}"
    exit 1
fi

# Create backup directory
mkdir -p "${BACKUP_DIR}"
cd "${BACKUP_DIR}"

echo "📋 Copying ShadowScan framework..."

# Copy core framework
cp -r "${SOURCE_DIR}/shadowscan" ./

# Copy standalone files
cp "${SOURCE_DIR}/shadowscan-standalone.py" ./ 2>/dev/null || echo "⚠️  shadowscan-standalone.py not found"
cp "${SOURCE_DIR}/shadowscan-windows.bat" ./ 2>/dev/null || echo "⚠️  shadowscan-windows.bat not found"
cp "${SOURCE_DIR}/install-standalone.sh" ./ 2>/dev/null || echo "⚠️  install-standalone.sh not found"

# Copy configuration files
cp "${SOURCE_DIR}/requirements.txt" ./ 2>/dev/null || echo "⚠️  requirements.txt not found"
cp "${SOURCE_DIR}/.env.example" ./ 2>/dev/null || echo "⚠️  .env.example not found"

# Copy documentation
cp "${SOURCE_DIR}/README_STANDALONE.md" ./ 2>/dev/null || echo "⚠️  README_STANDALONE.md not found"
cp "${SOURCE_DIR}/GOOGLE_DRIVE_INTEGRATION.md" ./ 2>/dev/null || echo "⚠️  GOOGLE_DRIVE_INTEGRATION.md not found"
cp "${SOURCE_DIR}/QUICK_SETUP.md" ./ 2>/dev/null || echo "⚠️  QUICK_SETUP.md not found"

# Copy test files
cp "${SOURCE_DIR}/test_modules_workflow.py" ./ 2>/dev/null || echo "⚠️  test_modules_workflow.py not found"

# Create simple installer script
cat > install-local.sh << 'EOF'
#!/bin/bash
# ShadowScan Local Installer

set -e

echo "🔍 ShadowScan Local Installer"
echo "============================="

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found! Please install Python 3.8+"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "🐍 Python version: ${PYTHON_VERSION}"

if ! python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)'; then
    echo "❌ Python 3.8+ required. Found: ${PYTHON_VERSION}"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
pip3 install --user -r requirements.txt

# Create configuration
if [ ! -f ".env" ]; then
    echo "⚙️  Creating configuration..."
    cp .env.example .env
    echo "✅ Configuration created. Please edit .env with your API keys."
else
    echo "⚙️  Configuration file already exists."
fi

# Make scripts executable
chmod +x shadowscan-standalone.py 2>/dev/null || true
chmod +x shadowscan-windows.bat 2>/dev/null || true

echo ""
echo "✅ Installation completed!"
echo ""
echo "🎯 Next steps:"
echo "1. Edit .env file with your API keys"
echo "2. Run: python3 shadowscan-standalone.py status"
echo "3. Run: python3 shadowscan-standalone.py workflow"
echo ""
echo "📖 Documentation:"
echo "   README_STANDALONE.md - Complete guide"
echo "   QUICK_SETUP.md - Quick start"
echo "   GOOGLE_DRIVE_INTEGRATION.md - Cloud setup"
EOF

chmod +x install-local.sh

# Create quick start script
cat > quick-start.sh << 'EOF'
#!/bin/bash
# ShadowScan Quick Start

echo "🚀 ShadowScan Quick Start"
echo "======================="

# Check if installed
if [ ! -f "shadowscan-standalone.py" ]; then
    echo "❌ ShadowScan not found! Please run install-local.sh first."
    exit 1
fi

# Check configuration
if [ ! -f ".env" ]; then
    echo "⚠️  Configuration not found. Creating from template..."
    cp .env.example .env
    echo "✅ Please edit .env with your API keys before continuing."
    exit 1
fi

# Test system
echo "🔍 Testing system..."
python3 shadowscan-standalone.py status

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ System ready!"
    echo ""
    echo "🎯 Quick commands:"
    echo "  python3 shadowscan-standalone.py workflow     # Complete test"
    echo "  python3 shadowscan-standalone.py screen -t 0xTarget    # Quick screening"
    echo "  python3 shadowscan-standalone.py attack analyze -t 0xTarget    # Attack analysis"
    echo ""
    echo "📖 For full guide: cat README_STANDALONE.md"
else
    echo ""
    echo "❌ System test failed. Please check installation."
fi
EOF

chmod +x quick-start.sh

# Create archive
echo "📦 Creating archive..."
cd ..
tar -czf "${ARCHIVE_NAME}" "$(basename "${BACKUP_DIR}")"

echo ""
echo -e "${GREEN}✅ Backup created successfully!${NC}"
echo ""
echo "📦 Archive location: ${BACKUP_DIR}/${ARCHIVE_NAME}"
echo "📂 Backup directory: ${BACKUP_DIR}"
echo ""
echo "📋 Contents:"
echo "   - Complete ShadowScan framework"
echo "   - Standalone runner scripts"
echo "   - Documentation"
echo "   - Local installer"
echo "   - Quick start script"
echo ""
echo "🚀 To deploy on another device:"
echo "   1. Copy ${ARCHIVE_NAME} to target device"
echo "   2. Extract: tar -xzf ${ARCHIVE_NAME}"
echo "   3. Run: cd $(basename "${BACKUP_DIR}") && ./install-local.sh"
echo "   4. Run: ./quick-start.sh"
echo ""
echo "📱 For Google Drive upload:"
echo "   - Upload ${ARCHIVE_NAME} to Google Drive"
echo "   - Download and extract on target device"
echo "   - Follow installation steps above"