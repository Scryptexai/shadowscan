# ShadowScan Quick Deployment Package

## 📦 What's Included

- ✅ **Complete ShadowScan Framework** (standalone edition)
- ✅ **Cross-platform Scripts** (Linux, Windows, macOS, Android)
- ✅ **Auto-installer** (no venv required)
- ✅ **Google Drive Integration** (access from anywhere)
- ✅ **Comprehensive Documentation**

## 🚀 3-Step Setup

### **Step 1: Download**
- Download this entire folder
- OR clone: `git clone [repository-url]`

### **Step 2: Install**
```bash
# Linux/macOS
chmod +x install-standalone.sh
./install-standalone.sh

# Windows
# Double-click install-standalone.sh or run in Git Bash

# Manual (all platforms)
pip3 install --user -r requirements.txt
```

### **Step 3: Configure**
```bash
# Copy and edit configuration
cp .env.example .env
# Edit .env with your API keys

# Test installation
python3 shadowscan-standalone.py status
```

## 🎯 Quick Commands

```bash
# System check
python3 shadowscan-standalone.py status

# Complete workflow test
python3 shadowscan-standalone.py workflow

# Quick screening
python3 shadowscan-standalone.py screen -t 0xTarget -c eth

# Attack analysis  
python3 shadowscan-standalone.py attack analyze -t 0xTarget -c eth
```

## 📱 Platform Support

| Platform | Method | Status |
|----------|--------|--------|
| Linux | `./install-standalone.sh` | ✅ |
| Windows | `shadowscan-windows.bat` | ✅ |
| macOS | Manual install | ✅ |
| Android | Termux | ✅ |
| ChromeOS | Linux env | ✅ |
| iOS | iSH shell | ✅ |

## 📁 Google Drive Setup

1. Upload entire folder to Google Drive
2. Access from any device
3. Sync reports automatically
4. Collaborate with team

📖 **Full Guide**: `GOOGLE_DRIVE_INTEGRATION.md`

## 🛡️ Security Features

- 🔒 Fork environment testing (safe)
- 🔒 Dry-run mode (simulation only)
- 🔒 Configurable API keys
- 🔒 Private key encryption
- 🔒 Audit trail for all operations

## 📞 Need Help?

- 📖 Documentation: `README_STANDALONE.md`
- 🔧 Troubleshooting: Check `python3 shadowscan-standalone.py status`
- 🐛 Report Issues: GitHub Issues
- 💬 Community: Discord server

---

**🎉 Ready to use in under 5 minutes!**