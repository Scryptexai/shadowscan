# 📁 Google Drive Integration Guide for ShadowScan Standalone

## 🚀 Setup Google Drive untuk ShadowScan

### **Step 1: Upload ke Google Drive**

#### **Metode A: Via Web Interface**
1. **Buka** [drive.google.com](https://drive.google.com)
2. **Buat folder baru**: `ShadowScan-Standalone`
3. **Upload semua file**:
   - `shadowscan/` (entire directory)
   - `shadowscan-standalone.py`
   - `shadowscan-windows.bat`
   - `install-standalone.sh`
   - `requirements.txt`
   - `README_STANDALONE.md`
   - `.env.example`

#### **Metode B: Google Drive Desktop**
1. **Install** Google Drive Desktop
2. **Sync** folder ShadowScan lokal ke Google Drive
3. **Akses** dari device manapun via Google Drive

### **Step 2: Struktur Folder di Google Drive**

```
Google Drive/
└── ShadowScan-Standalone/
    ├── shadowscan/
    │   ├── core/
    │   ├── commands/
    │   ├── collectors/
    │   ├── detectors/
    │   └── utils/
    ├── shadowscan-standalone.py
    ├── shadowscan-windows.bat
    ├── install-standalone.sh
    ├── requirements.txt
    ├── README_STANDALONE.md
    ├── .env.example
    └── quick-test
```

## 💻 **Download & Install di Device Baru**

### **Windows**

#### **Option 1: Direct Download**
```cmd
REM 1. Download folder dari Google Drive
REM 2. Ekstrak ke folder: C:\ShadowScan

REM 3. Install Python
REM Download dari: https://python.org

REM 4. Install dependencies
cd C:\ShadowScan
pip install --user -r requirements.txt

REM 5. Buat .env file
copy .env.example .env
REM Edit .env dengan notepad

REM 6. Test instalasi
shadowscan-windows.bat status
```

#### **Option 2: Google Drive Desktop**
```cmd
REM 1. Install Google Drive Desktop
REM 2. Sync ShadowScan folder
REM 3. Buka folder synced lokal

REM 4. Install Python dan dependencies
pip install --user -r requirements.txt

REM 5. Test
python shadowscan-standalone.py status
```

### **Linux/macOS**

#### **Option 1: Command Line Download**
```bash
# 1. Install Google Drive CLI (opsional)
# Atau download via web interface

# 2. Download dan ekstrak
cd ~
wget -O shadowscan-standalone.zip "GOOGLE_DRIVE_DOWNLOAD_LINK"
unzip shadowscan-standalone.zip
cd shadowscan-standalone

# 3. Install dependencies
pip3 install --user -r requirements.txt

# 4. Setup configuration
cp .env.example .env
nano .env

# 5. Make executable
chmod +x shadowscan-standalone.py

# 6. Test
python3 shadowscan-standalone.py status
```

#### **Option 2: Google Drive Desktop (Linux)**
```bash
# 1. Install Google Drive Desktop untuk Linux
# Atau gunakan OverGrive (third-party)

# 2. Setelah sync, navigasi ke folder
cd ~/Google\ Drive/ShadowScan-Standalone

# 3. Install dependencies
pip3 install --user -r requirements.txt

# 4. Setup dan test
python3 shadowscan-standalone.py status
```

### **Android (Termux)**

#### **Setup ShadowScan di Android**
```bash
# 1. Install Termux dari F-Droid
pkg update && pkg upgrade

# 2. Install Python dan dependencies
pkg install python python-pip git

# 3. Download dari Google Drive
# Gunakan browser untuk download, lalu pindah ke Termux

# 4. Install ShadowScan
cd /data/data/com.termux/files/home
unzip /sdcard/Download/shadowscan-standalone.zip
cd shadowscan-standalone

# 5. Install packages
pip install --user -r requirements.txt

# 6. Setup dan test
python shadowscan-standalone.py status
```

## 🔧 **Konfigurasi Cross-Device**

### **Shared Configuration File**
```env
# .env - simpan di Google Drive untuk shared config

# ======================================
# SHADOWSCAN SHARED CONFIGURATION
# ======================================

# Device-specific settings (gunakan prefix)
DEVICE_NAME=MyLaptop
DEVICE_TYPE=laptop

# Common settings
TARGET_CONTRACT=0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3
CHAIN_ID=1

# RPC URLs (gunakan environment-specific jika perlu)
RPC_MAINNET=https://virtual.mainnet.eu.rpc.tenderly.co/your_rpc
RPC_TESTNET=https://virtual.testnet.eu.rpc.tenderly.co/your_rpc

# API Keys (simpan di device masing-masing untuk security)
# ETHERSCAN_API_KEY=device_specific_key
```

### **Device-Specific Overrides**
```bash
# Buat file .env.local untuk override per-device
# Jangan simpan di Google Drive (add ke .gitignore)

# .env.local
ETHERSCAN_API_KEY=your_personal_api_key
PRIVATE_KEY=your_personal_private_key
DEVICE_NAME=WorkLaptop
```

## 🔄 **Sync Reports ke Google Drive**

### **Automatic Report Sync**
```bash
# Buat script untuk sync reports
cat > sync-reports.sh << 'EOF'
#!/bin/bash
# Sync reports to Google Drive

REPORT_DIR="reports"
GDRIVE_DIR="$HOME/Google Drive/ShadowScan-Reports"

# Create reports directory if not exists
mkdir -p "$REPORT_DIR"

# Copy to Google Drive if available
if [ -d "$GDRIVE_DIR" ]; then
    echo "📤 Syncing reports to Google Drive..."
    cp -r "$REPORT_DIR"/* "$GDRIVE_DIR/" 2>/dev/null || true
    echo "✅ Reports synced successfully!"
else
    echo "⚠️  Google Drive not found. Reports saved locally."
fi
EOF

chmod +x sync-reports.sh
```

### **Manual Sync Commands**
```bash
# Sync reports after analysis
./sync-reports.sh

# Atau sync manual
cp -r reports/ ~/Google\ Drive/ShadowScan-Reports/
```

## 📱 **Mobile Setup Guide**

### **iOS (iSH Shell)**
```bash
# 1. Install iSH dari App Store
# 2. Install Python
apk add python3 py3-pip

# 3. Download ShadowScan via browser
# 4. Extract dan install
pip install --user -r requirements.txt

# 5. Test
python3 shadowscan-standalone.py status
```

### **ChromeOS (Linux Environment)**
```bash
# 1. Enable Linux Development Environment
# 2. Open Terminal

# 3. Download dari Google Drive
# 4. Install dependencies
sudo apt update
sudo apt install python3 python3-pip

pip3 install --user -r requirements.txt

# 5. Test
python3 shadowscan-standalone.py status
```

## 🛡️ **Security Best Practices**

### **Google Drive Security**
1. **Jangan simpan private keys** di Google Drive
2. **Gunakan .env.local** untuk sensitive data
3. **Set sharing permissions** ke "Private" atau "Restricted"
4. **Enable two-factor authentication** untuk Google account
5. **Regular audit** siapa yang memiliki akses

### **Device Security**
```bash
# Buat file permissions script
cat > secure-setup.sh << 'EOF'
#!/bin/bash
# Secure ShadowScan installation

echo "🔒 Securing ShadowScan installation..."

# Set proper permissions
chmod 700 .env*
chmod 600 .env.local
chmod 700 shadowscan-standalone.py
chmod 700 shadowscan-windows.bat

# Remove sensitive files from Git tracking
echo ".env.local" >> .gitignore
echo "*.key" >> .gitignore
echo "*.pem" >> .gitignore

echo "✅ Security setup completed!"
EOF

chmod +x secure-setup.sh
./secure-setup.sh
```

## 🚨 **Troubleshooting Google Drive Issues**

### **Common Issues & Solutions**

#### **Sync Issues**
```bash
# Check Google Drive status
# Linux: Check systemd service
systemctl --user status google-drive

# Restart Google Drive
systemctl --user restart google-drive

# Check disk space
df -h ~/Google\ Drive
```

#### **Permission Issues**
```bash
# Fix file permissions
find ~/Google\ Drive/ShadowScan-Standalone -type f -exec chmod 644 {} \;
find ~/Google\ Drive/ShadowScan-Standalone -type d -exec chmod 755 {} \;

# Make scripts executable
chmod +x ~/Google\ Drive/ShadowScan-Standalone/*.sh
chmod +x ~/Google\ Drive/ShadowScan-Standalone/*.py
```

#### **Network Issues**
```bash
# Test internet connectivity
ping drive.google.com

# Test Google Drive API
curl -I https://www.googleapis.com/drive/v3/files

# Check proxy settings if behind corporate network
echo $HTTP_PROXY
echo $HTTPS_PROXY
```

## 📊 **Backup Strategy**

### **Automated Backup Script**
```bash
cat > backup-to-gdrive.sh << 'EOF'
#!/bin/bash
# Backup ShadowScan data to Google Drive

BACKUP_DIR="$HOME/ShadowScan-Backup-$(date +%Y%m%d)"
GDRIVE_DIR="$HOME/Google Drive/ShadowScan-Backups"

echo "💾 Creating backup..."

# Create backup
mkdir -p "$BACKUP_DIR"
cp -r shadowscan/ "$BACKUP_DIR/"
cp *.py "$BACKUP_DIR/"
cp *.bat "$BACKUP_DIR/"
cp *.sh "$BACKUP_DIR/"
cp requirements.txt "$BACKUP_DIR/"

# Copy to Google Drive
if [ -d "$GDRIVE_DIR" ]; then
    cp -r "$BACKUP_DIR" "$GDRIVE_DIR/"
    echo "✅ Backup completed: $BACKUP_DIR"
else
    echo "⚠️  Google Drive not accessible. Backup saved locally."
fi
EOF

chmod +x backup-to-gdrive.sh
```

### **Schedule Regular Backups**
```bash
# Add to crontab untuk automatic backup
# Edit crontab
crontab -e

# Add line untuk backup harian jam 2 pagi
0 2 * * * /path/to/backup-to-gdrive.sh
```

## 🎯 **Usage Workflow di Multiple Devices**

### **Development Workflow**
```bash
# Di laptop utama:
# 1. Develop dan test
python3 shadowscan-standalone.py workflow

# 2. Sync ke Google Drive
./sync-reports.sh

# Di device lain:
# 3. Download updates dari Google Drive
# 4. Test di device baru
python3 shadowscan-standalone.py status

# 5. Run analysis
python3 shadowscan-standalone.py screen -t 0xTarget
```

### **Collaboration Workflow**
```bash
# Team folder structure di Google Drive:
Google Drive/
└── Team-ShadowScan/
    ├── config/           # Shared configuration
    ├── reports/          # Collective reports
    ├── targets/          # Target lists
    └── devices/          # Device-specific setups
        ├── laptop-john/
        ├── desktop-mary/
        └── mobile-alex/
```

---

**🎉 Selamat! ShadowScan sekarang dapat diakses dari berbagai device via Google Drive!**

*Remember: Keep your private keys secure and never share sensitive configuration files!*