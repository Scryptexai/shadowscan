#!/usr/bin/env python3
"""
GhostScan - Comprehensive Blockchain Vulnerability Scanner
Entry point for the GhostScan framework
"""

import os
import sys
import argparse
from pathlib import Path

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(__file__))

try:
    from core.cli import GhostScanCLI
    from core.database import database
    from core.config_loader import config_loader
    from core.blockchain import blockchain_interface
except ImportError as e:
    print(f"❌ Error importing required modules: {e}")
    print("Please ensure all dependencies are installed:")
    print("pip install toml web3")
    sys.exit(1)

def setup_environment():
    """Setup environment and configuration"""
    # Create necessary directories
    directories = ['config', 'database', 'logs']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)

    # Load configuration
    try:
        config_loader.reload_configs()
        print("✅ Configuration loaded successfully")
    except Exception as e:
        print(f"⚠️ Warning: Could not load configuration: {e}")

    # Initialize database
    try:
        database.clear_cache()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"⚠️ Warning: Could not initialize database: {e}")

def check_dependencies():
    """Check if all required dependencies are installed"""
    required_packages = ['web3', 'toml']
    missing_packages = []

    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        print(f"❌ Missing required packages: {', '.join(missing_packages)}")
        print("Install them with:")
        print(f"pip install {' '.join(missing_packages)}")
        return False

    return True

def install_command():
    """Install GhostScan dependencies"""
    print("🔧 Installing GhostScan dependencies...")
    print("This will install required packages for GhostScan")
    print()

    import subprocess
    import sys

    packages = ['web3', 'toml']
    failed_packages = []

    for package in packages:
        try:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            print(f"✅ {package} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {package}: {e}")
            failed_packages.append(package)

    if failed_packages:
        print(f"\n⚠️ Failed to install: {', '.join(failed_packages)}")
        return False
    else:
        print("\n✅ All dependencies installed successfully!")
        print("You can now run: python main.py")
        return True

def version_command():
    """Show version information"""
    print("🔐 GhostScan - Comprehensive Blockchain Vulnerability Scanner")
    print("Version: 1.0.0")
    print("Author: Ghost Security Research")
    print("License: MIT")
    print()
    print("Features:")
    print("- Multi-chain support (Tenderly, Mainnet, Hardhat)")
    print("- Comprehensive vulnerability scanning")
    print("- Real blockchain execution")
    print("- Database management")
    print("- CLI interface")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='GhostScan - Comprehensive Blockchain Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Run GhostScan CLI
  python main.py --install         # Install dependencies
  python main.py --version          # Show version info
  python main.py --init-config      # Initialize configuration
        """
    )

    parser.add_argument('--install', action='store_true',
                       help='Install required dependencies')
    parser.add_argument('--version', action='version', version='GhostScan 1.0.0')
    parser.add_argument('--init-config', action='store_true',
                       help='Initialize configuration files')
    parser.add_argument('--setup-only', action='store_true',
                       help='Only setup environment and exit')

    args = parser.parse_args()

    # Handle install command
    if args.install:
        success = install_command()
        sys.exit(0 if success else 1)

    # Show version
    if hasattr(args, 'version') and args.version:
        version_command()
        sys.exit(0)

    # Initialize configuration
    if args.init_config:
        setup_environment()
        print("✅ Configuration initialized")
        print("You can now run: python main.py")
        sys.exit(0)

    # Setup environment
    setup_environment()

    # Check dependencies
    if not check_dependencies():
        print("\n💡 Tip: Run 'python main.py --install' to install dependencies")
        sys.exit(1)

    # Run CLI if not setup only
    if not args.setup_only:
        try:
            cli = GhostScanCLI()
            cli.run()
        except KeyboardInterrupt:
            print("\n👋 Thank you for using GhostScan!")
        except Exception as e:
            print(f"❌ Error running GhostScan: {e}")
            sys.exit(1)
    else:
        print("✅ GhostScan environment setup completed")

if __name__ == "__main__":
    main()