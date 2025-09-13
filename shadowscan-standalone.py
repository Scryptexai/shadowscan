#!/usr/bin/env python3
# ShadowScan Standalone Runner
# Cross-platform executable script

import os
import sys
import subprocess
import platform
from pathlib import Path

# Add current directory to Python path
SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

def check_dependencies():
    """Check if all required dependencies are installed."""
    required_packages = [
        'web3', 'click', 'eth_account', 'requests', 
        'aiohttp', 'asyncio', 'json', 'pathlib'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("Please run: pip3 install --user " + " ".join(missing_packages))
        return False
    
    return True

def load_environment():
    """Load environment variables from .env file."""
    env_file = SCRIPT_DIR / '.env'
    if not env_file.exists():
        print("❌ .env file not found!")
        print("Please create .env file with your configuration.")
        return False
    
    # Load environment variables
    with open(env_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key] = value
    
    return True

def run_command(command_args):
    """Run ShadowScan command."""
    try:
        if command_args[0] in ['screen', 's']:
            # Run screening command
            from shadowscan.commands.screen import screen
            screen.main(standalone_mode=True, args=command_args[1:])
        
        elif command_args[0] == 'attack':
            # Run attack command
            from shadowscan.commands.attack_commands import attack_commands
            attack_commands.main(standalone_mode=True, args=command_args[1:])
        
        elif command_args[0] == 'workflow':
            # Run complete workflow test
            import test_modules_workflow
            asyncio.run(test_modules_workflow.main())
        
        elif command_args[0] == 'status':
            # Check system status
            check_system_status()
        
        else:
            show_help()
    
    except Exception as e:
        print(f"❌ Error running command: {e}")
        return False
    
    return True

def check_system_status():
    """Check system status and dependencies."""
    print("🔍 ShadowScan System Status")
    print("=" * 30)
    
    # Check Python version
    python_version = sys.version_info
    print(f"🐍 Python: {python_version.major}.{python_version.minor}.{python_version.micro}")
    
    # Check dependencies
    if check_dependencies():
        print("✅ Dependencies: OK")
    else:
        print("❌ Dependencies: Missing")
    
    # Check environment
    if load_environment():
        print("✅ Configuration: OK")
        
        # Show key config
        target = os.environ.get('TARGET_CONTRACT', 'Not set')
        chain = os.environ.get('CHAIN_ID', 'Not set')
        print(f"🎯 Target: {target}")
        print(f"⛓️  Chain: {chain}")
    else:
        print("❌ Configuration: Missing")
    
    # Check modules
    try:
        from shadowscan.core.pipeline.screening_engine import ScreeningEngine
        from shadowscan.core.attack.attack_framework import AttackFramework
        print("✅ Modules: OK")
    except ImportError as e:
        print(f"❌ Modules: Error - {e}")
    
    print("\n📊 System ready for operation" if all([
        check_dependencies(),
        Path(SCRIPT_DIR / '.env').exists()
    ]) else "⚠️  System needs configuration")

def show_help():
    """Show help information."""
    print("""
🔍 ShadowScan Standalone Runner

Usage: python3 shadowscan-standalone.py [command] [options]

Commands:
  screen|s [options]     - Run contract screening
  attack [subcommand]    - Run attack analysis/execution
  workflow              - Run complete workflow test
  status                - Check system status
  help                  - Show this help

Screening Examples:
  python3 shadowscan-standalone.py screen -t 0xTarget -c eth
  python3 shadowscan-standalone.py s -t 0xTarget -c eth -m f -d f

Attack Examples:
  python3 shadowscan-standalone.py attack analyze -t 0xTarget -c eth
  python3 shadowscan-standalone.py attack execute -t 0xTarget -m reentrancy -e fork

Quick Start:
  1. Edit .env file with your API keys
  2. Run: python3 shadowscan-standalone.py status
  3. Run: python3 shadowscan-standalone.py workflow
""")

def main():
    """Main entry point."""
    print("🔍 ShadowScan Standalone Runner")
    print("=" * 30)
    
    if len(sys.argv) < 2:
        show_help()
        return
    
    command = sys.argv[1:]
    
    # Check if we're in the right directory
    if not (SCRIPT_DIR / 'shadowscan').exists():
        print("❌ ShadowScan directory not found!")
        print("Please run this script from the ShadowScan installation directory.")
        return
    
    # Run the command
    success = run_command(command)
    
    if success:
        print("\n✅ Command completed successfully!")
    else:
        print("\n❌ Command failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()