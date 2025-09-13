#!/usr/bin/env python3
"""
ShadowScan Fix and Setup Script

This script fixes the ShadowScan installation by creating missing files
and ensuring proper module structure.
"""

import os
import sys
from pathlib import Path


def create_file(file_path: Path, content: str):
    """Create a file with given content."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"✅ Created: {file_path}")


def fix_shadowscan_structure():
    """Fix ShadowScan directory structure and missing files."""
    
    print("🔧 Fixing ShadowScan structure...")
    
    # Get the root directory
    root_dir = Path.cwd()
    shadowscan_dir = root_dir / "shadowscan"
    
    if not shadowscan_dir.exists():
        print("❌ shadowscan directory not found!")
        sys.exit(1)
    
    # 1. Fix shadowscan/__init__.py
    init_content = '''"""
ShadowScan - Universal Cyber Attack Test Engine
"""

import sys
import warnings
from pathlib import Path

__version__ = "1.0.0"
__author__ = "ShadowScan Team"
__email__ = "team@shadowscan.dev"
__license__ = "MIT"

# Minimum Python version check
MINIMUM_PYTHON_VERSION = (3, 8)

if sys.version_info < MINIMUM_PYTHON_VERSION:
    raise RuntimeError(
        f"ShadowScan requires Python {'.'.join(map(str, MINIMUM_PYTHON_VERSION))} "
        f"or higher. You are using Python {'.'.join(map(str, sys.version_info[:2]))}."
    )

def get_version():
    return __version__

# Initialize logging
import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())
'''
    
    # 2. Core module files
    core_init_content = '''"""
ShadowScan Core Module
"""

try:
    from .blockchain_scanner import BlockchainScanner
    from .report_generator import ReportGenerator
except ImportError as e:
    import warnings
    warnings.warn(f"Some core modules not available: {e}", ImportWarning)
    
    class BlockchainScanner:
        def __init__(self, *args, **kwargs):
            raise NotImplementedError("BlockchainScanner module not available")
    
    class ReportGenerator:
        def __init__(self, *args, **kwargs):
            raise NotImplementedError("ReportGenerator module not available")

__all__ = ["BlockchainScanner", "ReportGenerator"]
'''
    
    # 3. Utils module files
    utils_init_content = '''"""
ShadowScan Utilities Module
"""

try:
    from .logger import setup_logger
except ImportError:
    import logging
    
    def setup_logger(name="shadowscan", level=logging.INFO):
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger(name)

__all__ = ["setup_logger"]
'''

    logger_content = '''"""
ShadowScan Logger Configuration
"""

import logging
import sys
from typing import Optional

def setup_logger(name: str = "shadowscan", level: int = logging.INFO, format_string: Optional[str] = None) -> logging.Logger:
    if format_string is None:
        format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if logger.handlers:
        return logger
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    
    formatter = logging.Formatter(format_string)
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    
    return logger
'''

    # 4. Models module files
    models_init_content = '''"""
ShadowScan Data Models
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, Optional

class SeverityLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM" 
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class Finding:
    id: str
    severity: SeverityLevel
    title: str
    description: str
    evidence: Dict[str, Any]
    recommendation: str

__all__ = ["Finding", "SeverityLevel"]
'''

    # 5. Config module files  
    config_init_content = '''"""
ShadowScan Configuration Module
"""

DEFAULT_CONFIG = {
    "networks": {
        "ethereum": {
            "name": "Ethereum Mainnet",
            "chain_id": 1,
            "rpc_url": "https://eth.llamarpc.com"
        },
        "polygon": {
            "name": "Polygon", 
            "chain_id": 137,
            "rpc_url": "https://polygon.llamarpc.com"
        },
        "bsc": {
            "name": "BNB Smart Chain",
            "chain_id": 56,
            "rpc_url": "https://bsc.llamarpc.com"
        }
    }
}

def get_config():
    return DEFAULT_CONFIG.copy()

def get_network_config(network: str):
    config = get_config()
    return config["networks"].get(network, {})

__all__ = ["DEFAULT_CONFIG", "get_config", "get_network_config"]
'''

    # Create all the files
    files_to_create = [
        (shadowscan_dir / "__init__.py", init_content),
        (shadowscan_dir / "core" / "__init__.py", core_init_content),
        (shadowscan_dir / "utils" / "__init__.py", utils_init_content),
        (shadowscan_dir / "utils" / "logger.py", logger_content),
        (shadowscan_dir / "models" / "__init__.py", models_init_content),
        (shadowscan_dir / "config" / "__init__.py", config_init_content),
    ]
    
    for file_path, content in files_to_create:
        create_file(file_path, content)
    
    print("✅ All missing files created!")


def main():
    """Main function to fix ShadowScan installation."""
    
    print("🌑 ShadowScan Installation Fixer")
    print("="*50)
    
    try:
        # Fix structure
        fix_shadowscan_structure()
        
        print("\n🔧 Running pip install in editable mode...")
        import subprocess
        result = subprocess.run([sys.executable, "-m", "pip", "install", "-e", "."], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Installation successful!")
        else:
            print(f"❌ Installation failed: {result.stderr}")
            return False
        
        # Test the CLI
        print("\n🧪 Testing CLI installation...")
        test_result = subprocess.run([sys.executable, "-c", "import shadowscan.cli; print('CLI import successful')"], 
                                   capture_output=True, text=True)
        
        if test_result.returncode == 0:
            print("✅ CLI module is working!")
            print("\n🎉 ShadowScan is now ready to use!")
            print("Try running: shadowscan --help")
        else:
            print(f"❌ CLI test failed: {test_result.stderr}")
            return False
            
        return True
        
    except Exception as e:
        print(f"❌ Error during fix: {str(e)}")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
