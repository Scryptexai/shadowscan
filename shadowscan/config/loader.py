# shadowscan/config/loader.py
import os
from dotenv import load_dotenv
from pathlib import Path
from .schemas import validate_config
from typing import Dict, Any, Optional

class ConfigLoader:
    """Sistem konfigurasi profesional dengan validasi ketat"""
    
    DEFAULT_CONFIG = {
        'MAX_THREADS': 5,
        'RATE_LIMIT_DELAY': 1.0,
        'TIMEOUT': 30,
        'STEALTH_MODE': True,
        'REPORT_FORMAT': 'pdf',
        'REPORT_DIR': 'reports'
    }

    def __init__(self, env_file: Optional[str] = None):
        self.env_file = env_file or '.env'
        self.config = self._load_config()
        self._validate_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load and parse configuration with defaults"""
        load_dotenv(self.env_file)
        
        config = {}
        
        # Target configuration
        config['TARGET_TYPE'] = os.getenv('TARGET_TYPE', 'blockchain').lower()
        config['TARGET_URL'] = os.getenv('TARGET_URL')
        config['TARGET_CONTRACT'] = os.getenv('TARGET_CONTRACT')
        
        # Blockchain configuration
        config['CHAIN_ID'] = int(os.getenv('CHAIN_ID', '1'))
        config['TENDERLY_RPC'] = os.getenv('TENDERLY_RPC')
        config['ETHERSCAN_API_KEY'] = os.getenv('ETHERSCAN_API_KEY')
        
        # Attacker configuration
        config['PRIVATE_KEY'] = os.getenv('PRIVATE_KEY')
        config['ATTACKER_ADDRESS'] = os.getenv('ATTACKER_ADDRESS')
        
        # Engine configuration
        config['MAX_THREADS'] = int(os.getenv('MAX_THREADS', str(self.DEFAULT_CONFIG['MAX_THREADS'])))
        config['RATE_LIMIT_DELAY'] = float(os.getenv('RATE_LIMIT_DELAY', str(self.DEFAULT_CONFIG['RATE_LIMIT_DELAY'])))
        config['TIMEOUT'] = int(os.getenv('TIMEOUT', str(self.DEFAULT_CONFIG['TIMEOUT'])))
        config['STEALTH_MODE'] = os.getenv('STEALTH_MODE', str(self.DEFAULT_CONFIG['STEALTH_MODE'])).lower() == 'true'
        
        # Reporting configuration
        config['REPORT_FORMAT'] = os.getenv('REPORT_FORMAT', self.DEFAULT_CONFIG['REPORT_FORMAT'])
        config['REPORT_DIR'] = os.getenv('REPORT_DIR', self.DEFAULT_CONFIG['REPORT_DIR'])
        
        return config

    def _validate_config(self) -> None:
        """Validasi konfigurasi dengan schema ketat"""
        errors = validate_config(self.config)
        if errors:
            error_msg = "Konfigurasi tidak valid:\n" + "\n".join(f"- {err}" for err in errors)
            raise ValueError(error_msg)

    def get(self, key: str, default: Any = None) -> Any:
        """Akses konfigurasi dengan aman"""
        return self.config.get(key, default)

    def all(self) -> Dict[str, Any]:
        """Dapatkan semua konfigurasi"""
        return self.config.copy()

    @classmethod
    def from_env(cls, env_file: Optional[str] = None) -> 'ConfigLoader':
        """Factory method untuk inisialisasi"""
        return cls(env_file)


def load_config(env_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Simple function to load configuration.
    
    Args:
        env_file: Path to .env file
        
    Returns:
        Configuration dictionary
    """
    loader = ConfigLoader(env_file)
    return loader.all()
