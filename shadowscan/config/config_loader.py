# shadowscan/config/config_loader.py
import os
from pathlib import Path
from typing import Dict, Any

class ConfigLoader:
    """Centralized configuration loader for ShadowScan."""

    def __init__(self):
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from .env file and environment variables."""
        # Try to load from .env file
        env_path = Path(__file__).parent.parent.parent / ".env"  # ~/shadowscan/.env
        if env_path.exists():
            from dotenv import load_dotenv
            load_dotenv(env_path)

        # Load all config from environment
        config = {
            "TARGET_TYPE": os.getenv("TARGET_TYPE", "blockchain"),
            "TARGET_URL": os.getenv("TARGET_URL", ""),
            "TARGET_CONTRACT": os.getenv("TARGET_CONTRACT", ""),
            "CHAIN_ID": int(os.getenv("CHAIN_ID", 1)),
            "TENDERLY_RPC": os.getenv("TENDERLY_RPC", ""),
            "ETHERSCAN_API_KEY": os.getenv("ETHERSCAN_API_KEY", ""),
            "TENDERLY_ACCESS_KEY": os.getenv("TENDERLY_ACCESS_KEY", ""),
            "TENDERLY_PROJECT_ID": os.getenv("TENDERLY_PROJECT_ID", ""),
            "PRIVATE_KEY": os.getenv("PRIVATE_KEY", ""),
            "ATTACKER_ADDRESS": os.getenv("ATTACKER_ADDRESS", ""),
            "MAX_THREADS": int(os.getenv("MAX_THREADS", 10)),
            "REPORT_FORMAT": os.getenv("REPORT_FORMAT", "pdf"),
            "REPORT_DIR": os.getenv("REPORT_DIR", "reports"),
        }
        return config

    def get(self, key: str, default=None):
        return self.config.get(key, default)

# Global config instance
config_loader = ConfigLoader()
CONFIG = config_loader.config
