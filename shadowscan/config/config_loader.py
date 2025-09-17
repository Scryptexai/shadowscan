# shadowscan/config/config_loader.py
import os
from pathlib import Path
from typing import Dict, Any, List

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
            # Target Configuration
            "TARGET_TYPE": os.getenv("TARGET_TYPE", "blockchain"),
            "TARGET_URL": os.getenv("TARGET_URL", ""),
            "TARGET_CONTRACT": os.getenv("TARGET_CONTRACT", ""),
            
            # Blockchain Configuration
            "CHAIN_ID": int(os.getenv("CHAIN_ID", 1)),
            "TICKER": os.getenv("TICKER", "ETH"),
            
            # RPC Configuration
            "RPC_URLS": {
                "ETH": os.getenv("ETH_RPC_URL", "https://eth.llamarpc.com"),
                "MATIC": os.getenv("MATIC_RPC_URL", "https://polygon.llamarpc.com"),
                "BNB": os.getenv("BNB_RPC_URL", "https://bsc-dataseed.binance.org"),
                "ARB": os.getenv("ARB_RPC_URL", "https://arbitrum.llamarpc.com"),
                "BASE": os.getenv("BASE_RPC_URL", "https://base.llamarpc.com"),
                "OPT": os.getenv("OPT_RPC_URL", "https://optimism.llamarpc.com"),
                "AVAX": os.getenv("AVAX_RPC_URL", "https://avalanche.llamarpc.com"),
                "FTM": os.getenv("FTM_RPC_URL", "https://fantom.llamarpc.com"),
            },
            
            # Chain IDs
            "CHAIN_IDS": {
                "ETH": int(os.getenv("ETH_CHAIN_ID", 1)),
                "MATIC": int(os.getenv("MATIC_CHAIN_ID", 137)),
                "BNB": int(os.getenv("BNB_CHAIN_ID", 56)),
                "ARB": int(os.getenv("ARB_CHAIN_ID", 42161)),
                "BASE": int(os.getenv("BASE_CHAIN_ID", 8453)),
                "OPT": int(os.getenv("OPT_CHAIN_ID", 10)),
                "AVAX": int(os.getenv("AVAX_CHAIN_ID", 43114)),
                "FTM": int(os.getenv("FTM_CHAIN_ID", 250)),
            },
            
            # Fork Configuration
            "TENDERLY_RPC": os.getenv("TENDERLY_RPC", ""),
            "TENDERLY_ACCOUNT_SLUG": os.getenv("TENDERLY_ACCOUNT_SLUG", ""),
            "TENDERLY_PROJECT_SLUG": os.getenv("TENDERLY_PROJECT_SLUG", ""),
            "TENDERLY_ACCESS_KEY": os.getenv("TENDERLY_ACCESS_KEY", ""),
            
            # API Keys
            "API_KEYS": {
                "ETHERSCAN": os.getenv("ETHERSCAN_API_KEY", ""),
                "INFURA": os.getenv("INFURA_API_KEY", ""),
                "POLYGONSCAN": os.getenv("POLYGONSCAN_API_KEY", ""),
                "BSCSCAN": os.getenv("BSCSCAN_API_KEY", ""),
                "ARBISCAN": os.getenv("ARBISCAN_API_KEY", ""),
            },
            
            # Attacker Configuration
            "PRIVATE_KEY": os.getenv("PRIVATE_KEY", ""),
            "ATTACKER_ADDRESS": os.getenv("ATTACKER_ADDRESS", ""),
            
            # Engine Configuration
            "MAX_THREADS": int(os.getenv("MAX_THREADS", 10)),
            "RATE_LIMIT_DELAY": float(os.getenv("RATE_LIMIT_DELAY", 1.5)),
            "TIMEOUT": int(os.getenv("TIMEOUT", 30)),
            "STEALTH_MODE": os.getenv("STEALTH_MODE", "true").lower() == "true",
            
            # Reporting Configuration
            "REPORT_FORMAT": os.getenv("REPORT_FORMAT", "pdf"),
            "REPORT_DIR": os.getenv("REPORT_DIR", "reports"),
            
            # Vulnerability Scanning Configuration
            "VULN_TYPES": self._parse_list(os.getenv("VULN_TYPES", "reentrancy,flashloan,oracle_manipulation,access_control,integer_overflow,underflow,front_running,sandwich_attack,fee_manipulation,price_oracle,liquidity_pool,token_approval,governance_attack,bridge_exploit,nft_marketplace,staking_vulnerability,vesting_contract,multisig_weakness,timestamp_dependency,randomness_failure")),
            "SCAN_INTENSITY": int(os.getenv("SCAN_INTENSITY", 7)),
            
            # AI Configuration
            "ZHIPU_API_KEY": os.getenv("ZHIPU_API_KEY", ""),
            
            # Advanced Configuration
            "ENABLE_DEEP_SCAN": os.getenv("ENABLE_DEEP_SCAN", "true").lower() == "true",
            "ENABLE_SYMBOLIC_EXECUTION": os.getenv("ENABLE_SYMBOLIC_EXECUTION", "true").lower() == "true",
            "ENABLE_TAINT_ANALYSIS": os.getenv("ENABLE_TAINT_ANALYSIS", "true").lower() == "true",
            "ENABLE_FORMAL_VERIFICATION": os.getenv("ENABLE_FORMAL_VERIFICATION", "true").lower() == "true",
            "MAX_CONCURRENT_SCANS": int(os.getenv("MAX_CONCURRENT_SCANS", 5)),
            "SCAN_TIMEOUT_SECONDS": int(os.getenv("SCAN_TIMEOUT_SECONDS", 300)),
        }
        return config
    
    def _parse_list(self, value: str) -> List[str]:
        """Parse comma-separated list from environment variable."""
        if not value:
            return []
        return [item.strip() for item in value.split(",") if item.strip()]
    
    def get_rpc_url(self, ticker: str = None) -> str:
        """Get RPC URL for specified ticker."""
        ticker = ticker or self.config["TICKER"]
        return self.config["RPC_URLS"].get(ticker.upper(), "https://eth.llamarpc.com")
    
    def get_chain_id(self, ticker: str = None) -> int:
        """Get chain ID for specified ticker."""
        ticker = ticker or self.config["TICKER"]
        return self.config["CHAIN_IDS"].get(ticker.upper(), 1)
    
    def get_api_key(self, service: str) -> str:
        """Get API key for specified service."""
        return self.config["API_KEYS"].get(service.upper(), "")
    
    def get_vulnerability_types(self) -> List[str]:
        """Get list of vulnerability types to scan for."""
        return self.config["VULN_TYPES"]

    def get(self, key: str, default=None):
        return self.config.get(key, default)

# Global config instance
config_loader = ConfigLoader()
CONFIG = config_loader.config
