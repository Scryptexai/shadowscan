#!/usr/bin/env python3
"""
Configuration Loader for GhostScan
TOML configuration management with dynamic loading and validation
"""

import toml
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from .database import database

class ConfigLoader:
    """Advanced configuration loader for GhostScan framework"""

    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)

        # Configuration files
        self.chains_config = self.config_dir / "chains.toml"
        self.scanners_config = self.config_dir / "scanners.toml"
        self.exploits_config = self.config_dir / "exploits.toml"

        # Cache loaded configurations
        self._loaded_configs = {}

        # Load all configurations
        self.load_all_configs()

    def load_toml_file(self, file_path: Path) -> Dict[str, Any]:
        """Load TOML configuration file with error handling"""
        try:
            if file_path.exists():
                with open(file_path, 'r') as f:
                    config = toml.load(f)
                    self._loaded_configs[file_path.name] = config
                    return config
            else:
                print(f"⚠️ Configuration file not found: {file_path}")
                return {}

        except Exception as e:
            print(f"⚠️ Error loading {file_path}: {e}")
            return {}

    def load_all_configs(self):
        """Load all configuration files"""
        # Load chains configuration
        self.chains_config_data = self.load_toml_file(self.chains_config)

        # Load scanners configuration
        self.scanners_config_data = self.load_toml_file(self.scanners_config)

        # Load exploits configuration
        self.exploits_config_data = self.load_toml_file(self.exploits_config)

        # Merge with database configuration
        self._merge_with_database()

    def _merge_with_database(self):
        """Merge loaded configurations with database settings"""
        # Get current configuration from database
        db_config = database.get_config()

        # Update chain configurations
        if "chains" in db_config:
            self._update_chains_from_database(db_config["chains"])

    def _update_chains_from_database(self, db_chains: List[Dict[str, Any]]):
        """Update chain configurations from database"""
        chains_section = self.chains_config_data.get("chains", [])

        # Add database chains to configuration
        for db_chain in db_chains:
            if not any(chain.get("name") == db_chain.get("name") for chain in chains_section):
                chains_section.append(db_chain)

        if chains_section:
            self.chains_config_data["chains"] = chains_section

    def get_chains(self, environment: str = None) -> List[Dict[str, Any]]:
        """Get chain configurations"""
        chains = self.chains_config_data.get("chains", [])

        if environment:
            chains = [chain for chain in chains if chain.get("environment") == environment]

        return chains

    def get_chain(self, chain_id: Union[str, int]) -> Optional[Dict[str, Any]]:
        """Get specific chain configuration"""
        chains = self.chains_config_data.get("chains", [])

        for chain in chains:
            if chain.get("chain_id") == chain_id or chain.get("name") == chain_id:
                return chain

        return None

    def get_scanners_config(self) -> Dict[str, Any]:
        """Get scanners configuration"""
        return self.scanners_config_data.get("scanners", {})

    def get_exploits_config(self) -> Dict[str, Any]:
        """Get exploits configuration"""
        return self.exploits_config_data.get("exploits", {})

    def get_environment_config(self, environment: str) -> Dict[str, Any]:
        """Get environment-specific configuration"""
        environments = self.chains_config_data.get("environments", {})
        return environments.get(environment, {})

    def get_supported_scanners(self, environment: str) -> List[str]:
        """Get list of supported scanners for an environment"""
        env_config = self.get_environment_config(environment)
        return env_config.get("supported_scanners", [])

    def get_supported_exploits(self, environment: str) -> List[str]:
        """Get list of supported exploits for an environment"""
        env_config = self.get_environment_config(environment)
        return env_config.get("supported_exploits", [])

    def validate_chain_config(self, chain_config: Dict[str, Any]) -> bool:
        """Validate chain configuration"""
        required_fields = ["name", "environment", "rpc_url", "chain_id"]

        for field in required_fields:
            if field not in chain_config:
                print(f"⚠️ Missing required field '{field}' in chain configuration")
                return False

        # Validate URL format
        if not chain_config["rpc_url"].startswith(("http://", "https://")):
            print(f"⚠️ Invalid RPC URL format: {chain_config['rpc_url']}")
            return False

        # Validate chain ID
        try:
            int(chain_config["chain_id"])
        except ValueError:
            print(f"⚠ Invalid chain ID: {chain_config['chain_id']}")
            return False

        return True

    def add_chain_config(self, chain_config: Dict[str, Any]) -> bool:
        """Add new chain configuration"""
        if not self.validate_chain_config(chain_config):
            return False

        # Add to TOML configuration
        if "chains" not in self.chains_config_data:
            self.chains_config_data["chains"] = []

        self.chains_config_data["chains"].append(chain_config)

        # Save configuration
        return self.save_config()

    def save_config(self) -> bool:
        """Save current configuration to files"""
        try:
            # Save chains configuration
            with open(self.chains_config, 'w') as f:
                toml.dump(self.chains_config_data, f)

            # Save scanners configuration
            with open(self.scanners_config, 'w') as f:
                toml.dump(self.scanners_config_data, f)

            # Save exploits configuration
            with open(self.exploits_config, 'w') as f:
                toml.dump(self.exploits_config_data, f)

            return True

        except Exception as e:
            print(f"⚠️ Error saving configuration: {e}")
            return False

    def get_default_attacker_config(self) -> Dict[str, Any]:
        """Get default attacker configuration"""
        return self.chains_config_data.get("attacker", {})

    def get_scanner_config(self, scanner_name: str) -> Dict[str, Any]:
        """Get specific scanner configuration"""
        scanners = self.get_scanners_config()
        return scanners.get(scanner_name, {})

    def get_exploit_config(self, exploit_name: str) -> Dict[str, Any]:
        """Get specific exploit configuration"""
        exploits = self.get_exploits_config()
        return exploits.get(exploit_name, {})

    def is_scanner_enabled(self, scanner_name: str) -> bool:
        """Check if a scanner is enabled"""
        scanner_config = self.get_scanner_config(scanner_name)
        return scanner_config.get("enabled", True)

    def is_exploit_enabled(self, exploit_name: str) -> bool:
        """Check if an exploit is enabled"""
        exploit_config = self.get_exploit_config(exploit_name)
        return exploit_config.get("enabled", True)

    def get_scanner_timeout(self, scanner_name: str) -> int:
        """Get scanner timeout configuration"""
        scanner_config = self.get_scanner_config(scanner_name)
        return scanner_config.get("timeout", 60)

    def get_exploit_timeout(self, exploit_name: str) -> int:
        """Get exploit timeout configuration"""
        exploit_config = self.get_exploit_config(exploit_name)
        return exploit_config.get("timeout", 120)

    def reload_configs(self):
        """Reload all configurations"""
        self._loaded_configs.clear()
        self.load_all_configs()

    def get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary"""
        return {
            "environments": list(self.chains_config_data.get("environments", {}).keys()),
            "chains": len(self.chains_config_data.get("chains", [])),
            "scanners": len(self.scanners_config_data.get("scanners", {})),
            "exploits": len(self.exploits_config_data.get("exploits", {})),
            "loaded_configs": list(self._loaded_configs.keys())
        }

# Global configuration loader instance
config_loader = ConfigLoader()

if __name__ == "__main__":
    # Test the configuration loader
    config = ConfigLoader()

    print("📋 Configuration Summary:")
    summary = config.get_config_summary()
    for key, value in summary.items():
        print(f"   {key}: {value}")

    print("\n🔗 Available Chains:")
    for chain in config.get_chains():
        print(f"   - {chain['name']} (ID: {chain['chain_id']})")

    print("\n🔍 Available Scanners:")
    scanners = config.get_scanners_config()
    for scanner_name in scanners.keys():
        enabled = config.is_scanner_enabled(scanner_name)
        print(f"   - {scanner_name}: {'✅' if enabled else '❌'}")

    print("\n💣 Available Exploits:")
    exploits = config.get_exploits_config()
    for exploit_name in exploits.keys():
        enabled = config.is_exploit_enabled(exploit_name)
        print(f"   - {exploit_name}: {'✅' if enabled else '❌'}")