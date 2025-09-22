#!/usr/bin/env python3
"""
Configuration Manager for Modular System
Handles configuration loading, validation, and environment management
"""

import json
import os
import yaml
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from pathlib import Path
import copy
from datetime import datetime

@dataclass
class ConfigSchema:
    """Configuration schema definition"""
    name: str
    version: str
    description: str
    fields: Dict[str, Any]
    required_fields: List[str]
    validation_rules: Dict[str, Any] = field(default_factory=dict)
    environment_mappings: Dict[str, str] = field(default_factory=dict)

class ConfigManager:
    """Centralized configuration management with validation and environment support"""

    def __init__(self, config_file: str = "config.yaml", environment: str = "development"):
        self.config_file = config_file
        self.environment = environment
        self.config = {}
        self.schema = None
        self.logger = logging.getLogger("ConfigManager")

        # Configuration sources in priority order
        self.sources = [
            "defaults",  # Default values
            "config_file",  # YAML/JSON config file
            "environment",  # Environment variables
            "command_line"  # Command line arguments (if supported)
        ]

        self._load_configuration()

    def _load_configuration(self):
        """Load configuration from all sources with proper precedence"""
        self.config = {}

        # Start with defaults
        self.config.update(self._get_default_config())

        # Load from config file
        if os.path.exists(self.config_file):
            file_config = self._load_from_file()
            self._merge_config(self.config, file_config)

        # Override with environment variables
        env_config = self._load_from_environment()
        self._merge_config(self.config, env_config)

        # Apply environment-specific settings
        self._apply_environment_settings()

        # Validate configuration
        self._validate_configuration()

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration values"""
        return {
            "system": {
                "name": "ShadowScan Modular System",
                "version": "1.0.0",
                "environment": self.environment,
                "debug_mode": False,
                "log_level": "INFO",
                "data_directory": "./data",
                "max_workers": 4,
                "timeout": 30
            },
            "database": {
                "type": "sqlite",
                "path": "./data/scanning.db",
                "backup_enabled": True,
                "backup_interval": 3600
            },
            "network": {
                "max_retries": 3,
                "retry_delay": 1,
                "timeout": 30,
                "user_agent": "ShadowScan-Scanner/1.0"
            },
            "scanning": {
                "phase_1": {
                    "enabled": True,
                    "max_protocols": 1000,
                    "categories": ["DEX", "LENDING", "YIELD", "BRIDGE", "NFT", "AGGREGATOR"]
                },
                "phase_2": {
                    "enabled": True,
                    "export_formats": ["json", "sqlite"]
                },
                "phase_3": {
                    "enabled": True,
                    "max_contracts": 5000
                }
            },
            "error_handling": {
                "enabled": True,
                "max_error_logs": 1000,
                "auto_recovery": True,
                "alert_thresholds": {
                    "critical": 1,
                    "high": 5,
                    "medium": 10
                }
            },
            "logging": {
                "enabled": True,
                "level": "INFO",
                "file_path": "./logs/system.log",
                "max_size": "10MB",
                "backup_count": 5
            }
        }

    def _load_from_file(self) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                if self.config_file.endswith('.yaml') or self.config_file.endswith('.yml'):
                    return yaml.safe_load(f) or {}
                else:
                    return json.load(f) or {}
        except Exception as e:
            self.logger.error(f"Failed to load config file {self.config_file}: {e}")
            return {}

    def _load_from_environment(self) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        env_config = {}

        # Environment variable mapping
        env_mappings = {
            "SHADOWSCAN_DEBUG": "system.debug_mode",
            "SHADOWSCAN_LOG_LEVEL": "logging.level",
            "SHADOWSCAN_MAX_WORKERS": "system.max_workers",
            "SHADOWSCAN_TIMEOUT": "system.timeout",
            "SHADOWSCAN_DB_PATH": "database.path",
            "SHADOWSCAN_DATA_DIR": "system.data_directory"
        }

        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                self._set_nested_value(env_config, config_path, self._convert_value(value))

        return env_config

    def _apply_environment_settings(self):
        """Apply environment-specific configuration overrides"""
        environment_overrides = {
            "development": {
                "system.debug_mode": True,
                "system.log_level": "DEBUG",
                "error_handling.auto_recovery": True
            },
            "testing": {
                "system.debug_mode": True,
                "system.log_level": "DEBUG",
                "scanning.phase_1.max_protocols": 10
            },
            "production": {
                "system.debug_mode": False,
                "system.log_level": "INFO",
                "error_handling.auto_recovery": True,
                "network.max_retries": 5
            }
        }

        overrides = environment_overrides.get(self.environment, {})
        for path, value in overrides.items():
            self._set_nested_value(self.config, path, value)

    def _validate_configuration(self):
        """Validate configuration against schema"""
        if not self.schema:
            return

        # Validate required fields
        for required_field in self.schema.required_fields:
            if not self._get_nested_value(self.config, required_field):
                raise ValueError(f"Required configuration field missing: {required_field}")

        # Apply validation rules
        for field_path, rule in self.schema.validation_rules.items():
            value = self._get_nested_value(self.config, field_path)
            if value is not None:
                self._validate_field_value(field_path, value, rule)

    def _validate_field_value(self, field_path: str, value: Any, rule: Dict[str, Any]):
        """Validate individual field value against rules"""
        rule_type = rule.get('type')

        if rule_type == 'string':
            if not isinstance(value, str):
                raise ValueError(f"Field {field_path} must be a string")

        elif rule_type == 'integer':
            if not isinstance(value, int):
                raise ValueError(f"Field {field_path} must be an integer")

        elif rule_type == 'boolean':
            if not isinstance(value, bool):
                raise ValueError(f"Field {field_path} must be a boolean")

        elif rule_type == 'list':
            if not isinstance(value, list):
                raise ValueError(f"Field {field_path} must be a list")

        elif rule_type == 'dict':
            if not isinstance(value, dict):
                raise ValueError(f"Field {field_path} must be a dictionary")

        # Validate range for numeric values
        if 'min' in rule and isinstance(value, (int, float)):
            if value < rule['min']:
                raise ValueError(f"Field {field_path} value {value} is less than minimum {rule['min']}")

        if 'max' in rule and isinstance(value, (int, float)):
            if value > rule['max']:
                raise ValueError(f"Field {field_path} value {value} is greater than maximum {rule['max']}")

        # Validate enum values
        if 'allowed' in rule:
            if value not in rule['allowed']:
                raise ValueError(f"Field {field_path} value {value} not in allowed values: {rule['allowed']}")

    def _get_nested_value(self, config: Dict[str, Any], path: str) -> Any:
        """Get nested configuration value using dot notation"""
        keys = path.split('.')
        current = config

        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None

        return current

    def _set_nested_value(self, config: Dict[str, Any], path: str, value: Any):
        """Set nested configuration value using dot notation"""
        keys = path.split('.')
        current = config

        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]

        current[keys[-1]] = value

    def _merge_config(self, base: Dict[str, Any], override: Dict[str, Any]):
        """Merge configuration dictionaries"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def _convert_value(self, value: str) -> Any:
        """Convert string value to appropriate type"""
        # Try to convert to boolean
        if value.lower() in ['true', 'false']:
            return value.lower() == 'true'

        # Try to convert to integer
        try:
            return int(value)
        except ValueError:
            pass

        # Try to convert to float
        try:
            return float(value)
        except ValueError:
            pass

        # Return as string
        return value

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self._get_nested_value(self.config, key) or default

    def set(self, key: str, value: Any):
        """Set configuration value"""
        self._set_nested_value(self.config, key, value)

    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section"""
        return self._get_nested_value(self.config, section) or {}

    def set_schema(self, schema: ConfigSchema):
        """Set configuration schema for validation"""
        self.schema = schema
        self._validate_configuration()

    def save_config(self, file_path: str = None):
        """Save current configuration to file"""
        file_path = file_path or self.config_file

        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(file_path) or '.', exist_ok=True)

            with open(file_path, 'w', encoding='utf-8') as f:
                if file_path.endswith('.yaml') or file_path.endswith('.yml'):
                    yaml.dump(self.config, f, default_flow_style=False, indent=2)
                else:
                    json.dump(self.config, f, indent=2, ensure_ascii=False)

            self.logger.info(f"Configuration saved to {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")

    def get_environment_config(self) -> Dict[str, Any]:
        """Get environment-specific configuration"""
        return self.get_section(self.environment)

    def validate_environment_config(self, required_keys: List[str]) -> bool:
        """Validate that environment has required configuration keys"""
        env_config = self.get_environment_config()

        for key in required_keys:
            if not self._get_nested_value(env_config, key):
                self.logger.error(f"Required configuration key missing for environment {self.environment}: {key}")
                return False

        return True

    def backup_config(self, backup_path: str = None) -> str:
        """Create backup of current configuration"""
        if not backup_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"config_backup_{timestamp}.yaml"

        try:
            self.save_config(backup_path)
            self.logger.info(f"Configuration backed up to {backup_path}")
            return backup_path
        except Exception as e:
            self.logger.error(f"Failed to backup configuration: {e}")
            return None

    def get_config_diff(self, other_config: Dict[str, Any]) -> Dict[str, Any]:
        """Get differences between current configuration and another"""
        def compare_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any], path: str = "") -> Dict[str, Any]:
            diff = {}

            all_keys = set(dict1.keys()) | set(dict2.keys())

            for key in all_keys:
                current_path = f"{path}.{key}" if path else key

                if key not in dict1:
                    diff[current_path] = {"added": dict2[key]}
                elif key not in dict2:
                    diff[current_path] = {"removed": dict1[key]}
                elif dict1[key] != dict2[key]:
                    if isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
                        nested_diff = compare_dicts(dict1[key], dict2[key], current_path)
                        diff.update(nested_diff)
                    else:
                        diff[current_path] = {
                            "old": dict1[key],
                            "new": dict2[key]
                        }

            return diff

        return compare_dicts(self.config, other_config)

    def reload_config(self):
        """Reload configuration from all sources"""
        self.logger.info("Reloading configuration...")
        self._load_configuration()
        self.logger.info("Configuration reloaded successfully")

# Global configuration manager instance
config_manager = ConfigManager()

def get_config(key: str = None, default: Any = None) -> Any:
    """Global function to get configuration"""
    if key:
        return config_manager.get(key, default)
    return config_manager.config

def set_config(key: str, value: Any):
    """Global function to set configuration"""
    config_manager.set(key, value)