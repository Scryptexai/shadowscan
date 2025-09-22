#!/usr/bin/env python3
"""
System Controller - Central Controller for Modular Scanning System
Coordinates all phases, manages system lifecycle, and provides unified interface
"""

import json
import logging
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
import threading
import time
from enum import Enum

from .core import (
    BaseManager, ConfigManager, DiagnosticTools, ErrorSeverity, ErrorCategory,
    handle_error, get_config, set_config
)
from .phases import Phase3Runner
from .scanners import ContractScanner

class SystemStatus(Enum):
    """System status enumeration"""
    INITIALIZING = "initializing"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"
    SHUTDOWN = "shutdown"

class SystemPhase(Enum):
    """System phase enumeration"""
    IDLE = "idle"
    PHASE_1 = "phase_1"
    PHASE_2 = "phase_2"
    PHASE_3 = "phase_3"
    PHASE_4 = "phase_4"
    PHASE_5 = "phase_5"
    PHASE_6 = "phase_6"
    REPORTING = "reporting"
    MAINTENANCE = "maintenance"

class ModularSystemController(BaseManager):
    """Central system controller for the modular scanning system"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Initialize debug mode first
        self.config = config or {}
        self.debug_mode = self.config.get('debug_mode', False)

        # Now call parent with proper config
        super().__init__("ModularSystemController", self.config)

        # System state
        self.status = SystemStatus.INITIALIZING
        self.current_phase = SystemPhase.IDLE
        self.phase_progress = 0.0

        # Components
        self.config_manager = ConfigManager()
        self.diagnostic = DiagnosticTools()
        self.phase_runner = None

        # Phase configuration
        self.phase_config = self._load_phase_configuration()

        # Thread management
        self.control_thread = None
        self.stop_event = threading.Event()

        # Logging
        self.logger.info("ModularSystemController initialized")

    def _load_phase_configuration(self) -> Dict[str, Any]:
        """Load phase configuration"""
        return {
            'phase_1': {
                'enabled': get_config('scanning.phase_1.enabled', True),
                'max_protocols': get_config('scanning.phase_1.max_protocols', 1000),
                'categories': get_config('scanning.phase_1.categories', [])
            },
            'phase_2': {
                'enabled': get_config('scanning.phase_2.enabled', True),
                'export_formats': get_config('scanning.phase_2.export_formats', [])
            },
            'phase_3': {
                'enabled': get_config('scanning.phase_3.enabled', True),
                'max_contracts': get_config('scanning.phase_3.max_contracts', 5000)
            }
        }

    def initialize_system(self) -> bool:
        """Initialize the entire modular system"""
        try:
            self.logger.info("Initializing modular scanning system")

            with self.diagnostic.trace_operation("ModularSystemController", "initialize_system"):
                # Validate configuration
                if not self._validate_system_configuration():
                    self.logger.error("System configuration validation failed")
                    return False

                # Setup directories
                self._setup_directories()

                # Initialize components
                if not self._initialize_components():
                    self.logger.error("Component initialization failed")
                    return False

                # Validate prerequisites
                if not self._validate_prerequisites():
                    self.logger.error("Prerequisites validation failed")
                    return False

                # Set system status
                self.status = SystemStatus.READY
                self.current_phase = SystemPhase.IDLE

                self.logger.info("Modular scanning system initialized successfully")
                return True

        except Exception as e:
            error_data = handle_error(e, "ModularSystemController", {"operation": "initialize_system"})
            self.status = SystemStatus.ERROR
            self.logger.error(f"System initialization failed: {e}")
            return False

    def _validate_system_configuration(self) -> bool:
        """Validate system configuration"""
        try:
            # Check required configuration keys
            required_keys = [
                'system.name',
                'system.version',
                'system.environment',
                'database.type',
                'database.path'
            ]

            missing_keys = []
            for key in required_keys:
                if not get_config(key):
                    missing_keys.append(key)

            if missing_keys:
                self.logger.error(f"Missing required configuration keys: {missing_keys}")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Configuration validation error: {e}")
            return False

    def _setup_directories(self):
        """Setup required directories"""
        try:
            directories = [
                'data',
                'logs',
                'reports',
                'intelligence_databases',
                'protocol_databases',
                'exports'
            ]

            for directory in directories:
                Path(directory).mkdir(exist_ok=True)

            self.logger.info("Directories setup completed")

        except Exception as e:
            self.logger.error(f"Directory setup failed: {e}")
            raise

    def _initialize_components(self) -> bool:
        """Initialize system components"""
        try:
            # Initialize phase runner
            self.phase_runner = Phase3Runner(self.config)

            # Initialize config manager
            self.config_manager = ConfigManager()

            # Initialize diagnostic tools
            self.diagnostic = DiagnosticTools()

            self.logger.info("Components initialization completed")
            return True

        except Exception as e:
            self.logger.error(f"Component initialization failed: {e}")
            return False

    def _validate_prerequisites(self) -> bool:
        """Validate system prerequisites"""
        try:
            # Check Phase 2 database
            phase2_file = "defi_protocol_database.json"
            if not Path(phase2_file).exists():
                self.logger.warning(f"Phase 2 database not found: {phase2_file}")
                # Create placeholder database
                self._create_placeholder_database()

            return True

        except Exception as e:
            self.logger.error(f"Prerequisites validation failed: {e}")
            return False

    def _create_placeholder_database(self):
        """Create placeholder database if Phase 2 doesn't exist"""
        try:
            placeholder_data = {
                "database_metadata": {
                    "created_date": datetime.now().isoformat(),
                    "total_protocols": 0,
                    "schema_version": "1.0.0",
                    "last_updated": datetime.now().isoformat()
                },
                "protocols": [],
                "categories_summary": {},
                "chains_summary": {},
                "risk_distribution": {},
                "maturity_distribution": {}
            }

            with open("defi_protocol_database.json", 'w', encoding='utf-8') as f:
                json.dump(placeholder_data, f, indent=2, ensure_ascii=False)

            self.logger.info("Placeholder database created")

        except Exception as e:
            self.logger.error(f"Failed to create placeholder database: {e}")

    def start_phase(self, phase: SystemPhase) -> bool:
        """Start specific phase"""
        try:
            if self.status != SystemStatus.READY:
                self.logger.error(f"System not ready. Current status: {self.status}")
                return False

            if self.current_phase != SystemPhase.IDLE:
                self.logger.error(f"Cannot start phase {phase}. Current phase: {self.current_phase}")
                return False

            # Check if phase is enabled
            if not self._is_phase_enabled(phase):
                self.logger.error(f"Phase {phase} is disabled in configuration")
                return False

            self.logger.info(f"Starting phase: {phase}")
            self.status = SystemStatus.RUNNING
            self.current_phase = phase

            # Start phase in separate thread
            self.control_thread = threading.Thread(target=self._execute_phase, args=(phase,))
            self.control_thread.start()

            return True

        except Exception as e:
            error_data = handle_error(e, "ModularSystemController", {"operation": "start_phase", "phase": phase})
            self.status = SystemStatus.ERROR
            self.logger.error(f"Failed to start phase {phase}: {e}")
            return False

    def _is_phase_enabled(self, phase: SystemPhase) -> bool:
        """Check if phase is enabled"""
        phase_name = phase.value
        return self.phase_config.get(phase_name, {}).get('enabled', False)

    def _execute_phase(self, phase: SystemPhase):
        """Execute phase in separate thread"""
        try:
            success = False

            if phase == SystemPhase.PHASE_3:
                success = self.phase_runner.run()
            else:
                self.logger.error(f"Phase {phase} not implemented yet")
                success = False

            # Update system status
            if success:
                self.status = SystemStatus.READY
                self.logger.info(f"Phase {phase} completed successfully")
            else:
                self.status = SystemStatus.ERROR
                self.logger.error(f"Phase {phase} failed")

        except Exception as e:
            error_data = handle_error(e, "ModularSystemController", {"operation": "execute_phase", "phase": phase})
            self.status = SystemStatus.ERROR
            self.logger.error(f"Phase {phase} execution failed: {e}")

        finally:
            self.current_phase = SystemPhase.IDLE
            self.phase_progress = 0.0

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        return {
            'system_name': get_config('system.name', 'Unknown'),
            'system_version': get_config('system.version', 'Unknown'),
            'environment': get_config('system.environment', 'Unknown'),
            'status': self.status.value,
            'current_phase': self.current_phase.value,
            'phase_progress': self.phase_progress,
            'uptime_seconds': (datetime.now() - self.created_at).total_seconds(),
            'last_error': getattr(self, 'last_error', None),
            'configuration': {
                'phase_1_enabled': self.phase_config.get('phase_1', {}).get('enabled', False),
                'phase_2_enabled': self.phase_config.get('phase_2', {}).get('enabled', False),
                'phase_3_enabled': self.phase_config.get('phase_3', {}).get('enabled', False)
            },
            'health': self.diagnostic.get_system_health(),
            'performance': self.diagnostic.get_performance_summary(hours=1)
        }

    def get_phase_status(self, phase: SystemPhase) -> Dict[str, Any]:
        """Get specific phase status"""
        phase_name = phase.value

        return {
            'phase': phase_name,
            'enabled': self._is_phase_enabled(phase),
            'config': self.phase_config.get(phase_name, {}),
            'last_execution': getattr(self, f'{phase_name}_last_execution', None),
            'execution_count': getattr(self, f'{phase_name}_execution_count', 0),
            'success_rate': getattr(self, f'{phase_name}_success_rate', 0.0)
        }

    def get_diagnostics(self) -> Dict[str, Any]:
        """Get comprehensive system diagnostics"""
        return {
            'system_status': self.get_system_status(),
            'performance_summary': self.diagnostic.get_performance_summary(hours=1),
            'health_check': self.diagnostic.get_system_health(),
            'error_summary': self._get_error_summary(),
            'component_health': self._get_component_health(),
            'recent_operations': self.diagnostic.get_performance_summary(hours=1),
            'memory_usage': self._get_memory_usage(),
            'system_resources': self._get_system_resources()
        }

    def _get_error_summary(self) -> Dict[str, Any]:
        """Get error summary"""
        return {
            'total_errors': len(self.diagnostic.error_history),
            'error_patterns': dict(self.diagnostic.error_patterns),
            'recent_errors': list(self.diagnostic.error_history)[-10:]
        }

    def _get_component_health(self) -> Dict[str, Any]:
        """Get component health status"""
        return {
            'ModularSystemController': self.diagnostic.get_system_health(),
            'ContractScanner': 'healthy',  # Would need actual health check
            'ConfigManager': 'healthy',
            'DiagnosticTools': 'healthy'
        }

    def _get_memory_usage(self) -> Dict[str, Any]:
        """Get memory usage information"""
        try:
            import psutil
            process = psutil.Process()
            return {
                'memory_rss': process.memory_info().rss / 1024 / 1024,  # MB
                'memory_vms': process.memory_info().vms / 1024 / 1024,  # MB
                'memory_percent': process.memory_percent(),
                'threads': process.num_threads(),
                'open_files': len(process.open_files())
            }
        except:
            return {'error': 'Could not get memory usage'}

    def _get_system_resources(self) -> Dict[str, Any]:
        """Get system resource usage"""
        try:
            import psutil
            return {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
                'network_connections': len(psutil.net_connections()),
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
        except:
            return {'error': 'Could not get system resources'}

    def export_diagnostics(self, filepath: Optional[str] = None) -> Optional[str]:
        """Export system diagnostics to file"""
        try:
            if not filepath:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filepath = f"system_diagnostics_{timestamp}.json"

            diagnostics = self.get_diagnostics()

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(diagnostics, f, indent=2, ensure_ascii=False)

            self.logger.info(f"Diagnostics exported to: {filepath}")
            return filepath

        except Exception as e:
            self.logger.error(f"Failed to export diagnostics: {e}")
            return None

    def run(self) -> bool:
        """Run system controller"""
        try:
            # Initialize system
            if not self.initialize_system():
                return False

            # Start Phase 3 as default
            return self.start_phase(SystemPhase.PHASE_3)

        except Exception as e:
            error_data = handle_error(e, "ModularSystemController", {"operation": "run"})
            self.logger.error(f"System controller failed: {e}")
            return False

    def cleanup(self):
        """Cleanup system resources"""
        try:
            self.logger.info("Cleaning up system resources")

            # Stop control thread if running
            if self.control_thread and self.control_thread.is_alive():
                self.stop_event.set()
                self.control_thread.join(timeout=5)

            # Cleanup components
            if hasattr(self, 'phase_runner') and self.phase_runner:
                self.phase_runner.cleanup()

            if hasattr(self, 'diagnostic') and self.diagnostic:
                self.diagnostic.take_memory_snapshot("cleanup")

            self.logger.info("System cleanup completed")

        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")


# Global system controller instance
system_controller = ModularSystemController()


def get_system_status() -> Dict[str, Any]:
    """Get system status globally"""
    return system_controller.get_system_status()


def start_phase(phase: SystemPhase) -> bool:
    """Start phase globally"""
    return system_controller.start_phase(phase)


def get_diagnostics() -> Dict[str, Any]:
    """Get system diagnostics globally"""
    return system_controller.get_diagnostics()


def main():
    """Main function to run system controller"""
    controller = ModularSystemController()
    success = controller.run()
    controller.cleanup()
    exit(0 if success else 1)


if __name__ == "__main__":
    main()