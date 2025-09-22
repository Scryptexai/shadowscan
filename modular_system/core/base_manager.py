#!/usr/bin/env python3
"""
Base Manager Class - Foundation for all modular components
Provides common functionality for error handling, logging, and debugging
"""

import logging
import traceback
from datetime import datetime
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod
import json
import os

class BaseManager(ABC):
    """Base class for all modular components with comprehensive error handling"""

    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None):
        self.name = name
        self.config = config or {}
        self.created_at = datetime.now()

        # Setup comprehensive logging
        self._setup_logging()

        # Initialize error tracking
        self.error_count = 0
        self.warning_count = 0
        self.operation_count = 0

        # Debug mode
        self.debug_mode = self.config.get('debug_mode', False)

        # Performance tracking
        self.performance_metrics = {}

        self.logger.info(f"Initialized {name} manager at {self.created_at}")

    def _setup_logging(self):
        """Setup comprehensive logging system"""
        # Create logger
        self.logger = logging.getLogger(self.name)
        self.logger.setLevel(logging.DEBUG if self.debug_mode else logging.INFO)

        # Prevent duplicate handlers
        if not self.logger.handlers:
            # Console handler
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)

            # File handler for detailed logs
            file_handler = logging.FileHandler(f"{self.name.lower()}.log")
            file_handler.setLevel(logging.DEBUG)

            # Formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
            console_handler.setFormatter(formatter)
            file_handler.setFormatter(formatter)

            self.logger.addHandler(console_handler)
            self.logger.addHandler(file_handler)

    def log_operation(self, operation: str, details: Dict[str, Any] = None):
        """Log operation with comprehensive details"""
        self.operation_count += 1
        log_data = {
            'operation': operation,
            'timestamp': datetime.now().isoformat(),
            'operation_number': self.operation_count,
            'details': details or {}
        }

        self.logger.info(f"Operation {self.operation_count}: {operation}")
        if details:
            self.logger.debug(f"Operation details: {json.dumps(details, indent=2)}")

        # Track performance
        if 'start_time' in details:
            duration = datetime.now() - details['start_time']
            self.performance_metrics[operation] = str(duration)
            self.logger.info(f"Operation duration: {duration}")

    def log_error(self, error: Exception, context: Dict[str, Any] = None, operation: str = None):
        """Comprehensive error logging with full context"""
        self.error_count += 1

        error_data = {
            'error_number': self.error_count,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'timestamp': datetime.now().isoformat(),
            'operation': operation or 'unknown',
            'context': context or {},
            'traceback': traceback.format_exc(),
            'file': getattr(error, '__file__', 'unknown'),
            'line': getattr(error, '__line__', 'unknown')
        }

        # Log error with different severity levels
        if isinstance(error, (ConnectionError, TimeoutError)):
            self.logger.error(f"Network Error #{self.error_count}: {error_data['error_message']}")
        elif isinstance(error, (ValueError, KeyError)):
            self.logger.warning(f"Data Error #{self.error_count}: {error_data['error_message']}")
        else:
            self.logger.error(f"Error #{self.error_count}: {error_data['error_message']}")

        # Log detailed error context
        self.logger.debug(f"Error context: {json.dumps(error_data, indent=2)}")

        # Save error to file for debugging
        self._save_error_log(error_data)

        return error_data

    def log_warning(self, message: str, context: Dict[str, Any] = None):
        """Log warning messages"""
        self.warning_count += 1
        self.logger.warning(f"Warning #{self.warning_count}: {message}")
        if context:
            self.logger.debug(f"Warning context: {json.dumps(context, indent=2)}")

    def _save_error_log(self, error_data: Dict[str, Any]):
        """Save detailed error log to file"""
        error_file = f"errors_{datetime.now().strftime('%Y%m%d')}.jsonl"

        try:
            with open(error_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(error_data) + '\n')
        except Exception as e:
            self.logger.error(f"Failed to save error log: {e}")

    def debug(self, message: str, data: Any = None):
        """Debug logging"""
        if self.debug_mode:
            self.logger.debug(f"DEBUG: {message}")
            if data is not None:
                self.logger.debug(f"Debug data: {json.dumps(data, indent=2, default=str)}")

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        return {
            'name': self.name,
            'created_at': self.created_at.isoformat(),
            'uptime_seconds': (datetime.now() - self.created_at).total_seconds(),
            'operation_count': self.operation_count,
            'error_count': self.error_count,
            'warning_count': self.warning_count,
            'debug_mode': self.debug_mode,
            'performance_metrics': self.performance_metrics,
            'last_error': getattr(self, 'last_error', None),
            'config': self.config
        }

    def health_check(self) -> Dict[str, Any]:
        """Perform health check on the component"""
        health = {
            'component': self.name,
            'status': 'healthy',
            'checks': {},
            'timestamp': datetime.now().isoformat()
        }

        # Check error rate
        error_rate = self.error_count / max(self.operation_count, 1)
        health['checks']['error_rate'] = {
            'status': 'warning' if error_rate > 0.1 else 'healthy',
            'value': error_rate,
            'threshold': 0.1
        }

        # Check operation count
        health['checks']['operation_count'] = {
            'status': 'healthy' if self.operation_count > 0 else 'warning',
            'value': self.operation_count
        }

        # Update overall status
        if any(check['status'] == 'warning' for check in health['checks'].values()):
            health['status'] = 'warning'

        return health

    @abstractmethod
    def run(self) -> bool:
        """Main method to be implemented by subclasses"""
        pass

    def safe_execute(self, operation: str, func, *args, **kwargs):
        """Safely execute operations with comprehensive error handling"""
        self.log_operation(operation, {'start_time': datetime.now(), 'args': str(args)[:100], 'kwargs': str(kwargs)[:100]})

        try:
            result = func(*args, **kwargs)
            self.log_operation(f"{operation}_completed")
            return result

        except Exception as e:
            error_data = self.log_error(e, {'operation': operation, 'args': args, 'kwargs': kwargs})
            self.last_error = error_data
            self.log_operation(f"{operation}_failed")
            raise

    def cleanup(self):
        """Cleanup resources"""
        try:
            self.logger.info(f"Cleaning up {self.name} resources")
            # Add cleanup logic here
        except Exception as e:
            self.log_error(e, {'operation': 'cleanup'})
        finally:
            self.logger.info(f"{self.name} cleanup completed")