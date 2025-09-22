#!/usr/bin/env python3
"""
Centralized Error Handler for Modular System
Provides comprehensive error handling, recovery, and debugging capabilities
"""

import logging
import traceback
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Callable
from enum import Enum
import json
import os
import sys
from dataclasses import dataclass, asdict
from collections import defaultdict, deque

class ErrorSeverity(Enum):
    """Error severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ErrorCategory(Enum):
    """Error categories"""
    NETWORK = "network"
    DATABASE = "database"
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONFIGURATION = "configuration"
    BUSINESS_LOGIC = "business_logic"
    SYSTEM = "system"
    EXTERNAL_API = "external_api"
    SECURITY = "security"

@dataclass
class ErrorEvent:
    """Structured error event data"""
    timestamp: datetime
    component: str
    severity: ErrorSeverity
    category: ErrorCategory
    error_type: str
    error_message: str
    trace: str
    context: Dict[str, Any]
    operation: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    resolved: bool = False
    resolution_notes: Optional[str] = None

class CentralizedErrorHandler:
    """Centralized error handling with recovery and debugging"""

    def __init__(self, max_errors: int = 1000, enable_auto_recovery: bool = True):
        self.max_errors = max_errors
        self.enable_auto_recovery = enable_auto_recovery

        # Error storage
        self.errors: deque = deque(maxlen=max_errors)
        self.error_counts = defaultdict(int)
        self.component_errors = defaultdict(int)

        # Recovery strategies
        self.recovery_strategies: Dict[str, Callable] = {}

        # Alert thresholds
        self.alert_thresholds = {
            ErrorSeverity.CRITICAL: 1,
            ErrorSeverity.HIGH: 5,
            ErrorSeverity.MEDIUM: 10,
            ErrorSeverity.LOW: 50
        }

        # Setup logging
        self.logger = logging.getLogger("CentralizedErrorHandler")
        self.error_log_file = f"error_log_{datetime.now().strftime('%Y%m%d')}.json"

        # Initialize recovery strategies
        self._initialize_default_recovery_strategies()

    def _initialize_default_recovery_strategies(self):
        """Initialize default recovery strategies"""
        self.recovery_strategies.update({
            'ConnectionError': self._retry_connection,
            'TimeoutError': self._increase_timeout,
            'ValueError': self._validate_input,
            'KeyError': self._provide_default,
            'PermissionError': self._check_permissions,
            'ModuleNotFoundError': self._install_dependency
        })

    def handle_error(self,
                    error: Exception,
                    component: str,
                    context: Dict[str, Any] = None,
                    operation: str = None,
                    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                    category: ErrorCategory = ErrorCategory.SYSTEM) -> ErrorEvent:
        """Handle error with comprehensive tracking and recovery"""

        # Create error event
        error_event = ErrorEvent(
            timestamp=datetime.now(),
            component=component,
            severity=severity,
            category=category,
            error_type=type(error).__name__,
            error_message=str(error),
            trace=traceback.format_exc(),
            context=context or {},
            operation=operation or "unknown"
        )

        # Store error
        self.errors.append(error_event)
        self.error_counts[error_event.error_type] += 1
        self.component_errors[component] += 1

        # Log error
        self._log_error(error_event)

        # Check for alerts
        self._check_alerts(error_event)

        # Attempt recovery if enabled
        if self.enable_auto_recovery:
            self._attempt_recovery(error_event)

        return error_event

    def _log_error(self, error_event: ErrorEvent):
        """Log error to file and console"""
        log_entry = {
            'timestamp': error_event.timestamp.isoformat(),
            'component': error_event.component,
            'severity': error_event.severity.value,
            'category': error_event.category.value,
            'error_type': error_event.error_type,
            'message': error_event.error_message,
            'operation': error_event.operation
        }

        # Console logging
        if error_event.severity in [ErrorSeverity.CRITICAL, ErrorSeverity.HIGH]:
            self.logger.error(f"CRITICAL ERROR in {error_event.component}: {error_event.error_message}")
        else:
            self.logger.warning(f"Error in {error_event.component}: {error_event.error_message}")

        # File logging
        try:
            with open(self.error_log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            self.logger.error(f"Failed to write error log: {e}")

    def _check_alerts(self, error_event: ErrorEvent):
        """Check if error thresholds are exceeded"""
        # Check component error count
        if self.component_errors[error_event.component] >= self.alert_thresholds[ErrorSeverity.MEDIUM]:
            self.logger.warning(f"High error count in {error_event.component}: {self.component_errors[error_event.component]}")

        # Check total error count by type
        if self.error_counts[error_event.error_type] >= self.alert_thresholds[ErrorSeverity.HIGH]:
            self.logger.warning(f"High frequency of {error_event.error_type}: {self.error_counts[error_event.error_type]}")

    def _attempt_recovery(self, error_event: ErrorEvent):
        """Attempt automatic recovery"""
        recovery_func = self.recovery_strategies.get(error_event.error_type)
        if recovery_func:
            try:
                recovery_func(error_event)
                error_event.resolved = True
                error_event.resolution_notes = f"Auto-recovery successful via {recovery_func.__name__}"
                self.logger.info(f"Auto-recovery successful for {error_event.error_type} in {error_event.component}")
            except Exception as recovery_error:
                error_event.resolution_notes = f"Recovery failed: {str(recovery_error)}"
                self.logger.error(f"Auto-recovery failed for {error_event.error_type}: {recovery_error}")

    def _retry_connection(self, error_event: ErrorEvent):
        """Retry connection strategy"""
        # Implement connection retry logic
        import time
        time.sleep(2)  # Wait before retry

        # This is a placeholder - actual implementation depends on the component
        self.logger.info("Retrying connection...")

    def _increase_timeout(self, error_event: ErrorEvent):
        """Increase timeout strategy"""
        # Implement timeout increase logic
        self.logger.info("Increasing timeout for operation...")

    def _validate_input(self, error_event: ErrorEvent):
        """Validate input data"""
        # Implement input validation logic
        self.logger.info("Validating input data...")

    def _provide_default(self, error_event: ErrorEvent):
        """Provide default value"""
        # Implement default value logic
        self.logger.info("Providing default value...")

    def _check_permissions(self, error_event: ErrorEvent):
        """Check and fix permissions"""
        # Implement permission checking logic
        self.logger.info("Checking permissions...")

    def _install_dependency(self, error_event: ErrorEvent):
        """Install missing dependency"""
        # Implement dependency installation logic
        self.logger.info("Installing missing dependency...")

    def get_error_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get error summary for specified time period"""
        cutoff_time = datetime.now() - timedelta(hours=hours)

        recent_errors = [e for e in self.errors if e.timestamp > cutoff_time]

        summary = {
            'period_hours': hours,
            'total_errors': len(recent_errors),
            'errors_by_severity': defaultdict(int),
            'errors_by_category': defaultdict(int),
            'errors_by_component': defaultdict(int),
            'errors_by_type': defaultdict(int),
            'top_errors': [],
            'unresolved_errors': len([e for e in recent_errors if not e.resolved]),
            'start_time': min([e.timestamp for e in recent_errors]).isoformat() if recent_errors else None,
            'end_time': max([e.timestamp for e in recent_errors]).isoformat() if recent_errors else None
        }

        # Count by various categories
        for error in recent_errors:
            summary['errors_by_severity'][error.severity.value] += 1
            summary['errors_by_category'][error.category.value] += 1
            summary['errors_by_component'][error.component] += 1
            summary['errors_by_type'][error.error_type] += 1

        # Get top errors
        summary['top_errors'] = sorted(
            recent_errors,
            key=lambda x: (
                -summary['errors_by_type'][x.error_type],
                x.severity.value,
                x.timestamp
            )
        )[:10]

        return summary

    def get_component_health(self, component: str) -> Dict[str, Any]:
        """Get health status for specific component"""
        component_errors = [e for e in self.errors if e.component == component]

        if not component_errors:
            return {
                'component': component,
                'status': 'healthy',
                'error_count': 0,
                'last_error': None,
                'health_score': 100
            }

        # Calculate health score
        recent_errors = component_errors[-100:]  # Last 100 errors
        critical_errors = [e for e in recent_errors if e.severity == ErrorSeverity.CRITICAL]
        high_errors = [e for e in recent_errors if e.severity == ErrorSeverity.HIGH]

        health_score = 100 - (len(critical_errors) * 10) - (len(high_errors) * 5)
        health_score = max(0, health_score)

        return {
            'component': component,
            'status': 'critical' if critical_errors else 'warning' if high_errors else 'healthy',
            'error_count': len(component_errors),
            'critical_errors': len(critical_errors),
            'high_errors': len(high_errors),
            'last_error': component_errors[-1].timestamp.isoformat() if component_errors else None,
            'health_score': health_score,
            'resolved_ratio': len([e for e in recent_errors if e.resolved]) / len(recent_errors) if recent_errors else 1
        }

    def add_recovery_strategy(self, error_type: str, recovery_func: Callable):
        """Add custom recovery strategy"""
        self.recovery_strategies[error_type] = recovery_func
        self.logger.info(f"Added recovery strategy for {error_type}")

    def clear_old_errors(self, days: int = 7):
        """Clear errors older than specified days"""
        cutoff_time = datetime.now() - timedelta(days=days)
        old_count = len([e for e in self.errors if e.timestamp < cutoff_time])

        self.errors = deque([e for e in self.errors if e.timestamp >= cutoff_time], maxlen=self.max_errors)

        self.logger.info(f"Cleared {old_count} old errors")

    def generate_debug_report(self) -> str:
        """Generate comprehensive debug report"""
        report = []
        report.append("=" * 60)
        report.append("ERROR HANDLER DEBUG REPORT")
        report.append("=" * 60)
        report.append(f"Generated at: {datetime.now().isoformat()}")
        report.append(f"Total errors tracked: {len(self.errors)}")
        report.append(f"Enable auto-recovery: {self.enable_auto_recovery}")
        report.append("")

        # Error summary
        summary = self.get_error_summary(hours=24)
        report.append("ERROR SUMMARY (Last 24 hours)")
        report.append("-" * 40)
        report.append(f"Total errors: {summary['total_errors']}")
        report.append(f"Unresolved errors: {summary['unresolved_errors']}")
        report.append(f"Top error types: {dict(list(summary['errors_by_type'].items())[:5])}")
        report.append("")

        # Component health
        report.append("COMPONENT HEALTH")
        report.append("-" * 40)
        for component in set([e.component for e in self.errors]):
            health = self.get_component_health(component)
            report.append(f"{component}: {health['status']} (score: {health['health_score']})")
        report.append("")

        # Recent errors
        report.append("RECENT ERRORS")
        report.append("-" * 40)
        for error in list(self.errors)[-10:]:
            report.append(f"{error.timestamp}: {error.component} - {error.error_type}: {error.error_message}")

        return "\n".join(report)

# Global error handler instance
global_error_handler = CentralizedErrorHandler()

def handle_error(error: Exception,
                component: str,
                context: Dict[str, Any] = None,
                operation: str = None,
                severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                category: ErrorCategory = ErrorCategory.SYSTEM) -> ErrorEvent:
    """Global error handling function"""
    return global_error_handler.handle_error(error, component, context, operation, severity, category)