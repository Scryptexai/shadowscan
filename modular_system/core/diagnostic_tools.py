#!/usr/bin/env python3
"""
Diagnostic Tools for Modular System
Provides comprehensive debugging, profiling, and monitoring capabilities
"""

import logging
import time
import psutil
import threading
import json
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque
import traceback
import sys
from contextlib import contextmanager

@dataclass
class PerformanceMetrics:
    """Performance metrics data structure"""
    timestamp: datetime
    component: str
    operation: str
    duration: float
    memory_usage: float
    cpu_usage: float
    success: bool
    error_message: Optional[str] = None

@dataclass
class SystemHealth:
    """System health data structure"""
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_connections: int
    thread_count: int
    active_operations: int
    error_rate: float
    warning_count: int

class DiagnosticTools:
    """Comprehensive diagnostic and monitoring tools"""

    def __init__(self, max_metrics: int = 1000, enable_profiling: bool = True):
        self.max_metrics = max_metrics
        self.enable_profiling = enable_profiling

        # Performance tracking
        self.performance_metrics: deque = deque(maxlen=max_metrics)
        self.component_metrics = defaultdict(lambda: deque(maxlen=100))
        self.operation_metrics = defaultdict(lambda: deque(maxlen=100))

        # System monitoring
        self.health_history: deque = deque(maxlen=100)
        self.health_checks = []

        # Error tracking
        self.error_history = deque(maxlen=500)
        self.error_patterns = defaultdict(int)

        # Memory profiling
        self.memory_snapshots = deque(maxlen=50)

        # Thread monitoring
        self.active_threads = {}
        self.thread_lock = threading.Lock()

        # Setup logging
        self.logger = logging.getLogger("DiagnosticTools")

        # Initialize health checks
        self._initialize_health_checks()

    def _initialize_health_checks(self):
        """Initialize system health checks"""
        self.health_checks = [
            self._check_cpu_usage,
            self._check_memory_usage,
            self._check_disk_usage,
            self._check_network_connections,
            self._check_thread_count
        ]

    def start_operation(self, component: str, operation: str) -> str:
        """Start operation timing and return operation ID"""
        operation_id = f"{component}_{operation}_{int(time.time() * 1000)}"

        with self.thread_lock:
            self.active_threads[operation_id] = {
                'component': component,
                'operation': operation,
                'start_time': time.time(),
                'memory_start': psutil.Process().memory_info().rss / 1024 / 1024,
                'cpu_start': psutil.Process().cpu_percent(),
                'active': True
            }

        self.logger.debug(f"Started operation: {operation_id}")
        return operation_id

    def end_operation(self, operation_id: str, success: bool = True, error_message: str = None):
        """End operation timing and record metrics"""
        try:
            with self.thread_lock:
                if operation_id not in self.active_threads:
                    self.logger.warning(f"Operation ID not found: {operation_id}")
                    return

                thread_info = self.active_threads[operation_id]
                del self.active_threads[operation_id]

                # Calculate metrics
                end_time = time.time()
                duration = end_time - thread_info['start_time']
                memory_end = psutil.Process().memory_info().rss / 1024 / 1024
                cpu_end = psutil.Process().cpu_percent()
                memory_usage = memory_end - thread_info['memory_start']
                cpu_usage = max(0, cpu_end - thread_info['cpu_start'])

                # Create performance metric
                metric = PerformanceMetrics(
                    timestamp=datetime.now(),
                    component=thread_info['component'],
                    operation=thread_info['operation'],
                    duration=duration,
                    memory_usage=memory_usage,
                    cpu_usage=cpu_usage,
                    success=success,
                    error_message=error_message
                )

                # Store metrics
                self.performance_metrics.append(metric)
                self.component_metrics[thread_info['component']].append(metric)
                self.operation_metrics[thread_info['operation']].append(metric)

                # Log completion
                status = "SUCCESS" if success else "FAILED"
                self.logger.info(f"Operation completed: {operation_id} - {status} - Duration: {duration:.2f}s")

                if not success:
                    self._track_error(thread_info['component'], thread_info['operation'], error_message)

        except Exception as e:
            self.logger.error(f"Error ending operation {operation_id}: {e}")

    @contextmanager
    def trace_operation(self, component: str, operation: str):
        """Context manager for operation tracing"""
        operation_id = self.start_operation(component, operation)
        try:
            yield operation_id
        except Exception as e:
            self.end_operation(operation_id, success=False, error_message=str(e))
            raise
        else:
            self.end_operation(operation_id, success=True)

    def _track_error(self, component: str, operation: str, error_message: str):
        """Track error patterns"""
        error_key = f"{component}_{operation}_{type(error).__name__}"
        self.error_patterns[error_key] += 1

        error_data = {
            'timestamp': datetime.now(),
            'component': component,
            'operation': operation,
            'error_message': error_message,
            'error_type': type(error).__name__ if isinstance(error, Exception) else 'Unknown'
        }

        self.error_history.append(error_data)

    def get_performance_summary(self, component: str = None, operation: str = None, hours: int = 24) -> Dict[str, Any]:
        """Get performance summary"""
        cutoff_time = datetime.now() - timedelta(hours=hours)

        # Filter metrics
        if component:
            metrics = list(self.component_metrics[component])
        elif operation:
            metrics = list(self.operation_metrics[operation])
        else:
            metrics = list(self.performance_metrics)

        recent_metrics = [m for m in metrics if m.timestamp > cutoff_time]

        if not recent_metrics:
            return {
                'total_operations': 0,
                'average_duration': 0,
                'success_rate': 0,
                'average_memory': 0,
                'average_cpu': 0,
                'error_count': 0
            }

        # Calculate summary
        total_operations = len(recent_metrics)
        successful_ops = sum(1 for m in recent_metrics if m.success)
        average_duration = sum(m.duration for m in recent_metrics) / total_operations
        average_memory = sum(m.memory_usage for m in recent_metrics) / total_operations
        average_cpu = sum(m.cpu_usage for m in recent_metrics) / total_operations
        error_count = total_operations - successful_ops

        return {
            'total_operations': total_operations,
            'success_rate': successful_ops / total_operations if total_operations > 0 else 0,
            'average_duration': average_duration,
            'average_memory': average_memory,
            'average_cpu': average_cpu,
            'error_count': error_count,
            'fastest_operation': min(recent_metrics, key=lambda x: x.duration).duration if recent_metrics else 0,
            'slowest_operation': max(recent_metrics, key=lambda x: x.duration).duration if recent_metrics else 0
        }

    def get_component_performance(self, component: str, hours: int = 24) -> Dict[str, Any]:
        """Get detailed performance metrics for specific component"""
        metrics = list(self.component_metrics[component])
        recent_metrics = [m for m in metrics if m.timestamp > datetime.now() - timedelta(hours=hours)]

        if not recent_metrics:
            return {'component': component, 'message': 'No data available'}

        # Group by operation
        operation_breakdown = defaultdict(lambda: {'count': 0, 'total_duration': 0, 'errors': 0})

        for metric in recent_metrics:
            operation_breakdown[metric.operation]['count'] += 1
            operation_breakdown[metric.operation]['total_duration'] += metric.duration
            if not metric.success:
                operation_breakdown[metric.operation]['errors'] += 1

        # Calculate averages
        for operation in operation_breakdown:
            op_data = operation_breakdown[operation]
            op_data['average_duration'] = op_data['total_duration'] / op_data['count']
            op_data['success_rate'] = (op_data['count'] - op_data['errors']) / op_data['count']

        return {
            'component': component,
            'total_operations': len(recent_metrics),
            'operations': dict(operation_breakdown),
            'overall_success_rate': sum(1 for m in recent_metrics if m.success) / len(recent_metrics),
            'average_duration': sum(m.duration for m in recent_metrics) / len(recent_metrics)
        }

    def record_health_check(self):
        """Record system health metrics"""
        try:
            health = SystemHealth(
                timestamp=datetime.now(),
                cpu_usage=psutil.cpu_percent(),
                memory_usage=psutil.virtual_memory().percent,
                disk_usage=psutil.disk_usage('/').percent,
                network_connections=len(psutil.net_connections()),
                thread_count=len(threading.enumerate()),
                active_operations=len(self.active_threads),
                error_rate=len([m for m in self.performance_metrics if not m.success]) / max(len(self.performance_metrics), 1),
                warning_count=len([m for m in self.performance_metrics if m.duration > 10])  # Operations taking > 10s
            )

            self.health_history.append(health)

        except Exception as e:
            self.logger.error(f"Error recording health check: {e}")

    def _check_cpu_usage(self) -> Dict[str, Any]:
        """Check CPU usage"""
        cpu_usage = psutil.cpu_percent()
        return {
            'check': 'cpu_usage',
            'status': 'healthy' if cpu_usage < 80 else 'warning' if cpu_usage < 90 else 'critical',
            'value': cpu_usage,
            'threshold': {'warning': 80, 'critical': 90}
        }

    def _check_memory_usage(self) -> Dict[str, Any]:
        """Check memory usage"""
        memory = psutil.virtual_memory()
        return {
            'check': 'memory_usage',
            'status': 'healthy' if memory.percent < 80 else 'warning' if memory.percent < 90 else 'critical',
            'value': memory.percent,
            'threshold': {'warning': 80, 'critical': 90}
        }

    def _check_disk_usage(self) -> Dict[str, Any]:
        """Check disk usage"""
        disk = psutil.disk_usage('/')
        return {
            'check': 'disk_usage',
            'status': 'healthy' if disk.percent < 80 else 'warning' if disk.percent < 90 else 'critical',
            'value': disk.percent,
            'threshold': {'warning': 80, 'critical': 90}
        }

    def _check_network_connections(self) -> Dict[str, Any]:
        """Check network connections"""
        try:
            connections = len(psutil.net_connections())
            return {
                'check': 'network_connections',
                'status': 'healthy' if connections < 100 else 'warning' if connections < 500 else 'critical',
                'value': connections,
                'threshold': {'warning': 100, 'critical': 500}
            }
        except:
            return {
                'check': 'network_connections',
                'status': 'error',
                'value': 0,
                'threshold': {}
            }

    def _check_thread_count(self) -> Dict[str, Any]:
        """Check thread count"""
        thread_count = len(threading.enumerate())
        return {
            'check': 'thread_count',
            'status': 'healthy' if thread_count < 50 else 'warning' if thread_count < 100 else 'critical',
            'value': thread_count,
            'threshold': {'warning': 50, 'critical': 100}
        }

    def get_system_health(self) -> Dict[str, Any]:
        """Get comprehensive system health status"""
        health_checks = []
        overall_status = 'healthy'

        for check_func in self.health_checks:
            try:
                result = check_func()
                health_checks.append(result)

                if result['status'] == 'critical':
                    overall_status = 'critical'
                elif result['status'] == 'warning' and overall_status != 'critical':
                    overall_status = 'warning'
            except Exception as e:
                health_checks.append({
                    'check': 'unknown',
                    'status': 'error',
                    'value': 0,
                    'error': str(e)
                })

        return {
            'overall_status': overall_status,
            'timestamp': datetime.now().isoformat(),
            'checks': health_checks,
            'active_operations': len(self.active_threads),
            'total_threads': len(threading.enumerate()),
            'performance_metrics_count': len(self.performance_metrics)
        }

    def take_memory_snapshot(self, label: str = None):
        """Take memory snapshot for debugging"""
        try:
            process = psutil.Process()
            snapshot = {
                'timestamp': datetime.now(),
                'label': label or 'snapshot',
                'memory_rss': process.memory_info().rss / 1024 / 1024,  # MB
                'memory_vms': process.memory_info().vms / 1024 / 1024,  # MB
                'cpu_percent': process.cpu_percent(),
                'threads': process.num_threads(),
                'open_files': len(process.open_files()),
                'connections': len(process.connections())
            }

            self.memory_snapshots.append(snapshot)
            self.logger.debug(f"Memory snapshot taken: {label or 'snapshot'} - {snapshot['memory_rss']:.2f}MB")

        except Exception as e:
            self.logger.error(f"Error taking memory snapshot: {e}")

    def generate_debug_report(self) -> str:
        """Generate comprehensive debug report"""
        report = []
        report.append("=" * 60)
        report.append("SYSTEM DEBUG REPORT")
        report.append("=" * 60)
        report.append(f"Generated at: {datetime.now().isoformat()}")
        report.append("")

        # System health
        health = self.get_system_health()
        report.append("SYSTEM HEALTH")
        report.append("-" * 40)
        report.append(f"Overall Status: {health['overall_status'].upper()}")
        for check in health['checks']:
            report.append(f"{check['check']}: {check['status']} ({check['value']:.1f})")
        report.append("")

        # Performance summary
        perf_summary = self.get_performance_summary(hours=1)
        report.append("PERFORMANCE SUMMARY (Last 1 hour)")
        report.append("-" * 40)
        report.append(f"Total Operations: {perf_summary['total_operations']}")
        report.append(f"Success Rate: {perf_summary['success_rate']:.2%}")
        report.append(f"Average Duration: {perf_summary['average_duration']:.2f}s")
        report.append(f"Average Memory: {perf_summary['average_memory']:.2f}MB")
        report.append(f"Error Count: {perf_summary['error_count']}")
        report.append("")

        # Component performance
        report.append("COMPONENT PERFORMANCE")
        report.append("-" * 40)
        for component in self.component_metrics.keys():
            comp_perf = self.get_component_performance(component, hours=1)
            if comp_perf['total_operations'] > 0:
                report.append(f"{component}: {comp_perf['total_operations']} operations, {comp_perf['overall_success_rate']:.2%} success rate")

        # Memory snapshots
        report.append("MEMORY SNAPSHOTS")
        report.append("-" * 40)
        for snapshot in list(self.memory_snapshots)[-5:]:
            report.append(f"{snapshot['timestamp']}: {snapshot['memory_rss']:.2f}MB ({snapshot['label']})")

        # Error patterns
        report.append("ERROR PATTERNS")
        report.append("-" * 40)
        for error_pattern, count in sorted(self.error_patterns.items(), key=lambda x: x[1], reverse=True)[:10]:
            report.append(f"{error_pattern}: {count} occurrences")

        # Active operations
        report.append("ACTIVE OPERATIONS")
        report.append("-" * 40)
        for op_id, op_info in self.active_threads.items():
            duration = time.time() - op_info['start_time']
            report.append(f"{op_id}: {duration:.1f}s")

        return "\n".join(report)

    def export_diagnostics(self, file_path: str = None):
        """Export diagnostic data to file"""
        if not file_path:
            file_path = f"diagnostic_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        diagnostic_data = {
            'timestamp': datetime.now().isoformat(),
            'system_health': self.get_system_health(),
            'performance_metrics': list(self.performance_metrics),
            'health_history': list(self.health_history),
            'error_history': list(self.error_history),
            'memory_snapshots': list(self.memory_snapshots),
            'error_patterns': dict(self.error_patterns),
            'component_metrics': {k: list(v) for k, v in self.component_metrics.items()}
        }

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(diagnostic_data, f, indent=2, default=str)

            self.logger.info(f"Diagnostics exported to {file_path}")
            return file_path
        except Exception as e:
            self.logger.error(f"Failed to export diagnostics: {e}")
            return None

# Global diagnostic tools instance
diagnostic_tools = DiagnosticTools()