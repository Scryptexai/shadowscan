# shadowscan/core/logger.py
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from ..config import ConfigLoader

class StealthLogger:
    """Sistem logging profesional dengan stealth mode"""
    
    def __init__(self, config: ConfigLoader):
        self.config = config
        self.logger = self._setup_logger()
        self.start_time = datetime.now()
        self.vulnerabilities_found = 0
        self.active_modules = []
        
    def _setup_logger(self) -> logging.Logger:
        """Setup logger dengan konfigurasi profesional"""
        logger = logging.getLogger('ShadowScan')
        logger.setLevel(logging.INFO)
        
        # Hapus handler default
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Handler untuk console
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(self._get_formatter())
        logger.addHandler(console_handler)
        
        # Handler untuk file jika diperlukan
        report_dir = Path(self.config.get('REPORT_DIR'))
        report_dir.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(
            report_dir / f'shadowscan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        )
        file_handler.setFormatter(self._get_formatter())
        logger.addHandler(file_handler)
        
        return logger
    
    def _get_formatter(self) -> logging.Formatter:
        """Formatter dengan stealth mode"""
        if self.config.get('STEALTH_MODE'):
            # Format minimalis untuk stealth mode
            return logging.Formatter('%(message)s')
        else:
            # Format detail untuk debugging
            return logging.Formatter(
                '%(asctime)s - %(levelname)s - [%(module)s] - %(message)s'
            )
    
    def info(self, message: str, *args, **kwargs) -> None:
        """Log info dengan stealth mode"""
        if not self.config.get('STEALTH_MODE') or kwargs.get('force', False):
            self.logger.info(message, *args)
    
    def warning(self, message: str, *args, **kwargs) -> None:
        """Log warning dengan stealth mode"""
        if not self.config.get('STEALTH_MODE') or kwargs.get('force', False):
            self.logger.warning(message, *args)
    
    def error(self, message: str, *args, **kwargs) -> None:
        """Log error dengan stealth mode"""
        if not self.config.get('STEALTH_MODE') or kwargs.get('force', False):
            self.logger.error(message, *args)
    
    def critical(self, message: str, *args, **kwargs) -> None:
        """Log critical dengan stealth mode"""
        if not self.config.get('STEALTH_MODE') or kwargs.get('force', False):
            self.logger.critical(message, *args)
    
    def add_vulnerability(self, vuln_type: str, description: str, severity: str) -> None:
        """Tambahkan temuan kerentanan"""
        self.vulnerabilities_found += 1
        severity_emoji = "🔴" if severity == "high" else "🟠" if severity == "medium" else "🟡"
        
        if not self.config.get('STEALTH_MODE'):
            self.logger.info(f"{severity_emoji} [{severity.upper()}] {vuln_type}: {description}")
        else:
            # Dalam stealth mode, hanya log ringkas
            self.logger.info(f"{severity_emoji} {vuln_type}")
    
    def start_scan(self, target: str) -> None:
        """Log awal scan"""
        self.info("=" * 80, force=True)
        self.info(f"🚀 SHADOWSCAN ENGINE STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", force=True)
        self.info(f"🎯 Target: {target}", force=True)
        self.info(f"🕵️‍♂️ Mode: {'Stealth' if self.config.get('STEALTH_MODE') else 'Verbose'}", force=True)
        self.info("=" * 80, force=True)
    
    def end_scan(self) -> None:
        """Log akhir scan"""
        duration = datetime.now() - self.start_time
        self.info("\n" + "=" * 80, force=True)
        self.info(f"🏁 SHADOWSCAN ENGINE FINISHED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", force=True)
        self.info(f"⏱️ Duration: {duration}", force=True)
        self.info(f"🔍 Vulnerabilities found: {self.vulnerabilities_found}", force=True)
        self.info("=" * 80, force=True)
    
    def register_module(self, module_name: str) -> None:
        """Daftarkan modul yang aktif"""
        self.active_modules.append(module_name)
        if not self.config.get('STEALTH_MODE'):
            self.info(f"🔧 Modul aktif: {module_name}")
