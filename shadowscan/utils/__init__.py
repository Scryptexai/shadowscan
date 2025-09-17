"""
ShadowScan Utilities Module
"""

try:
    from .logger import setup_logger
except ImportError:
    import logging
    
    def setup_logger(name="shadowscan", level=logging.INFO):
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger(name)

__all__ = ["setup_logger"]
