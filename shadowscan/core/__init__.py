"""
ShadowScan Core Module
"""

try:
    from .blockchain_scanner import BlockchainScanner
    from .report_generator import ReportGenerator
except ImportError as e:
    import warnings
    warnings.warn(f"Some core modules not available: {e}", ImportWarning)
    
    class BlockchainScanner:
        def __init__(self, *args, **kwargs):
            raise NotImplementedError("BlockchainScanner module not available")
    
    class ReportGenerator:
        def __init__(self, *args, **kwargs):
            raise NotImplementedError("ReportGenerator module not available")

__all__ = ["BlockchainScanner", "ReportGenerator"]
