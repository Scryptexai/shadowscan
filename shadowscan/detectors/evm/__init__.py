"""
EVM Vulnerability Detectors Module

This module provides comprehensive vulnerability detection for EVM smart contracts,
including 20 specialized detectors covering various attack vectors and security issues.
"""

from .vulnerability_detectors import (
    BaseVulnerabilityDetector,
    VulnerabilityType,
    VulnerabilityFinding,
    ReentrancyDetector,
    FlashloanDetector,
    AccessControlDetector,
    IntegerOverflowDetector,
    create_vulnerability_detector
)

from .additional_detectors import (
    UncheckedCallsDetector,
    FrontRunningDetector,
    TimeManipulationDetector,
    TokenApprovalDetector,
    DelegateCallMisuseDetector,
    SelfdestructMisuseDetector
)

from .specialized_detectors import (
    ProxyMisuseDetector,
    UpgradeMechanismDetector,
    MulticallExploitDetector,
    SignatureReplayDetector,
    StorageCollisionDetector
)

from .defi_detectors import (
    FeeManipulationDetector,
    SlippageProtectionDetector,
    PauseMechanismDetector,
    create_all_vulnerability_detectors,
    ComprehensiveVulnerabilityScanner
)

from .oracle_manipulation import (
    OracleManipulationDetector,
    OracleInfo,
    DEXPoolInfo,
    OracleVulnerability
)

__all__ = [
    # Base classes and enums
    'BaseVulnerabilityDetector',
    'VulnerabilityType',
    'VulnerabilityFinding',
    
    # Core vulnerability detectors
    'ReentrancyDetector',
    'FlashloanDetector',
    'AccessControlDetector',
    'IntegerOverflowDetector',
    
    # Additional vulnerability detectors
    'UncheckedCallsDetector',
    'FrontRunningDetector',
    'TimeManipulationDetector',
    'TokenApprovalDetector',
    'DelegateCallMisuseDetector',
    'SelfdestructMisuseDetector',
    
    # Specialized vulnerability detectors
    'ProxyMisuseDetector',
    'UpgradeMechanismDetector',
    'MulticallExploitDetector',
    'SignatureReplayDetector',
    'StorageCollisionDetector',
    'GasLimitationDetector',
    
    # DeFi/Protocol-specific detectors
    'FeeManipulationDetector',
    'SlippageProtectionDetector',
    'PauseMechanismDetector',
    'OracleManipulationDetector',
    
    # Data classes
    'OracleInfo',
    'DEXPoolInfo',
    'OracleVulnerability',
    
    # Factory functions and scanners
    'create_vulnerability_detector',
    'create_all_vulnerability_detectors',
    'ComprehensiveVulnerabilityScanner',
]