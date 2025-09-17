"""
ShadowScan Data Models
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, Optional

class SeverityLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM" 
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class Finding:
    id: str
    severity: SeverityLevel
    title: str
    description: str
    evidence: Dict[str, Any]
    recommendation: str

__all__ = ["Finding", "SeverityLevel"]
