"""
ShadowScan Finding Models
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
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity.value if isinstance(self.severity, SeverityLevel) else self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation
        }


__all__ = ["Finding", "SeverityLevel"]
