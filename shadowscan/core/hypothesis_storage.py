"""
Fixed shadowscan/core/hypothesis_storage.py

The issue is in enum serialization/deserialization. We need to handle enum conversion properly.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

class HypothesisStatus(Enum):
    HYPOTHESIS = "hypothesis"
    VERIFIED_TRUE = "verified_true" 
    VERIFIED_FALSE = "verified_false"
    INCONCLUSIVE = "inconclusive"

@dataclass
class Hypothesis:
    id: str
    target: str
    chain: str
    category: str
    title: str
    description: str
    severity: str
    exploitability_score: float
    evidence: Dict[str, Any]
    affected_functions: List[str]
    exploitation_cost: float
    potential_profit: float
    status: str  # Store as string instead of enum to avoid serialization issues
    created_at: str
    block_number: Optional[int] = None
    verified_at: Optional[str] = None
    verification_result: Optional[Dict[str, Any]] = None
    proof_of_concept: Optional[Dict[str, Any]] = None
    
    @classmethod
    def from_finding(cls, finding: Dict[str, Any], target: str, chain: str, block_number: int) -> 'Hypothesis':
        """Create hypothesis from screening finding."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hyp_id = f"HYP-{timestamp}-{str(uuid.uuid4())[:8].upper()}"
        
        return cls(
            id=hyp_id,
            target=target,
            chain=chain,
            category=finding.get("id", "UNKNOWN"),
            title=finding.get("title", "Unknown Vulnerability"),
            description=finding.get("description", "No description"),
            severity=finding.get("severity", "MEDIUM"),
            exploitability_score=finding.get("exploitability_score", 0.0),
            evidence=finding.get("evidence", {}),
            affected_functions=finding.get("affected_functions", []),
            exploitation_cost=finding.get("exploitation_cost", 0.0),
            potential_profit=finding.get("potential_profit", 0.0),
            status=HypothesisStatus.HYPOTHESIS.value,  # Store as string value
            created_at=datetime.now().isoformat(),
            block_number=block_number
        )
    
    def get_status_enum(self) -> HypothesisStatus:
        """Get status as enum."""
        try:
            return HypothesisStatus(self.status)
        except ValueError:
            return HypothesisStatus.HYPOTHESIS


class HypothesisStorage:
    """Persistent storage for hypotheses and verification results."""
    
    def __init__(self, storage_dir: str = "reports/findings"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Index file for quick lookups
        self.index_file = self.storage_dir / "index.json"
        self._load_index()
    
    def _load_index(self):
        """Load hypothesis index."""
        if self.index_file.exists():
            try:
                with open(self.index_file, 'r') as f:
                    self.index = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                self.index = self._create_empty_index()
        else:
            self.index = self._create_empty_index()
    
    def _create_empty_index(self):
        """Create empty index structure."""
        return {
            "hypotheses": {},
            "by_target": {},
            "by_category": {},
            "last_updated": datetime.now().isoformat()
        }
    
    def _save_index(self):
        """Save hypothesis index."""
        self.index["last_updated"] = datetime.now().isoformat()
        with open(self.index_file, 'w') as f:
            json.dump(self.index, f, indent=2)
    
    def store_hypothesis(self, hypothesis: Hypothesis) -> str:
        """Store new hypothesis and return ID."""
        
        # Convert to dict and handle enum serialization
        hyp_dict = asdict(hypothesis)
        
        # Save hypothesis file
        hyp_file = self.storage_dir / f"{hypothesis.id}.json"
        with open(hyp_file, 'w') as f:
            json.dump(hyp_dict, f, indent=2, default=str)
        
        # Update index
        self.index["hypotheses"][hypothesis.id] = {
            "target": hypothesis.target,
            "chain": hypothesis.chain,
            "category": hypothesis.category,
            "status": hypothesis.status,  # Already a string
            "created_at": hypothesis.created_at,
            "file": str(hyp_file)
        }
        
        # Index by target
        if hypothesis.target not in self.index["by_target"]:
            self.index["by_target"][hypothesis.target] = []
        self.index["by_target"][hypothesis.target].append(hypothesis.id)
        
        # Index by category
        if hypothesis.category not in self.index["by_category"]:
            self.index["by_category"][hypothesis.category] = []
        self.index["by_category"][hypothesis.category].append(hypothesis.id)
        
        self._save_index()
        return hypothesis.id
    
    def get_hypothesis(self, hyp_id: str) -> Optional[Hypothesis]:
        """Retrieve hypothesis by ID."""
        if hyp_id not in self.index["hypotheses"]:
            return None
        
        hyp_file = self.storage_dir / f"{hyp_id}.json"
        if not hyp_file.exists():
            return None
        
        try:
            with open(hyp_file, 'r') as f:
                data = json.load(f)
            
            # Status is already a string, no need to convert
            return Hypothesis(**data)
            
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            print(f"Error loading hypothesis {hyp_id}: {e}")
            return None
    
    def update_hypothesis(self, hypothesis: Hypothesis):
        """Update existing hypothesis."""
        hyp_dict = asdict(hypothesis)
        
        hyp_file = self.storage_dir / f"{hypothesis.id}.json"
        with open(hyp_file, 'w') as f:
            json.dump(hyp_dict, f, indent=2, default=str)
        
        # Update index status
        if hypothesis.id in self.index["hypotheses"]:
            self.index["hypotheses"][hypothesis.id]["status"] = hypothesis.status
        
        self._save_index()
    
    def list_hypotheses(self, 
                       target: Optional[str] = None,
                       category: Optional[str] = None,
                       status: Optional[HypothesisStatus] = None) -> List[Hypothesis]:
        """List hypotheses with optional filters."""
        
        hyp_ids = []
        
        if target:
            hyp_ids = self.index["by_target"].get(target, [])
        elif category:
            hyp_ids = self.index["by_category"].get(category, [])
        else:
            hyp_ids = list(self.index["hypotheses"].keys())
        
        hypotheses = []
        for hyp_id in hyp_ids:
            hyp = self.get_hypothesis(hyp_id)
            if hyp:
                # Filter by status if provided
                if status is None or hyp.get_status_enum() == status:
                    hypotheses.append(hyp)
        
        # Sort by creation time (newest first)
        hypotheses.sort(key=lambda h: h.created_at, reverse=True)
        return hypotheses
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get storage statistics."""
        total = len(self.index["hypotheses"])
        by_status = {}
        by_category = {}
        
        for hyp_info in self.index["hypotheses"].values():
            status = hyp_info["status"]
            category = hyp_info["category"]
            
            by_status[status] = by_status.get(status, 0) + 1
            by_category[category] = by_category.get(category, 0) + 1
        
        return {
            "total_hypotheses": total,
            "by_status": by_status,
            "by_category": by_category,
            "targets_scanned": len(self.index["by_target"]),
            "last_updated": self.index["last_updated"]
        }
    
    def store_screening_session(self, 
                              target: str, 
                              chain: str,
                              findings: List[Dict[str, Any]], 
                              block_number: int) -> List[str]:
        """Store all findings from screening session as hypotheses."""
        
        hypothesis_ids = []
        
        for finding in findings:
            hypothesis = Hypothesis.from_finding(finding, target, chain, block_number)
            hyp_id = self.store_hypothesis(hypothesis)
            hypothesis_ids.append(hyp_id)
        
        # Save session metadata
        session_file = self.storage_dir / f"session_{target[-8:]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        session_data = {
            "target": target,
            "chain": chain,
            "block_number": block_number,
            "timestamp": datetime.now().isoformat(),
            "hypothesis_ids": hypothesis_ids,
            "total_findings": len(findings)
        }
        
        with open(session_file, 'w') as f:
            json.dump(session_data, f, indent=2)
        
        return hypothesis_ids
    
    def mark_verified(self, 
                     hyp_id: str, 
                     verification_result: Dict[str, Any], 
                     proof_of_concept: Optional[Dict[str, Any]] = None) -> bool:
        """Mark hypothesis as verified with results."""
        
        hypothesis = self.get_hypothesis(hyp_id)
        if not hypothesis:
            return False
        
        # Determine verification status
        if verification_result.get("vulnerability_confirmed", False):
            hypothesis.status = HypothesisStatus.VERIFIED_TRUE.value
        elif verification_result.get("success", False):
            hypothesis.status = HypothesisStatus.VERIFIED_FALSE.value
        else:
            hypothesis.status = HypothesisStatus.INCONCLUSIVE.value
        
        hypothesis.verified_at = datetime.now().isoformat()
        hypothesis.verification_result = verification_result
        hypothesis.proof_of_concept = proof_of_concept
        
        self.update_hypothesis(hypothesis)
        return True
    
    def export_verified_exploits(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """Export all verified exploitable vulnerabilities."""
        
        verified_hypotheses = self.list_hypotheses(
            target=target,
            status=HypothesisStatus.VERIFIED_TRUE
        )
        
        exploits = []
        for hyp in verified_hypotheses:
            exploit_data = asdict(hyp)
            exploits.append(exploit_data)
        
        return exploits
