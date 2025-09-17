# shadowscan/utils/schema.py
"""Extended JSON schema for comprehensive screening results."""

from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import json
from datetime import datetime

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high" 
    CRITICAL = "critical"

class ProxyType(Enum):
    EIP1967 = "EIP-1967"
    TRANSPARENT = "Transparent"
    BEACON = "Beacon"
    UUPS = "UUPS"
    MINIMAL = "Minimal"
    NONE = "None"

class ScreeningMode(Enum):
    FORK = "fork"
    MAINNET = "mainnet"

class DepthLevel(Enum):
    SHALLOW = "shallow"
    FULL = "full"

@dataclass
class ProxyInfo:
    is_proxy: bool = False
    proxy_type: ProxyType = ProxyType.NONE
    implementation: Optional[str] = None
    admin: Optional[str] = None
    upgradeability_risk: RiskLevel = RiskLevel.LOW
    admin_type: str = "unknown"  # "eoa", "multisig", "timelock", "contract"

@dataclass
class FunctionSummary:
    total: int = 0
    sensitive: List[str] = field(default_factory=list)
    payable: List[str] = field(default_factory=list)
    external: List[str] = field(default_factory=list)

@dataclass
class Transaction:
    hash: str
    from_addr: str
    to: Optional[str]
    input: str
    value: str
    block: int
    timestamp: int
    gas_used: Optional[int] = None
    trace: Optional[Dict[str, Any]] = None

@dataclass
class Event:
    name: str
    tx_hash: str
    args: Dict[str, Any]
    block: int
    log_index: int
    address: str

@dataclass
class Balance:
    address: str
    balance: str
    token_address: Optional[str] = None
    decimals: int = 18

@dataclass
class Allowance:
    owner: str
    spender: str
    amount: str
    token_address: Optional[str] = None

@dataclass
class StorageSample:
    slot: str
    value: str
    interpreted: Optional[str] = None

@dataclass
class StateSnapshot:
    balances: List[Balance] = field(default_factory=list)
    allowances: List[Allowance] = field(default_factory=list)
    storage_samples: List[StorageSample] = field(default_factory=list)

@dataclass
class DexReference:
    pair: str
    router: str
    reserves: List[str]
    liquidity_usd: float
    depth_score: float
    dex_name: str = "unknown"
    fee_tier: Optional[str] = None

@dataclass
class OracleInfo:
    type: str = "unknown"  # "TWAP", "Chainlink", "Custom"
    sources: List[str] = field(default_factory=list)
    twap_window: Optional[int] = None
    twap_risk_score: float = 0.0
    price_feeds: List[str] = field(default_factory=list)

@dataclass
class Hypothesis:
    id: str
    category: str
    confidence: float
    description: str
    severity: RiskLevel = RiskLevel.LOW
    evidence: List[str] = field(default_factory=list)

@dataclass
class GraphNode:
    id: str
    label: str
    type: str  # "target", "contract", "dex", "oracle", "token"
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GraphEdge:
    source: str
    target: str
    type: str  # "call", "event", "transfer", "pair", "oracle"
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class InteractionGraph:
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScreeningSession:
    session_id: str
    target: str
    chain: str
    mode: ScreeningMode
    depth: DepthLevel
    block: int
    timestamp: str
    
    # Core contract data
    abi: Optional[List[Dict[str, Any]]] = None
    bytecode: Optional[str] = None
    is_proxy: bool = False
    proxy_info: ProxyInfo = field(default_factory=ProxyInfo)
    
    # Function analysis
    functions_summary: FunctionSummary = field(default_factory=FunctionSummary)
    
    # Transaction data
    txs: List[Transaction] = field(default_factory=list)
    events: List[Event] = field(default_factory=list)
    
    # State analysis
    state_snapshot: StateSnapshot = field(default_factory=StateSnapshot)
    
    # DeFi intelligence
    dex_refs: List[DexReference] = field(default_factory=list)
    oracle: OracleInfo = field(default_factory=OracleInfo)
    
    # Graph analysis
    interaction_graph: Optional[InteractionGraph] = None
    interaction_graph_path: Optional[str] = None
    
    # Detection results
    hypotheses: List[Hypothesis] = field(default_factory=list)
    
    # DEX Analysis (Ecosystem Tracking)
    is_dex: bool = False
    dex_protocol: Optional[str] = None
    dex_contract_type: Optional[str] = None
    dex_confidence: float = 0.0
    dex_analysis: Dict[str, Any] = field(default_factory=dict)
    related_contracts: List[Dict[str, Any]] = field(default_factory=list)
    vulnerability_patterns: List[str] = field(default_factory=list)
    high_priority_targets: int = 0
    
    # Metadata
    execution_time: float = 0.0
    rpc_calls_made: int = 0
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, handling enums and datetime objects."""
        return asdict(self)
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        def json_encoder(obj):
            if isinstance(obj, Enum):
                return obj.value
            if isinstance(obj, datetime):
                return obj.isoformat()
            return str(obj)
        
        return json.dumps(self.to_dict(), indent=indent, default=json_encoder)
