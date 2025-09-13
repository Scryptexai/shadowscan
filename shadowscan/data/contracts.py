# shadowscan/data/contracts.py
"""
Contract Registry for ShadowScan - Thread-safe persistent storage for discovered contracts.
Replaces static database with dynamic registry for screening sessions.
"""

import json
import os
import threading
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# ===================================================================
# CONTRACT REGISTRY DATA MODELS
# ===================================================================

@dataclass
class ContractInfo:
    """Information about a discovered contract."""
    address: str
    chain: str
    name: Optional[str] = None
    role: str = "unknown"  # token, dex, oracle, proxy, etc.
    abi: Optional[List[Dict]] = None
    bytecode: Optional[str] = None
    is_proxy: bool = False
    implementation: Optional[str] = None
    source_verified: bool = False
    first_seen: Optional[str] = None  # ISO timestamp
    last_updated: Optional[str] = None  # ISO timestamp
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.first_seen is None:
            self.first_seen = datetime.utcnow().isoformat()
        if self.last_updated is None:
            self.last_updated = datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractInfo':
        """Create from dictionary."""
        return cls(**data)

@dataclass
class TargetSession:
    """Information about a screening session target."""
    target: str  # Primary contract address
    chain: str
    session_id: str
    discovered_contracts: Set[str]  # Contract addresses
    session_start: Optional[str] = None
    session_end: Optional[str] = None
    status: str = "active"  # active, completed, partial, error
    
    def __post_init__(self):
        if self.session_start is None:
            self.session_start = datetime.utcnow().isoformat()
        if isinstance(self.discovered_contracts, list):
            self.discovered_contracts = set(self.discovered_contracts)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TargetSession':
        """Create from dictionary."""
        return cls(**data)

# ===================================================================
# CONTRACT REGISTRY - Thread-safe persistent storage
# ===================================================================

class ContractRegistry:
    """
    Thread-safe persistent storage for discovered contracts during screening sessions.
    Handles atomic writes, file locking, and efficient lookups.
    """
    
    def __init__(self, data_dir: str = "shadowscan/data"):
        """
        Initialize contract registry.
        
        Args:
            data_dir: Directory to store registry files
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Registry files
        self.contracts_file = self.data_dir / "contracts.json"
        self.sessions_file = self.data_dir / "sessions.json"
        self.lock_file = self.data_dir / "registry.lock"
        
        # In-memory cache
        self._contracts: Dict[str, ContractInfo] = {}  # chain:address -> ContractInfo
        self._sessions: Dict[str, TargetSession] = {}  # session_id -> TargetSession
        self._target_index: Dict[str, Set[str]] = {}  # target:chain -> session_ids
        
        # Threading
        self._lock = threading.RLock()
        
        # Load existing data
        self._load_registry()
    
    def _acquire_lock(self, timeout: int = 30) -> bool:
        """Acquire file lock for atomic operations."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                if not self.lock_file.exists():
                    self.lock_file.touch()
                    return True
                time.sleep(0.1)
            except Exception:
                time.sleep(0.1)
        return False
    
    def _release_lock(self):
        """Release file lock."""
        try:
            if self.lock_file.exists():
                self.lock_file.unlink()
        except Exception as e:
            logger.warning(f"Failed to release lock: {e}")
    
    def _load_registry(self):
        """Load registry from disk with error handling."""
        with self._lock:
            try:
                # Load contracts
                if self.contracts_file.exists():
                    with open(self.contracts_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        for key, contract_data in data.items():
                            self._contracts[key] = ContractInfo.from_dict(contract_data)
                
                # Load sessions
                if self.sessions_file.exists():
                    with open(self.sessions_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        for session_id, session_data in data.items():
                            # Convert list back to set for discovered_contracts
                            if 'discovered_contracts' in session_data and isinstance(session_data['discovered_contracts'], list):
                                session_data['discovered_contracts'] = set(session_data['discovered_contracts'])
                            session = TargetSession.from_dict(session_data)
                            self._sessions[session_id] = session
                            
                            # Build target index
                            target_key = f"{session.target}:{session.chain}"
                            if target_key not in self._target_index:
                                self._target_index[target_key] = set()
                            self._target_index[target_key].add(session_id)
                
                logger.info(f"Loaded registry: {len(self._contracts)} contracts, {len(self._sessions)} sessions")
                
            except Exception as e:
                logger.error(f"Failed to load registry: {e}")
                # Initialize empty registry
                self._contracts.clear()
                self._sessions.clear()
                self._target_index.clear()
    
    def _save_registry(self):
        """Save registry to disk with atomic write."""
        if not self._acquire_lock():
            raise RuntimeError("Failed to acquire registry lock")
        
        try:
            # Save contracts
            contracts_data = {
                key: contract.to_dict() 
                for key, contract in self._contracts.items()
            }
            
            # Write to temporary file first
            temp_contracts = self.contracts_file.with_suffix('.tmp')
            with open(temp_contracts, 'w', encoding='utf-8') as f:
                json.dump(contracts_data, f, indent=2, ensure_ascii=False)
            temp_contracts.replace(self.contracts_file)
            
            # Save sessions
            sessions_data = {}
            for session_id, session in self._sessions.items():
                session_dict = session.__dict__.copy()
                # Convert set to list for JSON serialization
                session_dict['discovered_contracts'] = list(session_dict['discovered_contracts'])
                sessions_data[session_id] = session_dict
            
            temp_sessions = self.sessions_file.with_suffix('.tmp')
            with open(temp_sessions, 'w', encoding='utf-8') as f:
                json.dump(sessions_data, f, indent=2, ensure_ascii=False)
            temp_sessions.replace(self.sessions_file)
            
            logger.debug("Registry saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save registry: {e}")
            raise
        finally:
            self._release_lock()
    
    def load(self, target: str, chain: str) -> Optional[TargetSession]:
        """
        Load existing session for target/chain combination.
        
        Args:
            target: Target contract address
            chain: Blockchain network
            
        Returns:
            TargetSession if found, None otherwise
        """
        with self._lock:
            target_key = f"{target}:{chain}"
            session_ids = self._target_index.get(target_key, set())
            
            if not session_ids:
                return None
            
            # Return the most recent active session
            for session_id in sorted(session_ids, reverse=True):
                session = self._sessions.get(session_id)
                if session and session.status in ["active", "partial"]:
                    return session
            
            return None
    
    def add_contract(self, target: str, chain: str, address: str, role: str = "unknown", 
                    metadata: Dict[str, Any] = None) -> ContractInfo:
        """
        Add a discovered contract to the registry.
        
        Args:
            target: Primary target address that led to discovery
            chain: Blockchain network
            address: Discovered contract address
            role: Contract role (token, dex, oracle, etc.)
            metadata: Additional contract metadata
            
        Returns:
            ContractInfo object
        """
        with self._lock:
            # Normalize address
            from web3 import Web3
            address_normalized = Web3.to_checksum_address(address)
            target = Web3.to_checksum_address(target)
            
            key = f"{chain}:{address_normalized.lower()}"
            
            # Check if contract already exists
            if key in self._contracts:
                contract = self._contracts[key]
                # Update if needed
                contract.role = role
                contract.address = address.lower()  # Ensure lowercase
                contract.last_updated = datetime.utcnow().isoformat()
                if metadata:
                    contract.metadata.update(metadata)
            else:
                # Create new contract entry
                contract = ContractInfo(
                    address=address.lower(),
                    chain=chain,
                    role=role,
                    metadata=metadata or {}
                )
                self._contracts[key] = contract
            
            # Add to active session
            target_key = f"{target}:{chain}"
            session_ids = self._target_index.get(target_key, set())
            
            if session_ids:
                # Add to most recent active session
                recent_session_id = sorted(session_ids, reverse=True)[0]
                session = self._sessions.get(recent_session_id)
                if session and session.status == "active":
                    session.discovered_contracts.add(address)
            
            # Save changes
            self._save_registry()
            
            logger.debug(f"Added contract {address} (role: {role}) to registry")
            return contract
    
    def get_contracts_for_target(self, target: str, chain: str) -> List[ContractInfo]:
        """
        Get all contracts discovered for a target/chain combination.
        
        Args:
            target: Target contract address
            chain: Blockchain network
            
        Returns:
            List of ContractInfo objects
        """
        with self._lock:
            target_key = f"{target}:{chain}"
            session_ids = self._target_index.get(target_key, set())
            
            contracts = []
            for session_id in session_ids:
                session = self._sessions.get(session_id)
                if session:
                    for contract_address in session.discovered_contracts:
                        key = f"{chain}:{contract_address}"
                        if key in self._contracts:
                            contracts.append(self._contracts[key])
            
            return contracts
    
    def create_session(self, target: str, chain: str, session_id: str) -> TargetSession:
        """
        Create a new screening session.
        
        Args:
            target: Target contract address
            chain: Blockchain network
            session_id: Unique session identifier
            
        Returns:
            TargetSession object
        """
        with self._lock:
            from web3 import Web3
            target = Web3.to_checksum_address(target)
            
            session = TargetSession(
                target=target,
                chain=chain,
                session_id=session_id,
                discovered_contracts=set()
            )
            
            self._sessions[session_id] = session
            
            # Update target index
            target_key = f"{target}:{chain}"
            if target_key not in self._target_index:
                self._target_index[target_key] = set()
            self._target_index[target_key].add(session_id)
            
            # Save changes
            self._save_registry()
            
            logger.info(f"Created session {session_id} for target {target}")
            return session
    
    def update_session(self, session_id: str, status: str = None, 
                      discovered_contracts: Set[str] = None) -> TargetSession:
        """
        Update session status and discovered contracts.
        
        Args:
            session_id: Session identifier
            status: New status (active, completed, partial, error)
            discovered_contracts: Set of discovered contract addresses
            
        Returns:
            Updated TargetSession object
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")
            
            if status:
                session.status = status
                if status in ["completed", "error"]:
                    session.session_end = datetime.utcnow().isoformat()
            
            if discovered_contracts is not None:
                session.discovered_contracts = set(discovered_contracts)
            
            # Save changes
            self._save_registry()
            
            logger.debug(f"Updated session {session_id}: status={status}, contracts={len(session.discovered_contracts)}")
            return session
    
    def get_contract(self, chain: str, address: str) -> Optional[ContractInfo]:
        """
        Get specific contract information.
        
        Args:
            chain: Blockchain network
            address: Contract address
            
        Returns:
            ContractInfo if found, None otherwise
        """
        with self._lock:
            from web3 import Web3
            address = Web3.to_checksum_address(address)
            key = f"{chain}:{address}"
            return self._contracts.get(key)
    
    def find_contracts_by_role(self, chain: str, role: str) -> List[ContractInfo]:
        """
        Find all contracts with specific role on a chain.
        
        Args:
            chain: Blockchain network
            role: Contract role to filter by
            
        Returns:
            List of matching ContractInfo objects
        """
        with self._lock:
            return [
                contract for contract in self._contracts.values()
                if contract.chain == chain and contract.role == role
            ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get registry statistics.
        
        Returns:
            Dictionary with registry statistics
        """
        with self._lock:
            return {
                "total_contracts": len(self._contracts),
                "total_sessions": len(self._sessions),
                "contracts_by_chain": {
                    chain: len([c for c in self._contracts.values() if c.chain == chain])
                    for chain in set(c.chain for c in self._contracts.values())
                },
                "contracts_by_role": {
                    role: len([c for c in self._contracts.values() if c.role == role])
                    for role in set(c.role for c in self._contracts.values())
                },
                "active_sessions": len([s for s in self._sessions.values() if s.status == "active"])
            }
    
    def cleanup_old_sessions(self, days: int = 7):
        """
        Clean up old completed sessions.
        
        Args:
            days: Remove sessions older than this many days
        """
        with self._lock:
            cutoff_time = datetime.utcnow().timestamp() - (days * 24 * 3600)
            sessions_to_remove = []
            
            for session_id, session in self._sessions.items():
                if session.session_end:
                    end_time = datetime.fromisoformat(session.session_end.replace('Z', '+00:00')).timestamp()
                    if end_time < cutoff_time:
                        sessions_to_remove.append(session_id)
            
            for session_id in sessions_to_remove:
                session = self._sessions[session_id]
                target_key = f"{session.target}:{session.chain}"
                
                # Remove from target index
                if target_key in self._target_index:
                    self._target_index[target_key].discard(session_id)
                    if not self._target_index[target_key]:
                        del self._target_index[target_key]
                
                # Remove session
                del self._sessions[session_id]
            
            if sessions_to_remove:
                self._save_registry()
                logger.info(f"Cleaned up {len(sessions_to_remove)} old sessions")

# ===================================================================
# LEGACY STATIC DATABASE (Preserved for reference)
# ===================================================================

VULNERABLE_CONTRACTS = {
    # Historic vulnerabilities for educational analysis
    'dao_hack': {
        'address': '0xbb9bc244d798123fde783fcc1c72d3bb8c189413',
        'description': 'The DAO - Historic reentrancy vulnerability',
        'chain': 'ethereum',
        'vulnerability_types': ['reentrancy', 'governance'],
        'date_discovered': '2016-06-17'
    },
    
    'parity_multisig': {
        'address': '0x863df6bfa4469f3ead0be8f9f2aae51c91a907b4',
        'description': 'Parity Multisig - Accidentally killed wallet',
        'chain': 'ethereum', 
        'vulnerability_types': ['kill_function', 'access_control'],
        'date_discovered': '2017-11-08'
    },
    
    'cream_finance': {
        'address': '0x2db6c82ce72c8d7d770ba1b5f5ed0b6e075066d6',
        'description': 'Cream Finance - Flash loan attack',
        'chain': 'ethereum',
        'vulnerability_types': ['flashloan', 'price_manipulation'],
        'date_discovered': '2021-10-27'
    }
}

# ===================================================================
# MAJOR DEFI PROTOCOLS
# ===================================================================

DEFI_PROTOCOLS = {
    'compound_v2': {
        'comptroller': '0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B',
        'price_oracle': '0x50ce56A3239671Ab62f185704Caedf626352741e',
        'markets': {
            'cDAI': '0x5d3a536E4D6DbD6114cc1Ead35777bAB11E4B98',
            'cUSDT': '0xf650C3d88D12dB855b8bf7D11Be6C55A4e07dCC9',
            'cUSDC': '0x39AA39c021dfbaE8faC545936693aC917d5E7563',
            'cETH': '0x4Ddc2D193948926D02f9B1fE9e1daa0718270ED5',
            'cWBTC': '0xC11b1268C1A384e55C48c2391d8d480264A3A7F4'
        }
    },
    
    'aave_v2': {
        'lending_pool': '0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9',
        'price_oracle': '0xA50ba011c48153De246E5192C8f9258A2ba79Ca9',
        'oracle_sentinel': '0xeE1a2F7dA0A0a4B2F7a0a4B2F7a0a4B2F7a0a4B'
    },
    
    'aave_v3': {
        'pool': '0x87870Bca909D4C42E71d6E2c4C7C5C8D0a3B5f9E',
        'price_oracle': '0x54586bE62E3c3580375aE3723C145253060Ca0C2'
    },
    
    'makerdao': {
        'spot': '0x65C79fcB50Ca1594B025960e539eD7A9a6D434A3',
        'vat': '0x35D1b3F3D7966A1DFe207aa4514C12a259A0492B',
        'price_feeds': {
            'ETH_USD': '0x773616E4d11A78F511299002da57A0a94577F1f4',
            'BTC_USD': '0xaE2C3F21896c02510aA187BdA0791cDA77083708',
            'USDC_USD': '0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6'
        }
    }
}

# ===================================================================
# DEX CONTRACTS
# ===================================================================

DEX_CONTRACTS = {
    'uniswap_v2': {
        'factory': '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f',
        'router': '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',
        'pair_created_topic': '0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9',
        'version': 'v2',
        'name': 'Uniswap V2',
        'init_code_hash': '96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f'
    },
    
    'uniswap_v3': {
        'factory': '0x1F98431c8aD98523631AE4a59f267346ea31F984',
        'router': '0xE592427A0AEce92De3Edee1F18E0157C05861564',
        'router2': '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
        'pool_created_topic': '0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118',
        'version': 'v3',
        'name': 'Uniswap V3'
    },
    
    'sushiswap': {
        'factory': '0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac',
        'router': '0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F',
        'pair_created_topic': '0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9',
        'version': 'v2',
        'name': 'SushiSwap',
        'init_code_hash': 'e18a34eb0e04b04f7a0ac29a6e80748dca96319b42c54d679cb821dca90c6303'
    },
    
    'curve': {
        'registry': '0x90E00ACe148ca3b23Ac1bC8C240C2a7Dd9c2d7f5',
        'crypto_registry': '0x8F942C20D02bEfc377D41445793068908E2250D0',
        'factory': '0xB9fC157394Af804a3578134A6585C0dc9cc990d4',
        'name': 'Curve Finance'
    },
    
    'balancer_v2': {
        'vault': '0xBA12222222228d8Ba445958a75a0704d566BF2C8',
        'factory': '0x8E9aa87E45f74CF4bb9fa6b65A2B4D3CCa60a95b',
        'name': 'Balancer V2'
    }
}

# ===================================================================
# ORACLE CONTRACTS
# ===================================================================

ORACLE_CONTRACTS = {
    'chainlink': {
        'registry': '0x47Fb2585D2C56Fe188D0E6ec628a38b74fceeedf',
        'aggregators': {
            'ETH_USD': '0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419',
            'BTC_USD': '0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c',
            'USDC_USD': '0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6',
            'USDT_USD': '0x3E7d1eAB13ad0104d2750B8863b489D65364e32D',
            'DAI_USD': '0xAed0c38402a5d19df6E4c03F4E2DceD6e29c1ee9',
            'LINK_USD': '0x2c1d072e956AFFC0D435Cb7AC38EF18d24d9127c'
        }
    }
}

# ===================================================================
# MAJOR TOKENS
# ===================================================================

MAJOR_TOKENS = {
    'WETH': {
        'address': '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
        'name': 'Wrapped Ether',
        'symbol': 'WETH',
        'decimals': 18,
        'type': 'wrapped_native'
    },
    
    'USDC': {
        'address': '0xA0b86a33E6441cF0047f25C4AD19f2c7f84951e5',
        'name': 'USD Coin',
        'symbol': 'USDC', 
        'decimals': 6,
        'type': 'stablecoin'
    },
    
    'USDT': {
        'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
        'name': 'Tether USD',
        'symbol': 'USDT',
        'decimals': 6,
        'type': 'stablecoin',
        'known_issues': ['centralization', 'pause_function', 'blacklist']
    },
    
    'DAI': {
        'address': '0x6B175474E89094C44Da98b954EedeAC495271d0F',
        'name': 'Dai Stablecoin',
        'symbol': 'DAI',
        'decimals': 18,
        'type': 'stablecoin'
    },
    
    'WBTC': {
        'address': '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599',
        'name': 'Wrapped BTC',
        'symbol': 'WBTC',
        'decimals': 8,
        'type': 'wrapped_asset'
    },
    
    'UNI': {
        'address': '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984',
        'name': 'Uniswap',
        'symbol': 'UNI',
        'decimals': 18,
        'type': 'governance_token'
    }
}

# ===================================================================
# TEST CONTRACTS (for development and testing)
# ===================================================================

TEST_CONTRACTS = {
    'simple_token': '0x...',  # Add test contract addresses
    'vulnerable_reentrancy': '0x...',
    'flash_loan_target': '0x...',
    'proxy_test': '0x...'
}

# ===================================================================
# HELPER FUNCTIONS
# ===================================================================

def get_contract_info(address: str) -> Dict[str, Any]:
    """Get contract information by address."""
    address = address.lower()
    
    # Check in all categories
    all_contracts = {
        **{k: v for k, v in MAJOR_TOKENS.items()},
        **{k: v for k, v in VULNERABLE_CONTRACTS.items()},
        **{f"dex_{k}": v for k, v in DEX_CONTRACTS.items()},
        **{f"oracle_{k}": v for k, v in ORACLE_CONTRACTS.items()}
    }
    
    for name, info in all_contracts.items():
        contract_address = info.get('address', '').lower()
        if contract_address == address:
            return {
                'name': name,
                'info': info,
                'category': 'token' if name in MAJOR_TOKENS else 'protocol'
            }
    
    return {'name': 'unknown', 'info': {}, 'category': 'unknown'}

def is_known_vulnerable(address: str) -> bool:
    """Check if address is a known vulnerable contract."""
    address = address.lower()
    return any(
        v.get('address', '').lower() == address 
        for v in VULNERABLE_CONTRACTS.values()
    )

def get_dex_info(dex_name: str) -> Dict[str, Any]:
    """Get DEX configuration by name."""
    return DEX_CONTRACTS.get(dex_name, {})

def get_token_info(address: str) -> Dict[str, Any]:
    """Get token information by address."""
    address = address.lower()
    for token_info in MAJOR_TOKENS.values():
        if token_info.get('address', '').lower() == address:
            return token_info
    return {}

def get_base_tokens() -> Dict[str, str]:
    """Get common base tokens for pair calculations."""
    return {
        symbol: info['address'] 
        for symbol, info in MAJOR_TOKENS.items()
        if info.get('type') in ['stablecoin', 'wrapped_native', 'wrapped_asset']
    }

def get_chainlink_feeds() -> Dict[str, str]:
    """Get Chainlink price feed addresses."""
    return ORACLE_CONTRACTS['chainlink']['aggregators']

# ===================================================================
# TARGET CONTRACTS FOR TESTING
# ===================================================================

RECOMMENDED_TARGETS = {
    'beginner': [
        {
            'address': MAJOR_TOKENS['USDT']['address'],
            'name': 'USDT (Tether)',
            'description': 'Centralized stablecoin with known patterns',
            'expected_findings': ['centralization', 'pause_function', 'blacklist']
        },
        {
            'address': MAJOR_TOKENS['UNI']['address'], 
            'name': 'UNI Token',
            'description': 'Governance token with voting mechanics',
            'expected_findings': ['governance_risks', 'voting_power']
        }
    ],
    
    'intermediate': [
        {
            'address': DEX_CONTRACTS['uniswap_v2']['router'],
            'name': 'Uniswap V2 Router',
            'description': 'Complex DEX router with multiple functions',
            'expected_findings': ['slippage_attacks', 'mev_vulnerable']
        }
    ],
    
    'advanced': [
        {
            'address': DEFI_PROTOCOLS['compound_v2']['comptroller'],
            'name': 'Compound Comptroller', 
            'description': 'DeFi lending protocol controller',
            'expected_findings': ['oracle_manipulation', 'liquidation_risks']
        }
    ]
}
