import asyncio
import json
import re
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from web3 import Web3
from shadowscan.adapters.evm.provider import EVMProvider

@dataclass
class FunctionInfo:
    selector: str
    signature: str
    name: str
    inputs: List[Dict[str, Any]]
    outputs: List[Dict[str, Any]]
    mutability: str
    visibility: str
    access_controlled: bool = False
    modifiers: List[str] = field(default_factory=list)

@dataclass 
class EventInfo:
    signature: str
    name: str
    inputs: List[Dict[str, Any]]
    topic_hash: str

@dataclass
class StorageSlot:
    slot: int
    name: Optional[str]
    type_info: str
    access_pattern: str

@dataclass
class ContractIntelligence:
    address: str
    name: Optional[str]
    functions: List[FunctionInfo]
    events: List[EventInfo]
    storage_layout: List[StorageSlot]
    is_proxy: bool
    implementation: Optional[str]
    owner_functions: List[str]
    mint_functions: List[str]
    transfer_functions: List[str]
    sensitive_functions: List[str]
    upgradeable: bool
    access_controls: Dict[str, Any]
    compiler_version: Optional[str] = None
    source_verified: bool = False


class ContractIntelCollector:
    """Enhanced contract intelligence collector with proxy support."""
    
    def __init__(self, provider: EVMProvider):
        self.provider = provider
        
        # Enhanced sensitive selectors database
        self.SENSITIVE_SELECTORS = {
            "0xa9059cbb": "transfer(address,uint256)",
            "0x23b872dd": "transferFrom(address,address,uint256)", 
            "0x095ea7b3": "approve(address,uint256)",
            "0x40c10f19": "mint(address,uint256)",
            "0x42966c68": "burn(uint256)",
            "0x8da5cb5b": "owner()",
            "0xf2fde38b": "transferOwnership(address)",
            "0x9dc29fac": "burn(address,uint256)",
            "0xa457c2d7": "decreaseAllowance(address,uint256)",
            "0x39509351": "increaseAllowance(address,uint256)",
            "0x70a08231": "balanceOf(address)",
            "0x313ce567": "decimals()",
            "0x06fdde03": "name()",
            "0x95d89b41": "symbol()",
            "0x18160ddd": "totalSupply()",
            "0xdd62ed3e": "allowance(address,address)",
            # Oracle/Price related
            "0x50d25bcd": "latestRoundData()",
            "0x8205bf6a": "getReserves()",
            "0x0902f1ac": "getReserves()",
            # Admin functions
            "0x8f32d59b": "isOwner()",
            "0x715018a6": "renounceOwnership()",
        }
    
    async def collect_intelligence(self, 
                                 contract_address: str, 
                                 include_storage: bool = True) -> ContractIntelligence:
        """Enhanced intelligence collection with proxy resolution."""
        
        # Get basic contract info
        contract_info = await self.provider.get_contract_info(contract_address)
        
        # If it's a proxy, try to get implementation ABI
        target_abi = contract_info.abi
        if contract_info.is_proxy and contract_info.implementation:
            try:
                impl_info = await self.provider.get_contract_info(contract_info.implementation)
                if impl_info.abi:
                    target_abi = impl_info.abi
                    print(f"Using implementation ABI: {contract_info.implementation}")
            except Exception as e:
                print(f"Failed to get implementation ABI: {e}")
        
        # Analyze functions (with fallback to bytecode analysis)
        functions = await self._analyze_functions(contract_address, target_abi)
        
        # If no functions found via ABI, try bytecode analysis
        if not functions:
            print("No ABI available, attempting bytecode analysis...")
            functions = await self._extract_functions_from_bytecode(contract_address)
        
        # Analyze events
        events = await self._analyze_events(target_abi)
        
        # Analyze storage
        storage_layout = []
        if include_storage:
            storage_layout = await self._analyze_storage(contract_address)
        
        # Categorize functions
        owner_functions = [f.name for f in functions if self._is_owner_function(f)]
        mint_functions = [f.name for f in functions if self._is_mint_function(f)]
        transfer_functions = [f.name for f in functions if self._is_transfer_function(f)]
        sensitive_functions = [f.name for f in functions if self._is_sensitive_function(f)]
        
        # Analyze access controls
        access_controls = await self._analyze_access_controls(functions)
        
        # Check upgradeability
        upgradeable = await self._check_upgradeability(contract_address, functions)
        
        return ContractIntelligence(
            address=contract_address,
            name=await self._get_contract_name(functions),
            functions=functions,
            events=events,
            storage_layout=storage_layout,
            is_proxy=contract_info.is_proxy,
            implementation=contract_info.implementation,
            owner_functions=owner_functions,
            mint_functions=mint_functions,
            transfer_functions=transfer_functions,
            sensitive_functions=sensitive_functions,
            upgradeable=upgradeable,
            access_controls=access_controls,
            source_verified=contract_info.source_verified
        )
    
    async def _analyze_functions(self, 
                               contract_address: str, 
                               abi: Optional[List[Dict]]) -> List[FunctionInfo]:
        """Analyze contract functions from ABI."""
        functions = []
        
        if not abi:
            return functions
        
        for item in abi:
            if item.get("type") != "function":
                continue
                
            name = item["name"]
            inputs = item.get("inputs", [])
            outputs = item.get("outputs", [])
            
            input_types = [inp["type"] for inp in inputs]
            signature = f"{name}({','.join(input_types)})"
            
            selector = Web3.keccak(text=signature)[:4].hex()
            
            mutability = item.get("stateMutability", "nonpayable")
            visibility = "public"
            
            access_controlled = self._has_access_control(name, inputs)
            
            functions.append(FunctionInfo(
                selector=selector,
                signature=signature,
                name=name,
                inputs=inputs,
                outputs=outputs,
                mutability=mutability,
                visibility=visibility,
                access_controlled=access_controlled
            ))
        
        return functions
    
    async def _extract_functions_from_bytecode(self, contract_address: str) -> List[FunctionInfo]:
        """Enhanced bytecode analysis for function extraction."""
        contract_info = await self.provider.get_contract_info(contract_address)
        bytecode = contract_info.bytecode.lower()
        
        functions = []
        
        # Look for function selector patterns in bytecode
        # Pattern: PUSH4 followed by function selector
        selector_matches = re.findall(r'63([0-9a-f]{8})', bytecode)
        
        # Also look for common ERC20 patterns
        erc20_patterns = [
            "a9059cbb",  # transfer
            "23b872dd",  # transferFrom  
            "095ea7b3",  # approve
            "70a08231",  # balanceOf
            "18160ddd",  # totalSupply
            "313ce567",  # decimals
            "06fdde03",  # name
            "95d89b41",  # symbol
        ]
        
        found_selectors = set(selector_matches)
        
        # Add common selectors if bytecode is large enough (likely implements them)
        if len(bytecode) > 2000:  # Reasonable size for ERC20
            for pattern in erc20_patterns:
                if pattern in bytecode:
                    found_selectors.add(pattern)
        
        # Convert selectors to function info
        for selector_hex in found_selectors:
            selector = "0x" + selector_hex
            signature = self.SENSITIVE_SELECTORS.get(selector, f"unknown_{selector_hex}")
            name = signature.split("(")[0]
            
            functions.append(FunctionInfo(
                selector=selector,
                signature=signature,
                name=name,
                inputs=[],  # Unknown from bytecode
                outputs=[],
                mutability="unknown",
                visibility="external",
                access_controlled=False
            ))
        
        return functions
    
    async def _analyze_events(self, abi: Optional[List[Dict]]) -> List[EventInfo]:
        """Analyze contract events."""
        events = []
        
        if not abi:
            return events
            
        for item in abi:
            if item.get("type") != "event":
                continue
                
            name = item["name"]
            inputs = item.get("inputs", [])
            
            input_types = [inp["type"] for inp in inputs]
            signature = f"{name}({','.join(input_types)})"
            
            topic_hash = Web3.keccak(text=signature).hex()
            
            events.append(EventInfo(
                signature=signature,
                name=name,
                inputs=inputs,
                topic_hash=topic_hash
            ))
        
        return events
    
    async def _analyze_storage(self, contract_address: str) -> List[StorageSlot]:
        """Analyze storage layout."""
        storage_slots = []
        
        common_slots = {
            0: "owner",
            1: "totalSupply", 
            2: "balances_mapping",
            3: "allowances_mapping",
            # EIP-1967 proxy slots
            int("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16): "implementation",
            int("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", 16): "admin"
        }
        
        for slot, name in common_slots.items():
            try:
                value = await self.provider.get_storage_at(contract_address, slot)
                if value != "0x" + "00" * 32:
                    storage_slots.append(StorageSlot(
                        slot=slot,
                        name=name,
                        type_info="uint256" if name in ["totalSupply"] else "address",
                        access_pattern="read_write"
                    ))
            except Exception:
                continue
        
        return storage_slots
    
    def _is_owner_function(self, func: FunctionInfo) -> bool:
        owner_keywords = ["owner", "admin", "governance", "onlyOwner"]
        return any(keyword.lower() in func.name.lower() for keyword in owner_keywords)
    
    def _is_mint_function(self, func: FunctionInfo) -> bool:
        mint_keywords = ["mint", "_mint", "mintMinerReward", "issue"]
        return any(keyword.lower() in func.name.lower() for keyword in mint_keywords)
    
    def _is_transfer_function(self, func: FunctionInfo) -> bool:
        transfer_keywords = ["transfer", "transferFrom", "send", "sendValue"]
        return any(keyword.lower() in func.name.lower() for keyword in transfer_keywords)
    
    def _is_sensitive_function(self, func: FunctionInfo) -> bool:
        return (func.selector in self.SENSITIVE_SELECTORS or 
                func.mutability == "payable" or
                self._is_owner_function(func) or
                self._is_mint_function(func))
    
    def _has_access_control(self, name: str, inputs: List[Dict]) -> bool:
        access_patterns = ["onlyOwner", "onlyAdmin", "onlyGovernance", "requireAuth"]
        return any(pattern.lower() in name.lower() for pattern in access_patterns)
    
    async def _analyze_access_controls(self, functions: List[FunctionInfo]) -> Dict[str, Any]:
        controls = {
            "has_owner": False,
            "has_admin": False,
            "protected_functions": [],
            "public_sensitive": []
        }
        
        for func in functions:
            if self._is_owner_function(func):
                controls["has_owner"] = True
                
            if "admin" in func.name.lower():
                controls["has_admin"] = True
                
            if func.access_controlled:
                controls["protected_functions"].append(func.name)
            elif self._is_sensitive_function(func):
                controls["public_sensitive"].append(func.name)
        
        return controls
    
    async def _check_upgradeability(self, 
                                  contract_address: str, 
                                  functions: List[FunctionInfo]) -> bool:
        try:
            impl_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
            impl_value = await self.provider.get_storage_at(contract_address, impl_slot)
            if impl_value != "0x" + "00" * 32:
                return True
        except Exception:
            pass
        
        upgrade_keywords = ["upgrade", "setImplementation", "initialize"]
        for func in functions:
            if any(keyword.lower() in func.name.lower() for keyword in upgrade_keywords):
                return True
        
        return False
    
    async def _get_contract_name(self, functions: List[FunctionInfo]) -> Optional[str]:
        for func in functions:
            if func.name in ["name", "getName"]:
                return func.name
        return None
