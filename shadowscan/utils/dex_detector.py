"""
DEX Protocol Detection Module
Identifies DEX contracts and protocols for focused vulnerability analysis
"""

import json
import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

@dataclass
class DEXProtocol:
    """DEX Protocol Information"""
    name: str
    router_pattern: str
    factory_pattern: str
    pool_pattern: str
    known_addresses: Set[str]
    vulnerability_focus: List[str]

class DEXDetector:
    """DEX Contract Detection System"""
    
    def __init__(self):
        self.protocols = self._load_protocols()
        self.dex_signatures = self._load_signatures()
        
    def _load_protocols(self) -> Dict[str, DEXProtocol]:
        """Load DEX protocol definitions"""
        return {
            "uniswap_v2": DEXProtocol(
                name="Uniswap V2",
                router_pattern=r"0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
                factory_pattern=r"0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
                pool_pattern=r"0x[0-9a-fA-F]{40}",  # Any pair address
                known_addresses={
                    "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",  # Router
                    "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",  # Factory
                },
                vulnerability_focus=["flashloan", "price_manipulation", "liquidity_pool"]
            ),
            "uniswap_v3": DEXProtocol(
                name="Uniswap V3",
                router_pattern=r"0xE592427A0AEce92De3Edee1F18E0157C05861564",
                factory_pattern=r"0x1F98431c8aD98523631AE4a59f267346ea31F984",
                pool_pattern=r"0x[0-9a-fA-F]{40}",
                known_addresses={
                    "0xE592427A0AEce92De3Edee1F18E0157C05861564",  # Router
                    "0x1F98431c8aD98523631AE4a59f267346ea31F984",  # Factory
                },
                vulnerability_focus=["flashloan", "price_manipulation", "concentrated_liquidity"]
            ),
            "sushiswap": DEXProtocol(
                name="Sushiswap",
                router_pattern=r"0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F",
                factory_pattern=r"0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac",
                pool_pattern=r"0x[0-9a-fA-F]{40}",
                known_addresses={
                    "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F",  # Router
                    "0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac",  # Factory
                },
                vulnerability_focus=["flashloan", "price_manipulation", "liquidity_pool"]
            ),
            "pancakeswap": DEXProtocol(
                name="Pancakeswap",
                router_pattern=r"0x10ED43C718714eb63d5aA57B78B54704E256024E",
                factory_pattern=r"0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73",
                pool_pattern=r"0x[0-9a-fA-F]{40}",
                known_addresses={
                    "0x10ED43C718714eb63d5aA57B78B54704E256024E",  # Router
                    "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73",  # Factory
                },
                vulnerability_focus=["flashloan", "price_manipulation", "liquidity_pool"]
            ),
            "curve": DEXProtocol(
                name="Curve Finance",
                router_pattern=r"0x99a58482BD75Aab4b26353f4D2059b3A03838e2e",
                factory_pattern=r"0x0000000022D53366457F9d5E68Ec105046FC4383",
                pool_pattern=r"0x[0-9a-fA-F]{40}",
                known_addresses={
                    "0x99a58482BD75Aab4b26353f4D2059b3A03838e2e",  # Router
                },
                vulnerability_focus=["flashloan", "price_manipulation", "stablecoin"]
            )
        }
    
    def _load_signatures(self) -> Dict[str, List[str]]:
        """Load function signatures for DEX detection"""
        return {
            "router_functions": [
                "swapExactTokensForTokens",
                "swapTokensForExactTokens", 
                "swapExactETHForTokens",
                "swapTokensForExactETH",
                "getAmountsOut",
                "getAmountsIn",
                "addLiquidity",
                "removeLiquidity"
            ],
            "factory_functions": [
                "createPair",
                "getPair",
                "allPairs",
                "allPairsLength"
            ],
            "pool_functions": [
                "getReserves",
                "token0",
                "token1",
                "swap",
                "mint",
                "burn"
            ]
        }
    
    def detect_dex_contracts(self, contract_address: str, contract_abi: List[Dict]) -> Dict[str, any]:
        """Detect DEX contracts and identify protocol type"""
        result = {
            "is_dex": False,
            "protocol": None,
            "contract_type": None,
            "confidence": 0.0,
            "vulnerability_focus": [],
            "related_contracts": []
        }
        
        if not contract_abi:
            return result
        
        # Extract function names from ABI
        function_names = [item.get("name", "") for item in contract_abi if item.get("type") == "function"]
        
        # Check for router patterns
        router_matches = len(set(function_names) & set(self.dex_signatures["router_functions"]))
        factory_matches = len(set(function_names) & set(self.dex_signatures["factory_functions"]))
        pool_matches = len(set(function_names) & set(self.dex_signatures["pool_functions"]))
        
        # Determine contract type and protocol
        if router_matches >= 3:
            result["contract_type"] = "router"
            result["is_dex"] = True
            result["confidence"] = min(router_matches / len(self.dex_signatures["router_functions"]), 1.0)
            
            # Identify specific protocol
            for protocol_name, protocol in self.protocols.items():
                if re.match(protocol.router_pattern, contract_address, re.IGNORECASE):
                    result["protocol"] = protocol_name
                    result["vulnerability_focus"] = protocol.vulnerability_focus
                    break
        
        elif factory_matches >= 2:
            result["contract_type"] = "factory"
            result["is_dex"] = True
            result["confidence"] = min(factory_matches / len(self.dex_signatures["factory_functions"]), 1.0)
            
            for protocol_name, protocol in self.protocols.items():
                if re.match(protocol.factory_pattern, contract_address, re.IGNORECASE):
                    result["protocol"] = protocol_name
                    result["vulnerability_focus"] = protocol.vulnerability_focus
                    break
        
        elif pool_matches >= 2:
            result["contract_type"] = "pool"
            result["is_dex"] = True
            result["confidence"] = min(pool_matches / len(self.dex_signatures["pool_functions"]), 1.0)
        
        return result
    
    def find_related_dex_contracts(self, target_address: str, transactions: List[Dict]) -> List[Dict]:
        """Find DEX contracts related to target through transactions"""
        related_contracts = []
        
        for tx in transactions:
            # Check from address
            if tx.get("from") and tx["from"].lower() != target_address.lower():
                related_contracts.append({
                    "address": tx["from"],
                    "relationship": "sender",
                    "transaction_hash": tx.get("hash", "")
                })
            
            # Check to address
            if tx.get("to") and tx["to"].lower() != target_address.lower():
                related_contracts.append({
                    "address": tx["to"],
                    "relationship": "receiver",
                    "transaction_hash": tx.get("hash", "")
                })
            
            # Check contract addresses in transaction logs
            if tx.get("logs"):
                for log in tx["logs"]:
                    if log.get("address") and log["address"].lower() != target_address.lower():
                        related_contracts.append({
                            "address": log["address"],
                            "relationship": "log_contract",
                            "transaction_hash": tx.get("hash", "")
                        })
        
        # Remove duplicates and prioritize DEX contracts
        unique_contracts = {}
        for contract in related_contracts:
            addr = contract["address"].lower()
            if addr not in unique_contracts:
                unique_contracts[addr] = contract
        
        return list(unique_contracts.values())
    
    def prioritize_dex_targets(self, contracts: List[Dict]) -> List[Dict]:
        """Prioritize DEX contracts for vulnerability scanning"""
        prioritized = []
        
        for contract in contracts:
            address = contract["address"]
            
            # Check against known DEX addresses
            for protocol_name, protocol in self.protocols.items():
                if address.lower() in [addr.lower() for addr in protocol.known_addresses]:
                    prioritized.append({
                        **contract,
                        "protocol": protocol_name,
                        "priority": "high",
                        "vulnerability_focus": protocol.vulnerability_focus
                    })
                    break
            else:
                # Unknown contract, mark for analysis
                prioritized.append({
                    **contract,
                    "protocol": "unknown",
                    "priority": "medium",
                    "vulnerability_focus": ["general_dex_analysis"]
                })
        
        # Sort by priority
        priority_order = {"high": 0, "medium": 1, "low": 2}
        prioritized.sort(key=lambda x: priority_order.get(x["priority"], 2))
        
        return prioritized
    
    def get_dex_vulnerability_patterns(self, protocol: str, contract_type: str) -> List[str]:
        """Get vulnerability patterns specific to DEX type"""
        patterns = {
            "router": [
                "flashloan_vulnerability",
                "price_manipulation",
                "front_running",
                "slippage_manipulation"
            ],
            "pool": [
                "liquidity_drain",
                "impermanent_loss_exploit",
                "price_oracle_manipulation",
                "sandwich_attack"
            ],
            "factory": [
                "pair_creation_vulnerability",
                "authorization_bypass",
                "contract_impersonation"
            ]
        }
        
        base_patterns = patterns.get(contract_type, ["general_dex_vulnerability"])
        
        # Add protocol-specific patterns
        if protocol == "uniswap_v3":
            base_patterns.extend(["concentrated_liquidity_exploit", "fee_manipulation"])
        elif protocol == "curve":
            base_patterns.extend(["stablecoin_manipulation", "crypto_pools_exploit"])
        
        return base_patterns