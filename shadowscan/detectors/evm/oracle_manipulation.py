"""
ShadowScan Oracle Manipulation Detector

Detects vulnerabilities related to price oracle manipulation in DeFi protocols:
- Single point of failure oracles
- Manipulatable DEX-based price feeds
- TWAP (Time Weighted Average Price) vulnerabilities
- Flash loan attack surfaces via oracle manipulation
"""

import asyncio
import math
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from decimal import Decimal

from shadowscan.adapters.evm.provider import EVMProvider
from shadowscan.models.findings import Finding, SeverityLevel

@dataclass
class OracleInfo:
    address: str
    oracle_type: str  # chainlink, uniswap_v2, uniswap_v3, custom
    price_source: str
    update_frequency: int
    last_update: int
    price_deviation_threshold: float
    is_manipulatable: bool
    manipulation_cost: Optional[float] = None

@dataclass
class DEXPoolInfo:
    address: str
    token0: str
    token1: str
    reserves0: int
    reserves1: int
    total_liquidity: int
    pool_type: str  # uniswap_v2, uniswap_v3, curve, balancer
    fee_tier: Optional[int] = None
    manipulation_cost_usd: Optional[float] = None

@dataclass
class OracleVulnerability:
    vulnerability_type: str
    severity: str
    description: str
    affected_functions: List[str]
    exploitation_cost: float
    potential_profit: float
    evidence: Dict[str, Any]


class OracleManipulationDetector:
    """Detects oracle manipulation vulnerabilities."""
    
    def __init__(self, provider: EVMProvider):
        self.provider = provider
        
        # Common oracle contract addresses (Ethereum mainnet)
        self.CHAINLINK_FEEDS = {
            "ETH/USD": "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419",
            "BTC/USD": "0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c",
            "USDC/USD": "0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6"
        }
        
        # Common DEX factory addresses
        self.DEX_FACTORIES = {
            "uniswap_v2": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
            "uniswap_v3": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
            "sushiswap": "0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac"
        }
        
        # Oracle-related function signatures
        self.ORACLE_FUNCTIONS = {
            "0x50d25bcd": "latestRoundData()",  # Chainlink
            "0x8205bf6a": "getReserves()",      # Uniswap V2
            "0x70a08231": "balanceOf(address)", # ERC20 balance
            "0x313ce567": "decimals()",        # Token decimals
            "0x0902f1ac": "getReserves()",     # Pair reserves
        }
    
    async def screen(self, target_contract: str) -> Dict[str, Any]:
        """Screen for oracle manipulation vulnerabilities."""
        
        findings = []
        
        # 1. Analyze target contract for oracle usage
        oracle_usage = await self._analyze_oracle_usage(target_contract)
        
        # 2. Check for DEX-based price feeds
        dex_oracles = await self._analyze_dex_oracles(target_contract)
        
        # 3. Analyze TWAP vulnerabilities
        twap_vulns = await self._analyze_twap_vulnerabilities(target_contract, dex_oracles)
        
        # 4. Check for single point of failure
        spof_vulns = await self._analyze_single_point_failures(oracle_usage)
        
        # 5. Calculate manipulation costs
        manipulation_costs = await self._calculate_manipulation_costs(dex_oracles)
        
        # Generate findings
        for vuln in twap_vulns + spof_vulns:
            findings.append({
                "id": f"ORACLE_MANIP_{vuln.vulnerability_type.upper()}",
                "title": f"Oracle Manipulation: {vuln.vulnerability_type}",
                "description": vuln.description,
                "severity": vuln.severity,
                "category": "oracle_manipulation",
                "confidence": self._calculate_confidence(vuln),
                "exploitability_score": self._calculate_exploitability(vuln),
                "affected_functions": vuln.affected_functions,
                "evidence": vuln.evidence,
                "exploitation_cost": vuln.exploitation_cost,
                "potential_profit": vuln.potential_profit
            })
        
        return {
            "findings": findings,
            "oracle_usage": oracle_usage,
            "dex_oracles": dex_oracles,
            "manipulation_costs": manipulation_costs,
            "metadata": {
                "total_oracles_found": len(oracle_usage),
                "manipulatable_oracles": len([o for o in oracle_usage if o.is_manipulatable]),
                "min_manipulation_cost": min([c for c in manipulation_costs.values()] or [float('inf')])
            }
        }
    
    async def _analyze_oracle_usage(self, contract_address: str) -> List[OracleInfo]:
        """Analyze how the contract uses price oracles."""
        oracles = []
        
        # Get contract info
        try:
            contract_info = await self.provider.get_contract_info(contract_address)
            
            if not contract_info.abi:
                return oracles
            
            # Look for oracle-related function calls in the contract
            for function in contract_info.abi:
                if function.get("type") != "function":
                    continue
                
                # Check if function likely uses oracles
                if self._function_uses_oracle(function):
                    # Try to trace oracle calls (simplified)
                    oracle_addresses = await self._trace_oracle_calls(
                        contract_address, function["name"]
                    )
                    
                    for oracle_addr in oracle_addresses:
                        oracle_type = await self._identify_oracle_type(oracle_addr)
                        
                        oracles.append(OracleInfo(
                            address=oracle_addr,
                            oracle_type=oracle_type,
                            price_source="unknown",
                            update_frequency=0,
                            last_update=0,
                            price_deviation_threshold=0.05,  # 5% default
                            is_manipulatable=oracle_type in ["uniswap_v2", "uniswap_v3", "custom"]
                        ))
            
        except Exception as e:
            pass  # Continue with other analyses
        
        return oracles
    
    async def _analyze_dex_oracles(self, contract_address: str) -> List[DEXPoolInfo]:
        """Analyze DEX-based oracle usage."""
        dex_pools = []
        
        # Check common DEX patterns
        for dex_name, factory_addr in self.DEX_FACTORIES.items():
            pools = await self._find_related_pools(contract_address, factory_addr, dex_name)
            dex_pools.extend(pools)
        
        # Calculate manipulation costs for each pool
        for pool in dex_pools:
            pool.manipulation_cost_usd = await self._estimate_pool_manipulation_cost(pool)
        
        return dex_pools
    
    async def _find_related_pools(self, 
                                 contract_address: str,
                                 factory_address: str, 
                                 dex_type: str) -> List[DEXPoolInfo]:
        """Find DEX pools that the contract might use for pricing."""
        pools = []
        
        # This is simplified - in reality, we'd trace through contract calls
        # to find which pools are actually used for pricing
        
        # For demonstration, return mock pool data
        if dex_type == "uniswap_v2":
            pools.append(DEXPoolInfo(
                address="0xa478c2975ab1ea89e8196811f51a7b7ade33eb11",  # ETH/DAI
                token0="0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  # WETH
                token1="0x6B175474E89094C44Da98b954EedeAC495271d0F",  # DAI
                reserves0=50000 * 10**18,  # Mock reserves
                reserves1=100000000 * 10**18,
                total_liquidity=150000000,
                pool_type=dex_type
            ))
        
        return pools
    
    async def _analyze_twap_vulnerabilities(self, 
                                          contract_address: str,
                                          dex_oracles: List[DEXPoolInfo]) -> List[OracleVulnerability]:
        """Analyze TWAP (Time Weighted Average Price) vulnerabilities."""
        vulnerabilities = []
        
        for pool in dex_oracles:
            # Check if TWAP window is too short
            twap_window = await self._get_twap_window(contract_address, pool.address)
            
            if twap_window and twap_window < 600:  # Less than 10 minutes
                vulnerabilities.append(OracleVulnerability(
                    vulnerability_type="short_twap_window",
                    severity="HIGH",
                    description=f"TWAP window of {twap_window} seconds is too short, "
                              f"allowing for manipulation within a single block or few blocks",
                    affected_functions=await self._get_functions_using_pool(contract_address, pool.address),
                    exploitation_cost=pool.manipulation_cost_usd or 100000,  # Default $100k
                    potential_profit=500000,  # Estimated based on protocol TVL
                    evidence={
                        "pool_address": pool.address,
                        "twap_window": twap_window,
                        "pool_liquidity": pool.total_liquidity,
                        "manipulation_cost": pool.manipulation_cost_usd
                    }
                ))
            
            # Check for single-block manipulation possibility
            if await self._can_manipulate_single_block(pool):
                vulnerabilities.append(OracleVulnerability(
                    vulnerability_type="single_block_manipulation",
                    severity="CRITICAL",
                    description="Pool can be manipulated within a single block using flash loans",
                    affected_functions=await self._get_functions_using_pool(contract_address, pool.address),
                    exploitation_cost=pool.manipulation_cost_usd or 50000,
                    potential_profit=1000000,
                    evidence={
                        "pool_address": pool.address,
                        "current_reserves": [pool.reserves0, pool.reserves1],
                        "estimated_flash_loan_needed": pool.manipulation_cost_usd
                    }
                ))
        
        return vulnerabilities
    
    async def _analyze_single_point_failures(self, oracles: List[OracleInfo]) -> List[OracleVulnerability]:
        """Analyze single point of failure vulnerabilities."""
        vulnerabilities = []
        
        # Group oracles by type
        oracle_types = {}
        for oracle in oracles:
            oracle_types.setdefault(oracle.oracle_type, []).append(oracle)
        
        # Check for single oracle dependency
        if len(oracles) == 1:
            oracle = oracles[0]
            vulnerabilities.append(OracleVulnerability(
                vulnerability_type="single_oracle_dependency",
                severity="HIGH",
                description="Contract depends on a single price oracle, creating a single point of failure",
                affected_functions=["price_dependent_functions"],  # Would be more specific in real implementation
                exploitation_cost=0,  # No cost to exploit oracle failure
                potential_profit=0,  # Depends on the specific vulnerability
                evidence={
                    "oracle_address": oracle.address,
                    "oracle_type": oracle.oracle_type,
                    "is_manipulatable": oracle.is_manipulatable
                }
            ))
        
        # Check for lack of oracle diversity
        manipulatable_count = len([o for o in oracles if o.is_manipulatable])
        if manipulatable_count > len(oracles) * 0.7:  # More than 70% manipulatable
            vulnerabilities.append(OracleVulnerability(
                vulnerability_type="insufficient_oracle_diversity",
                severity="MEDIUM",
                description=f"{manipulatable_count}/{len(oracles)} oracles are manipulatable",
                affected_functions=["price_dependent_functions"],
                exploitation_cost=min([o.manipulation_cost for o in oracles if o.manipulation_cost] or [100000]),
                potential_profit=200000,
                evidence={
                    "total_oracles": len(oracles),
                    "manipulatable_oracles": manipulatable_count,
                    "oracle_types": list(oracle_types.keys())
                }
            ))
        
        return vulnerabilities
    
    async def _calculate_manipulation_costs(self, dex_pools: List[DEXPoolInfo]) -> Dict[str, float]:
        """Calculate the cost to manipulate each DEX pool."""
        costs = {}
        
        for pool in dex_pools:
            if pool.pool_type == "uniswap_v2":
                # Simplified cost calculation for Uniswap V2
                # Real calculation would consider slippage, fees, and desired price impact
                cost = await self._calculate_uniswap_v2_manipulation_cost(pool)
                costs[pool.address] = cost
        
        return costs
    
    async def _calculate_uniswap_v2_manipulation_cost(self, pool: DEXPoolInfo) -> float:
        """Calculate cost to manipulate Uniswap V2 pool price."""
        
        # Simplified calculation: cost to move price by 10%
        # Real implementation would be more sophisticated
        k = pool.reserves0 * pool.reserves1  # Constant product
        
        # To increase token1 price by 10%, we need to buy token1 (remove from pool)
        new_reserve1 = pool.reserves1 * 0.9  # 10% reduction
        new_reserve0 = k / new_reserve1  # Maintain constant product
        
        tokens_needed = new_reserve0 - pool.reserves0
        
        # Convert to USD (simplified - would use real price feeds)
        cost_usd = tokens_needed * 2000  # Assume $2000 per ETH
        
        return cost_usd
    
    def _function_uses_oracle(self, function: Dict[str, Any]) -> bool:
        """Check if function likely uses price oracles."""
        oracle_keywords = [
            "price", "getPrice", "latestRoundData", "getReserves",
            "oracle", "feed", "rate", "exchange"
        ]
        
        func_name = function.get("name", "").lower()
        return any(keyword.lower() in func_name for keyword in oracle_keywords)
    
    async def _trace_oracle_calls(self, contract_address: str, function_name: str) -> List[str]:
        """Trace oracle contract calls (simplified implementation)."""
        # This would require transaction tracing or static analysis
        # For now, return mock addresses
        return ["0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"]  # Mock Chainlink feed
    
    async def _identify_oracle_type(self, oracle_address: str) -> str:
        """Identify the type of oracle."""
        
        # Check if it's a known Chainlink feed
        if oracle_address in self.CHAINLINK_FEEDS.values():
            return "chainlink"
        
        # Check contract code patterns (simplified)
        try:
            contract_info = await self.provider.get_contract_info(oracle_address)
            bytecode = contract_info.bytecode.lower()
            
            if "uniswap" in bytecode or "getreserves" in bytecode:
                return "uniswap_v2"
            elif "getuserdata" in bytecode:
                return "uniswap_v3" 
            else:
                return "custom"
                
        except Exception:
            return "unknown"
    
    async def _get_twap_window(self, contract_address: str, pool_address: str) -> Optional[int]:
        """Get TWAP window duration in seconds."""
        # This would analyze the contract to find TWAP window configuration
        # For now, return mock data
        return 300  # 5 minutes (potentially vulnerable)
    
    async def _get_functions_using_pool(self, contract_address: str, pool_address: str) -> List[str]:
        """Get functions that use specific pool for pricing."""
        # This would trace contract execution to find functions using the pool
        return ["getPrice", "liquidate", "borrow"]
    
    async def _can_manipulate_single_block(self, pool: DEXPoolInfo) -> bool:
        """Check if pool can be manipulated within a single block."""
        # Consider liquidity depth vs typical flash loan sizes
        flash_loan_capacity = 100000 * 10**18  # Mock: 100k ETH flash loan capacity
        
        # If manipulation cost is less than flash loan capacity, single-block is possible
        return (pool.manipulation_cost_usd or 0) < flash_loan_capacity * 2000  # ETH price
    
    async def _estimate_pool_manipulation_cost(self, pool: DEXPoolInfo) -> float:
        """Estimate cost to manipulate pool price by significant amount."""
        if pool.pool_type == "uniswap_v2":
            return await self._calculate_uniswap_v2_manipulation_cost(pool)
        else:
            # Default estimation
            return pool.total_liquidity * 0.05  # 5% of liquidity
    
    def _calculate_confidence(self, vuln: OracleVulnerability) -> float:
        """Calculate confidence score for vulnerability."""
        if vuln.vulnerability_type == "single_block_manipulation":
            return 0.9  # High confidence
        elif vuln.vulnerability_type == "short_twap_window":
            return 0.8  # High confidence
        else:
            return 0.6  # Medium confidence
    
    def _calculate_exploitability(self, vuln: OracleVulnerability) -> float:
        """Calculate exploitability score (0-1)."""
        # Consider cost vs profit ratio
        if vuln.exploitation_cost == 0:
            return 1.0
        
        profit_ratio = vuln.potential_profit / max(vuln.exploitation_cost, 1)
        
        if profit_ratio > 5:  # 5x return
            return 0.9
        elif profit_ratio > 2:  # 2x return
            return 0.7
        elif profit_ratio > 1:  # Profitable
            return 0.5
        else:
            return 0.2

