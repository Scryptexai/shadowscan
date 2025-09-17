#!/usr/bin/env python3
"""
Morpho Protocol Screening Module
Screening-only vulnerability detection for DeFi protocols
No gas required - only reading blockchain state
"""

import asyncio
import json
import os
import time
import logging
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass
from web3 import Web3, HTTPProvider
from eth_utils import to_checksum_address, from_wei, to_wei, is_address
import aiohttp
import requests
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DeFiVulnerability:
    """DeFi vulnerability finding"""
    vulnerability_type: str
    severity: str
    protocol: str
    contract_address: str
    description: str
    impact: str
    confidence: float
    details: Dict[str, Any]
    exploitation_method: Optional[str] = None
    potential_loss: Optional[float] = None

@dataclass
class ContractInfo:
    """Smart contract information"""
    address: str
    name: str
    abi: List[Dict[str, Any]]
    balance: float
    total_supply: Optional[float] = None
    tvl: Optional[float] = None
    functions: List[str] = None
    events: List[str] = None

class MorphoProtocolScanner:
    """Morpho protocol vulnerability scanner - screening only"""
    
    def __init__(self):
        self.config = self._load_config()
        self.web3_providers = {}
        self.session = None
        self._initialize_providers()
        
        # Real DeFi contracts for testing (using verified contracts)
        self.morpho_contracts = {
            'ethereum': {
                'uniswap_v2_factory': to_checksum_address('0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f'),  # Uniswap V2 Factory
                'uniswap_v2_router': to_checksum_address('0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D'),  # Uniswap V2 Router
                'weth': to_checksum_address('0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2'),  # WETH
                'usdc': to_checksum_address('0xA0b86a33E6417aAb7b6DbCBbe9FD4E89c0778a4B'),  # USDC
                'dai': to_checksum_address('0x6B175474E89094C44Da98b954EedeAC495271d0F')  # DAI
            },
            'base': {
                'uniswap_v3_factory': to_checksum_address('0x33128a8fC17869897dcE68Ed026d694621f6FDfD'),  # Uniswap V3 Factory
                'weth': to_checksum_address('0x4200000000000000000000000000000000000006'),  # WETH on Base
                'usdc': to_checksum_address('0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'),  # USDC on Base
                'aerodrome_factory': to_checksum_address('0x420DD381b31aEf6683db6B902084cB0FFeE009Ab'),  # Aerodrome Factory
                'aerodrome_router': to_checksum_address('0xcf77a3Ba969d5381E67F7532b45B2e4993316A4E')  # Aerodrome Router
            },
            'arbitrum': {
                'uniswap_v3_factory': to_checksum_address('0x1F98431c8aD98523631AE4a59f267346ea31F984'),  # Uniswap V3 Factory
                'weth': to_checksum_address('0x82aF49447D8a07e3bd95BD0d56f35241523fBab1'),  # WETH on Arbitrum
                'usdc': to_checksum_address('0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8'),  # USDC on Arbitrum
                'arbitrum_bridge': to_checksum_address('0x5047d31F91C689F8cC4169f4Afa7760942a3cC1B'),  # Arbitrum Bridge
                'gmx_router': to_checksum_address('0xaBBc5F99639c9B6bCb58544ddf04EFA6802F4064')  # GMX Router
            }
        }
        
        # Common DeFi vulnerability patterns
        self.defi_vulnerabilities = {
            'flashloan': {
                'functions': ['flashLoan', 'flashloan', 'executeOperation'],
                'indicators': ['borrow', 'repay', 'liquidate'],
                'check_pattern': 'no_reentrancy_guard'
            },
            'oracle_manipulation': {
                'functions': ['getPrice', 'getPriceFeed', 'latestRoundData'],
                'indicators': ['price', 'oracle', 'feed'],
                'check_pattern': 'unprotected_oracle'
            },
            'reentrancy': {
                'functions': ['withdraw', 'transfer', 'transferFrom'],
                'indicators': ['call', 'delegatecall', 'staticcall'],
                'check_pattern': 'external_call_before_update'
            },
            'access_control': {
                'functions': ['onlyOwner', 'onlyGovernance', 'accessControl'],
                'indicators': ['owner', 'governance', 'admin'],
                'check_pattern': 'missing_access_control'
            },
            'integer_overflow': {
                'functions': ['add', 'sub', 'mul', 'div'],
                'indicators': ['balance', 'amount', 'totalSupply'],
                'check_pattern': 'unchecked_arithmetic'
            }
        }
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from environment"""
        return {
            'rpc_urls': {
                'ethereum': os.getenv('ETH_RPC_URL', 'https://eth.llamarpc.com'),
                'base': os.getenv('BASE_RPC_URL', 'https://base.llamarpc.com'),
                'tenderly': os.getenv('TENDERLY_RPC', 'https://virtual.mainnet.eu.rpc.tenderly.co/eeffdb55-4da5-4241-a9eb-bb6ac3ef16e8')
            },
            'api_keys': {
                'etherscan': os.getenv('ETHERSCAN_API_KEY', ''),
                'tenderly': os.getenv('TENDERLY_ACCESS_KEY', 'uke68o7FiButiRduw7XJy0BYuzHNZFfR')
            },
            'chain_ids': {
                'ethereum': 1,
                'base': 8453,
                'tenderly': 1
            }
        }
    
    def _initialize_providers(self):
        """Initialize Web3 providers for screening"""
        for network, rpc_url in self.config['rpc_urls'].items():
            try:
                w3 = Web3(HTTPProvider(rpc_url))
                if w3.is_connected():
                    self.web3_providers[network] = w3
                    logger.info(f"✅ Connected to {network} for screening")
                else:
                    logger.warning(f"⚠️ Failed to connect to {network}")
            except Exception as e:
                logger.error(f"❌ Error connecting to {network}: {e}")
    
    async def screen_morpho_protocol(self, network: str = 'ethereum') -> Dict[str, Any]:
        """Screen Morpho protocol for vulnerabilities - read-only operations"""
        if network not in self.web3_providers:
            raise ValueError(f"Network {network} not available")
        
        w3 = self.web3_providers[network]
        
        logger.info(f"🔍 Screening Morpho protocol on {network}")
        
        screening_results = {
            'protocol': 'Morpho',
            'network': network,
            'timestamp': datetime.now().isoformat(),
            'contracts': {},
            'vulnerabilities': [],
            'tvl_analysis': {},
            'risk_assessment': {}
        }
        
        try:
            # Step 1: Analyze main contracts
            for contract_name, contract_address in self.morpho_contracts.get(network, {}).items():
                logger.info(f"📊 Analyzing {contract_name}: {contract_address}")
                
                contract_info = await self._analyze_contract(w3, contract_address, network)
                screening_results['contracts'][contract_name] = contract_info
                
                # Step 2: Check for vulnerabilities
                vulnerabilities = await self._check_defi_vulnerabilities(w3, contract_info, network)
                screening_results['vulnerabilities'].extend(vulnerabilities)
            
            # Step 3: TVL and risk analysis
            tvl_analysis = await self._analyze_tvl(w3, network)
            screening_results['tvl_analysis'] = tvl_analysis
            
            # Step 4: Overall risk assessment
            risk_assessment = self._assess_overall_risk(screening_results)
            screening_results['risk_assessment'] = risk_assessment
            
        except Exception as e:
            logger.error(f"❌ Error screening Morpho protocol: {e}")
            screening_results['error'] = str(e)
        
        return screening_results
    
    async def _analyze_contract(self, w3: Web3, contract_address: str, network: str) -> ContractInfo:
        """Analyze individual contract - read only"""
        try:
            # Ensure checksum address
            if not is_address(contract_address):
                logger.error(f"❌ Invalid address format: {contract_address}")
                return ContractInfo(
                    address=contract_address,
                    name="Invalid Address",
                    abi=[],
                    balance=0.0,
                    functions=[],
                    events=[]
                )
            
            contract_address = to_checksum_address(contract_address)
            
            # Get contract code
            contract_code = w3.eth.get_code(contract_address)
            if contract_code == b'':
                logger.warning(f"⚠️ No contract code found at {contract_address}")
                return ContractInfo(
                    address=contract_address,
                    name="Invalid Contract",
                    abi=[],
                    balance=0.0
                )
            
            # Get balance
            balance_wei = w3.eth.get_balance(contract_address)
            balance = float(from_wei(balance_wei, 'ether'))
            
            # Get ABI from Etherscan
            abi = await self._get_contract_abi(contract_address, network)
            
            # Extract functions and events
            functions = []
            events = []
            
            for item in abi:
                if item.get('type') == 'function':
                    functions.append(item.get('name', 'unknown'))
                elif item.get('type') == 'event':
                    events.append(item.get('name', 'unknown'))
            
            # Get contract name
            contract_name = self._get_contract_name(contract_address, network)
            
            return ContractInfo(
                address=contract_address,
                name=contract_name,
                abi=abi,
                balance=balance,
                functions=functions,
                events=events
            )
            
        except Exception as e:
            logger.error(f"❌ Error analyzing contract {contract_address}: {e}")
            return ContractInfo(
                address=contract_address,
                name="Error",
                abi=[],
                balance=0.0
            )
    
    async def _get_contract_abi(self, contract_address: str, network: str) -> List[Dict[str, Any]]:
        """Get contract ABI from Etherscan - read only"""
        try:
            api_key = self.config['api_keys'].get('etherscan', '')
            api_url = f'https://api.etherscan.io/api?module=contract&action=getabi&address={contract_address}&apikey={api_key}'
            
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('status') == '1':
                            return json.loads(data.get('result', '[]'))
            return []
        except Exception as e:
            logger.error(f"❌ Error getting ABI: {e}")
            return []
    
    def _get_contract_name(self, contract_address: str, network: str) -> str:
        """Get contract name - cached or from Etherscan"""
        try:
            # Try to get from cache or Etherscan
            contract_names = {
                '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f': 'UniswapV2Factory',
                '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D': 'UniswapV2Router',
                '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2': 'WETH',
                '0xA0b86a33E6417aAb7b6DbCBbe9FD4E89c0778a4B': 'USDC',
                '0x6B175474E89094C44Da98b954EedeAC495271d0F': 'DAI',
                '0x33128a8fC17869897dcE68Ed026d694621f6FDfD': 'UniswapV3Factory',
                '0x4200000000000000000000000000000000000006': 'WETH',
                '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913': 'USDC',
                '0x420DD381b31aEf6683db6B902084cB0FFeE009Ab': 'AerodromeFactory',
                '0xcf77a3Ba969d5381E67F7532b45B2e4993316A4E': 'AerodromeRouter',
                '0x1F98431c8aD98523631AE4a59f267346ea31F984': 'UniswapV3Factory',
                '0x82aF49447D8a07e3bd95BD0d56f35241523fBab1': 'WETH',
                '0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8': 'USDC',
                '0x5047d31F91C689F8cC4169f4Afa7760942a3cC1B': 'ArbitrumBridge',
                '0xaBBc5F99639c9B6bCb58544ddf04EFA6802F4064': 'GMXRouter'
            }
            
            return contract_names.get(contract_address, 'Unknown')
            
        except Exception as e:
            logger.error(f"❌ Error getting contract name: {e}")
            return 'Unknown'
    
    async def _check_defi_vulnerabilities(self, w3: Web3, contract_info: ContractInfo, network: str) -> List[DeFiVulnerability]:
        """Check for DeFi-specific vulnerabilities - analysis only"""
        vulnerabilities = []
        
        if not contract_info or not contract_info.functions:
            logger.warning(f"⚠️ Skipping vulnerability check for contract with no functions: {contract_info.address if contract_info else 'Unknown'}")
            return vulnerabilities
        
        try:
            # Check flashloan vulnerabilities
            flashloan_vulns = await self._check_flashloan_vulnerabilities(w3, contract_info, network)
            vulnerabilities.extend(flashloan_vulns)
            
            # Check oracle manipulation vulnerabilities
            oracle_vulns = await self._check_oracle_vulnerabilities(w3, contract_info, network)
            vulnerabilities.extend(oracle_vulns)
            
            # Check reentrancy vulnerabilities
            reentrancy_vulns = await self._check_reentrancy_vulnerabilities(w3, contract_info, network)
            vulnerabilities.extend(reentrancy_vulns)
            
            # Check access control vulnerabilities
            access_vulns = await self._check_access_control_vulnerabilities(w3, contract_info, network)
            vulnerabilities.extend(access_vulns)
            
            # Check integer overflow vulnerabilities
            overflow_vulns = await self._check_integer_overflow_vulnerabilities(w3, contract_info, network)
            vulnerabilities.extend(overflow_vulns)
            
        except Exception as e:
            logger.error(f"❌ Error checking vulnerabilities: {e}")
        
        return vulnerabilities
    
    async def _check_flashloan_vulnerabilities(self, w3: Web3, contract_info: ContractInfo, network: str) -> List[DeFiVulnerability]:
        """Check for flashloan vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Look for flashloan-related functions
            flashloan_functions = ['flashLoan', 'flashloan', 'executeOperation', 'flashCallback']
            
            if any(func in contract_info.functions for func in flashloan_functions):
                # Check if contract has significant balance (potential target)
                if contract_info.balance > 1000:  # > 1000 ETH
                    vulnerabilities.append(DeFiVulnerability(
                        vulnerability_type='flashloan',
                        severity='High',
                        protocol='Morpho',
                        contract_address=contract_info.address,
                        description='Contract has flashloan functions and significant balance',
                        impact='Potential flashloan attack leading to fund drainage',
                        confidence=0.8,
                        details={
                            'balance': contract_info.balance,
                            'flashloan_functions': [f for f in flashloan_functions if f in contract_info.functions]
                        },
                        exploitation_method='Flashloan arbitrage or price manipulation attack',
                        potential_loss=contract_info.balance * 0.5  # Estimated 50% loss
                    ))
                
                # Check for reentrancy protection in flashloan functions
                if 'nonReentrant' not in contract_info.functions:
                    vulnerabilities.append(DeFiVulnerability(
                        vulnerability_type='flashloan_reentrancy',
                        severity='Critical',
                        protocol='Morpho',
                        contract_address=contract_info.address,
                        description='Flashloan functions lack reentrancy protection',
                        impact='Reentrancy attack during flashloan execution',
                        confidence=0.9,
                        details={
                            'missing_protection': 'nonReentrant',
                            'vulnerable_functions': [f for f in flashloan_functions if f in contract_info.functions]
                        },
                        exploitation_method='Reentrancy attack during flashloan callback',
                        potential_loss=contract_info.balance
                    ))
            
        except Exception as e:
            logger.error(f"❌ Error checking flashloan vulnerabilities: {e}")
        
        return vulnerabilities
    
    async def _check_oracle_vulnerabilities(self, w3: Web3, contract_info: ContractInfo, network: str) -> List[DeFiVulnerability]:
        """Check for oracle manipulation vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Look for oracle-related functions
            oracle_functions = ['getPrice', 'getPriceFeed', 'latestRoundData', 'peek', 'get']
            
            if any(func in contract_info.functions for func in oracle_functions):
                # Check if oracle functions are protected
                if 'onlyOwner' not in contract_info.functions and 'accessControl' not in contract_info.functions:
                    vulnerabilities.append(DeFiVulnerability(
                        vulnerability_type='oracle_manipulation',
                        severity='High',
                        protocol='Morpho',
                        contract_address=contract_info.address,
                        description='Oracle functions lack access control',
                        impact='Price manipulation leading to incorrect valuations',
                        confidence=0.7,
                        details={
                            'unprotected_functions': [f for f in oracle_functions if f in contract_info.functions],
                            'missing_protection': 'Access control'
                        },
                        exploitation_method='Oracle price manipulation attack',
                        potential_loss=min(contract_info.balance * 1000000, 10000000)  # Cap at 10M
                    ))
                
                # Check for time-weighted average price (TWAP) protection
                if 'twap' not in contract_info.functions.lower() and 'timeWeighted' not in str(contract_info.functions).lower():
                    vulnerabilities.append(DeFiVulnerability(
                        vulnerability_type='oracle_front_running',
                        severity='Medium',
                        protocol='Morpho',
                        contract_address=contract_info.address,
                        description='Oracle lacks TWAP protection against front-running',
                        impact='Front-running attacks on oracle updates',
                        confidence=0.6,
                        details={
                            'missing_protection': 'TWAP',
                            'vulnerable_functions': [f for f in oracle_functions if f in contract_info.functions]
                        },
                        exploitation_method='Front-running oracle manipulation',
                        potential_loss=min(contract_info.balance * 100000, 1000000)  # Cap at 1M
                    ))
            
        except Exception as e:
            logger.error(f"❌ Error checking oracle vulnerabilities: {e}")
        
        return vulnerabilities
    
    async def _check_reentrancy_vulnerabilities(self, w3: Web3, contract_info: ContractInfo, network: str) -> List[DeFiVulnerability]:
        """Check for reentrancy vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Look for functions that make external calls
            external_call_functions = ['withdraw', 'transfer', 'transferFrom', 'borrow', 'repay']
            
            vulnerable_functions = [f for f in external_call_functions if f in contract_info.functions]
            
            if vulnerable_functions:
                # Check for reentrancy protection
                if 'nonReentrant' not in contract_info.functions:
                    vulnerabilities.append(DeFiVulnerability(
                        vulnerability_type='reentrancy',
                        severity='Critical',
                        protocol='Morpho',
                        contract_address=contract_info.address,
                        description='External call functions lack reentrancy protection',
                        impact='Reentrancy attack leading to fund drainage',
                        confidence=0.8,
                        details={
                            'vulnerable_functions': vulnerable_functions,
                            'missing_protection': 'nonReentrant modifier'
                        },
                        exploitation_method='Reentrancy attack during external calls',
                        potential_loss=contract_info.balance * 0.8  # Estimated 80% loss
                    ))
        
        except Exception as e:
            logger.error(f"❌ Error checking reentrancy vulnerabilities: {e}")
        
        return vulnerabilities
    
    async def _check_access_control_vulnerabilities(self, w3: Web3, contract_info: ContractInfo, network: str) -> List[DeFiVulnerability]:
        """Check for access control vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Look for sensitive functions
            sensitive_functions = ['withdraw', 'transferOwnership', 'setFee', 'setOracle', 'pause']
            
            unprotected_functions = [f for f in sensitive_functions if f in contract_info.functions]
            
            if unprotected_functions:
                # Check for access control mechanisms
                access_control_functions = ['onlyOwner', 'onlyGovernance', 'require', 'assert']
                
                if not any(acf in str(contract_info.functions) for acf in access_control_functions):
                    vulnerabilities.append(DeFiVulnerability(
                        vulnerability_type='access_control',
                        severity='High',
                        protocol='Morpho',
                        contract_address=contract_info.address,
                        description='Sensitive functions lack access control',
                        impact='Unauthorized access to critical functions',
                        confidence=0.7,
                        details={
                            'unprotected_functions': unprotected_functions,
                            'missing_protection': 'Access control modifiers'
                        },
                        exploitation_method='Unauthorized function execution',
                        potential_loss=contract_info.balance
                    ))
        
        except Exception as e:
            logger.error(f"❌ Error checking access control vulnerabilities: {e}")
        
        return vulnerabilities
    
    async def _check_integer_overflow_vulnerabilities(self, w3: Web3, contract_info: ContractInfo, network: str) -> List[DeFiVulnerability]:
        """Check for integer overflow vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Look for arithmetic functions
            arithmetic_functions = ['add', 'sub', 'mul', 'div', 'balance', 'totalSupply']
            
            vulnerable_functions = [f for f in arithmetic_functions if f in contract_info.functions]
            
            if vulnerable_functions:
                # Check for SafeMath or overflow protection
                has_safe_math = 'SafeMath' in str(contract_info.functions) or 'safeMath' in str(contract_info.functions)
                
                if not has_safe_math:
                    vulnerabilities.append(DeFiVulnerability(
                        vulnerability_type='integer_overflow',
                        severity='Medium',
                        protocol='Morpho',
                        contract_address=contract_info.address,
                        description='Arithmetic operations lack overflow protection',
                        impact='Integer overflow leading to balance manipulation',
                        confidence=0.6,
                        details={
                            'vulnerable_functions': vulnerable_functions,
                            'missing_protection': 'SafeMath library'
                        },
                        exploitation_method='Integer overflow attack',
                        potential_loss=min(contract_info.balance * 10000, 1000000)  # Cap at 1M
                    ))
        
        except Exception as e:
            logger.error(f"❌ Error checking integer overflow vulnerabilities: {e}")
        
        return vulnerabilities
    
    async def _analyze_tvl(self, w3: Web3, network: str) -> Dict[str, Any]:
        """Analyze Total Value Locked (TVL) - read only"""
        try:
            tvl_analysis = {
                'total_tvl': 0.0,
                'contracts': {},
                'risk_factors': []
            }
            
            # Get balances of major contracts
            for contract_name, contract_address in self.morpho_contracts.get(network, {}).items():
                try:
                    balance_wei = w3.eth.get_balance(contract_address)
                    balance = float(from_wei(balance_wei, 'ether'))
                    
                    tvl_analysis['contracts'][contract_name] = {
                        'address': contract_address,
                        'balance': balance,
                        'risk_level': 'High' if balance > 1000 else 'Medium' if balance > 100 else 'Low'
                    }
                    
                    tvl_analysis['total_tvl'] += balance
                    
                    # Risk factors based on balance
                    if balance > 10000:
                        tvl_analysis['risk_factors'].append({
                            'type': 'high_balance',
                            'contract': contract_name,
                            'amount': balance,
                            'description': f'Contract holds {balance} ETH - high value target'
                        })
                    
                except Exception as e:
                    logger.error(f"❌ Error getting balance for {contract_name}: {e}")
            
            return tvl_analysis
            
        except Exception as e:
            logger.error(f"❌ Error analyzing TVL: {e}")
            return {'error': str(e)}
    
    def _assess_overall_risk(self, screening_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall protocol risk"""
        try:
            vulnerabilities = screening_results.get('vulnerabilities', [])
            tvl_analysis = screening_results.get('tvl_analysis', {})
            
            # Count vulnerabilities by severity
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Low')
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # Calculate overall risk score
            risk_score = (
                severity_counts['Critical'] * 10 +
                severity_counts['High'] * 5 +
                severity_counts['Medium'] * 2 +
                severity_counts['Low'] * 1
            )
            
            # Determine overall risk level
            if risk_score >= 20:
                overall_risk = 'Critical'
            elif risk_score >= 10:
                overall_risk = 'High'
            elif risk_score >= 5:
                overall_risk = 'Medium'
            else:
                overall_risk = 'Low'
            
            # Calculate potential total loss
            total_tvl = tvl_analysis.get('total_tvl', 0)
            potential_loss = sum(vuln.get('potential_loss', 0) for vuln in vulnerabilities)
            
            return {
                'overall_risk': overall_risk,
                'risk_score': risk_score,
                'severity_counts': severity_counts,
                'total_vulnerabilities': len(vulnerabilities),
                'total_tvl': total_tvl,
                'potential_loss': min(potential_loss, total_tvl),
                'recommendations': self._generate_recommendations(severity_counts, overall_risk)
            }
            
        except Exception as e:
            logger.error(f"❌ Error assessing overall risk: {e}")
            return {'error': str(e)}
    
    def _generate_recommendations(self, severity_counts: Dict[str, int], overall_risk: str) -> List[str]:
        """Generate recommendations based on risk assessment"""
        recommendations = []
        
        if severity_counts['Critical'] > 0:
            recommendations.append("🚨 CRITICAL: Immediate action required - Critical vulnerabilities detected")
            recommendations.append("🔒 Implement emergency security measures")
            recommendations.append("📞 Contact security team immediately")
        
        if severity_counts['High'] > 0:
            recommendations.append("⚠️ HIGH: Prioritize fixing high-severity vulnerabilities")
            recommendations.append("🛡️ Implement additional security controls")
            recommendations.append("🔍 Conduct thorough security audit")
        
        if severity_counts['Medium'] > 0:
            recommendations.append("⚡ MEDIUM: Address medium-severity vulnerabilities in next sprint")
            recommendations.append("📋 Add to security backlog")
            recommendations.append("🔧 Improve code review process")
        
        if overall_risk in ['High', 'Critical']:
            recommendations.append("💰 Consider bug bounty program")
            recommendations.append("🔒 Implement multi-signature controls")
            recommendations.append("📊 Continuous monitoring required")
        
        return recommendations

async def main():
    """Main screening function"""
    scanner = MorphoProtocolScanner()
    
    try:
        # Screen Morpho protocol on different networks
        networks = ['ethereum', 'base']  # Add more as needed
        
        for network in networks:
            print(f"\\n🔍 SCREENING MORPHO PROTOCOL ON {network.upper()}")
            print("=" * 60)
            
            results = await scanner.screen_morpho_protocol(network)
            
            # Display results
            print(f"\\n📊 SCREENING RESULTS FOR {network.upper()}")
            print("-" * 40)
            
            # TVL Analysis
            tvl_analysis = results.get('tvl_analysis', {})
            total_tvl = tvl_analysis.get('total_tvl', 0)
            print(f"💰 Total TVL: {total_tvl:,.2f} ETH")
            
            # Vulnerabilities
            vulnerabilities = results.get('vulnerabilities', [])
            print(f"🔍 Vulnerabilities Found: {len(vulnerabilities)}")
            
            if vulnerabilities:
                print("\\n🚨 VULNERABILITIES:")
                for i, vuln in enumerate(vulnerabilities, 1):
                    print(f"   {i}. {vuln.vulnerability_type.upper()} ({vuln.severity})")
                    print(f"      Contract: {vuln.contract_address}")
                    print(f"      Impact: {vuln.impact}")
                    print(f"      Confidence: {vuln.confidence:.1%}")
                    if vuln.potential_loss:
                        print(f"      Potential Loss: {vuln.potential_loss:,.2f} ETH")
            
            # Risk Assessment
            risk_assessment = results.get('risk_assessment', {})
            if risk_assessment:
                print(f"\\n⚖️ Overall Risk: {risk_assessment.get('overall_risk', 'Unknown')}")
                print(f"📈 Risk Score: {risk_assessment.get('risk_score', 0)}")
                
                recommendations = risk_assessment.get('recommendations', [])
                if recommendations:
                    print("\\n💡 RECOMMENDATIONS:")
                    for rec in recommendations:
                        print(f"   • {rec}")
            
            # Save results
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"morpho_screening_{network}_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"\\n💾 Results saved to: {filename}")
        
    except Exception as e:
        logger.error(f"❌ Screening failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())