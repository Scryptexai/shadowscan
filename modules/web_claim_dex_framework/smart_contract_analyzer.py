#!/usr/bin/env python3
"""
Smart Contract Interaction Layer
Comprehensive smart contract analysis and testing for claim websites and DEX platforms
"""

import asyncio
import json
import re
import os
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass
import logging
from web3 import Web3, HTTPProvider
from web3.exceptions import ContractLogicError
from eth_utils import to_checksum_address
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ContractInfo:
    address: str
    name: str
    symbol: str
    decimals: int
    total_supply: int
    owner: str
    contract_type: str
    abi: List[Dict[str, Any]]
    bytecode: str
    is_verified: bool

@dataclass
class ContractVulnerability:
    vulnerability_type: str
    severity: str
    description: str
    contract_address: str
    function_name: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    impact: str
    recommendation: str

@dataclass
class FunctionAnalysis:
    name: str
    signature: str
    payable: bool
    state_mutability: str
    inputs: List[Dict[str, Any]]
    outputs: List[Dict[str, Any]]
    is_owner_only: bool
    is_public: bool
    vulnerabilities: List[ContractVulnerability]

@dataclass
class ContractAnalysisResult:
    contract_info: ContractInfo
    functions_analysis: List[FunctionAnalysis]
    vulnerabilities: List[ContractVulnerability]
    security_score: int
    gas_analysis: Dict[str, Any]
    bytecode_analysis: Dict[str, Any]
    access_control_analysis: Dict[str, Any]
    business_logic_analysis: Dict[str, Any]

class SmartContractAnalyzer:
    def __init__(self):
        self.web3_providers = {
            'ethereum': Web3(HTTPProvider('https://mainnet.infura.io/v3/YOUR_PROJECT_ID')),
            'bsc': Web3(HTTPProvider('https://bsc-dataseed1.defibit.io/')),
            'polygon': Web3(HTTPProvider('https://polygon-rpc.com/')),
            'arbitrum': Web3(HTTPProvider('https://arb1.arbitrum.io/rpc')),
            'avalanche': Web3(HTTPProvider('https://api.avax.network/ext/bc/C/rpc')),
            'fantom': Web3(HTTPProvider('https://rpc.ftm.tools/')),
            'optimism': Web3(HTTPProvider('https://mainnet.optimism.io/')),
            'localhost': Web3(HTTPProvider('http://localhost:8545')),
            'localhost2': Web3(HTTPProvider('http://localhost:9545'))
        }
        
        self.common_abis = {
            'erc20': [
                {"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"stateMutability":"view","type":"function"},
                {"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"stateMutability":"view","type":"function"},
                {"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"stateMutability":"view","type":"function"},
                {"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
                {"inputs":[{"name":"account","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
                {"inputs":[{"name":"recipient","type":"address"},{"name":"amount","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},
                {"inputs":[{"name":"owner","type":"address"},{"name":"spender","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
                {"inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},
                {"inputs":[{"name":"sender","type":"address"},{"name":"recipient","type":"address"},{"name":"amount","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}
            ],
            'erc721': [
                {"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"stateMutability":"view","type":"function"},
                {"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"stateMutability":"view","type":"function"},
                {"inputs":[{"name":"tokenId","type":"uint256"}],"name":"ownerOf","outputs":[{"name":"","type":"address"}],"stateMutability":"view","type":"function"},
                {"inputs":[{"name":"owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
                {"inputs":[{"name":"to","type":"address"},{"name":"tokenId","type":"uint256"}],"name":"approve","outputs":[],"stateMutability":"nonpayable","type":"function"},
                {"inputs":[{"name":"from","type":"address"},{"name":"to","type":"address"},{"name":"tokenId","type":"uint256"}],"name":"transferFrom","outputs":[],"stateMutability":"nonpayable","type":"function"},
                {"inputs":[{"name":"to","type":"address"},{"name":"tokenId","type":"uint256"}],"name":"mint","outputs":[],"stateMutability":"nonpayable","type":"function"}
            ],
            'claim': [
                {"inputs":[],"name":"claim","outputs":[],"stateMutability":"nonpayable","type":"function"},
                {"inputs":[{"name":"amount","type":"uint256"}],"name":"claim","outputs":[],"stateMutability":"nonpayable","type":"function"},
                {"inputs":[{"name":"recipient","type":"address"},{"name":"amount","type":"uint256"}],"name":"claim","outputs":[],"stateMutability":"nonpayable","type":"function"},
                {"inputs":[{"name":"signature","type":"bytes"}],"name":"claim","outputs":[],"stateMutability":"nonpayable","type":"function"},
                {"inputs":[],"name":"claimAirdrop","outputs":[],"stateMutability":"nonpayable","type":"function"},
                {"inputs":[{"name":"amount","type":"uint256"}],"name":"claimAirdrop","outputs":[],"stateMutability":"nonpayable","type":"function"}
            ],
            'owner': [
                {"inputs":[],"name":"owner","outputs":[{"name":"","type":"address"}],"stateMutability":"view","type":"function"},
                {"inputs":[{"name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},
                {"inputs":[{"name":"account","type":"address"}],"name":"isOwner","outputs":[{"name":"","type":"bool"}],"stateMutability":"view","type":"function"},
                {"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"}
            ],
            'pausable': [
                {"inputs":[],"name":"paused","outputs":[{"name":"","type":"bool"}],"stateMutability":"view","type":"function"},
                {"inputs":[],"name":"pause","outputs":[],"stateMutability":"nonpayable","type":"function"},
                {"inputs":[],"name":"unpause","outputs":[],"stateMutability":"nonpayable","type":"function"}
            ],
            'mintable': [
                {"inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"name":"mint","outputs":[],"stateMutability":"nonpayable","type":"function"},
                {"inputs":[{"name":"amount","type":"uint256"}],"name":"mint","outputs":[],"stateMutability":"nonpayable","type":"function"},
                {"inputs":[],"name":"mint","outputs":[],"stateMutability":"nonpayable","type":"function"}
            ]
        }
        
        self.vulnerability_patterns = {
            'reentrancy': r'call\.value|transfer|send',
            'overflow': r'add\(|sub\(|mul\(|div\(',
            'underflow': r'sub\(|uint.*max',
            'access_control': r'require.*owner|onlyOwner',
            'unchecked_call': r'call\(|delegatecall\(',
            'selfdestruct': r'selfdestruct\(',
            'delegatecall': r'delegatecall\(',
            'tx_origin': r'tx\.origin',
            'block_timestamp': r'block\.timestamp',
            'blockhash': r'blockhash\('
        }

    async def analyze_smart_contracts(self, contract_addresses: List[str], network: str = 'bsc') -> List[ContractAnalysisResult]:
        logger.info(f"🔗 Starting comprehensive smart contract analysis for {len(contract_addresses)} contracts on {network}")
        
        results = []
        
        for address in contract_addresses:
            try:
                result = await self._analyze_single_contract(address, network)
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(f"Error analyzing contract {address}: {e}")
        
        return results

    async def _analyze_single_contract(self, contract_address: str, network: str) -> Optional[ContractAnalysisResult]:
        try:
            # Get Web3 instance for the network
            w3 = self.web3_providers.get(network)
            if not w3 or not w3.is_connected():
                logger.warning(f"Network {network} not available")
                return None
            
            # Normalize address
            contract_address = to_checksum_address(contract_address)
            
            # Get basic contract info
            contract_info = await self._get_contract_info(w3, contract_address, network)
            if not contract_info:
                return None
            
            # Analyze functions
            functions_analysis = await self._analyze_functions(w3, contract_info)
            
            # Analyze bytecode
            bytecode_analysis = await self._analyze_bytecode(w3, contract_info.bytecode)
            
            # Analyze vulnerabilities
            vulnerabilities = await self._analyze_contract_vulnerabilities(w3, contract_info, functions_analysis)
            
            # Analyze gas usage
            gas_analysis = await self._analyze_gas_usage(w3, contract_info, functions_analysis)
            
            # Analyze access control
            access_control_analysis = await self._analyze_access_control(w3, contract_info, functions_analysis)
            
            # Analyze business logic
            business_logic_analysis = await self._analyze_business_logic(w3, contract_info, functions_analysis)
            
            # Calculate security score
            security_score = self._calculate_security_score(vulnerabilities, functions_analysis)
            
            return ContractAnalysisResult(
                contract_info=contract_info,
                functions_analysis=functions_analysis,
                vulnerabilities=vulnerabilities,
                security_score=security_score,
                gas_analysis=gas_analysis,
                bytecode_analysis=bytecode_analysis,
                access_control_analysis=access_control_analysis,
                business_logic_analysis=business_logic_analysis
            )
            
        except Exception as e:
            logger.error(f"Error analyzing contract {contract_address}: {e}")
            return None

    async def _get_contract_info(self, w3: Web3, contract_address: str, network: str) -> Optional[ContractInfo]:
        try:
            # Get contract code
            bytecode = w3.eth.get_code(contract_address).hex()
            if not bytecode or bytecode == '0x':
                return None
            
            # Try to get contract info using standard ABIs
            contract_info = None
            
            for abi_name, abi in self.common_abis.items():
                try:
                    contract = w3.eth.contract(address=contract_address, abi=abi)
                    
                    # Try to get basic info
                    name = symbol = decimals = total_supply = owner = ""
                    
                    try:
                        name = contract.functions.name().call()
                    except:
                        pass
                    
                    try:
                        symbol = contract.functions.symbol().call()
                    except:
                        pass
                    
                    try:
                        decimals = contract.functions.decimals().call()
                    except:
                        pass
                    
                    try:
                        total_supply = contract.functions.totalSupply().call()
                    except:
                        pass
                    
                    try:
                        owner = contract.functions.owner().call()
                    except:
                        pass
                    
                    contract_info = ContractInfo(
                        address=contract_address,
                        name=name,
                        symbol=symbol,
                        decimals=decimals,
                        total_supply=total_supply,
                        owner=owner,
                        contract_type=abi_name,
                        abi=abi,
                        bytecode=bytecode,
                        is_verified=False  # Would need to check with block explorers
                    )
                    
                    break
                    
                except Exception as e:
                    continue
            
            if not contract_info:
                # Create basic contract info
                contract_info = ContractInfo(
                    address=contract_address,
                    name="Unknown",
                    symbol="UNKNOWN",
                    decimals=18,
                    total_supply=0,
                    owner="",
                    contract_type="unknown",
                    abi=[],
                    bytecode=bytecode,
                    is_verified=False
                )
            
            return contract_info
            
        except Exception as e:
            logger.error(f"Error getting contract info for {contract_address}: {e}")
            return None

    async def _analyze_functions(self, w3: Web3, contract_info: ContractInfo) -> List[FunctionAnalysis]:
        functions_analysis = []
        
        if not contract_info.abi:
            return functions_analysis
        
        contract = w3.eth.contract(address=contract_info.address, abi=contract_info.abi)
        
        for abi_item in contract_info.abi:
            if abi_item.get('type') == 'function':
                try:
                    function_analysis = await self._analyze_single_function(w3, contract, abi_item, contract_info)
                    if function_analysis:
                        functions_analysis.append(function_analysis)
                except Exception as e:
                    logger.error(f"Error analyzing function {abi_item.get('name', 'unknown')}: {e}")
        
        return functions_analysis

    async def _analyze_single_function(self, w3: Web3, contract, abi_item: Dict[str, Any], contract_info: ContractInfo) -> Optional[FunctionAnalysis]:
        function_name = abi_item.get('name', '')
        signature = self._get_function_signature(abi_item)
        
        # Extract function properties
        payable = abi_item.get('stateMutability') == 'payable'
        state_mutability = abi_item.get('stateMutability', 'nonpayable')
        inputs = abi_item.get('inputs', [])
        outputs = abi_item.get('outputs', [])
        
        # Test if function is owner-only
        is_owner_only = await self._test_owner_only_function(w3, contract, function_name, inputs, contract_info)
        
        # Test if function is public (can be called)
        is_public = await self._test_public_function(w3, contract, function_name, inputs)
        
        # Analyze function-specific vulnerabilities
        vulnerabilities = await self._analyze_function_vulnerabilities(w3, contract, function_name, inputs, contract_info)
        
        return FunctionAnalysis(
            name=function_name,
            signature=signature,
            payable=payable,
            state_mutability=state_mutability,
            inputs=inputs,
            outputs=outputs,
            is_owner_only=is_owner_only,
            is_public=is_public,
            vulnerabilities=vulnerabilities
        )

    def _get_function_signature(self, abi_item: Dict[str, Any]) -> str:
        function_name = abi_item.get('name', '')
        inputs = abi_item.get('inputs', [])
        
        input_types = []
        for inp in inputs:
            input_types.append(inp.get('type', ''))
        
        return f"{function_name}({','.join(input_types)})"

    async def _test_owner_only_function(self, w3: Web3, contract, function_name: str, inputs: List[Dict[str, Any]], contract_info: ContractInfo) -> bool:
        if not contract_info.owner:
            return False
        
        # Get a non-owner account (using account[1] if available)
        try:
            accounts = w3.eth.accounts
            if len(accounts) > 1 and accounts[1].lower() != contract_info.owner.lower():
                test_account = accounts[1]
                
                # Try to call function from non-owner account
                try:
                    # Build function call with dummy parameters
                    args = self._build_dummy_args(inputs)
                    
                    # Get function
                    function = getattr(contract.functions, function_name)
                    
                    # Try to call from non-owner
                    if inputs:
                        tx_hash = function(*args).transact({'from': test_account})
                    else:
                        tx_hash = function().transact({'from': test_account})
                    
                    # If transaction succeeds, it's not owner-only
                    return False
                    
                except Exception as e:
                    error_msg = str(e).lower()
                    if 'owner' in error_msg or 'only owner' in error_msg:
                        return True
                    return False
        except:
            pass
        
        return False

    async def _test_public_function(self, w3: Web3, contract, function_name: str, inputs: List[Dict[str, Any]]) -> bool:
        try:
            # Try to call function
            function = getattr(contract.functions, function_name)
            args = self._build_dummy_args(inputs)
            
            if inputs:
                result = function(*args).call()
            else:
                result = function().call()
            
            return True
            
        except Exception as e:
            # If it's a view function that reverts, it might still be public
            if 'view' in str(e).lower() or 'constant' in str(e).lower():
                try:
                    # Try with a different account
                    accounts = w3.eth.accounts
                    if accounts:
                        if inputs:
                            result = function(*args).call({'from': accounts[0]})
                        else:
                            result = function().call({'from': accounts[0]})
                        return True
                except:
                    pass
            
            return False

    def _build_dummy_args(self, inputs: List[Dict[str, Any]]) -> List[Any]:
        args = []
        for inp in inputs:
            param_type = inp.get('type', '')
            
            if param_type.startswith('uint'):
                args.append(1)
            elif param_type.startswith('int'):
                args.append(1)
            elif param_type == 'address':
                args.append('0x0000000000000000000000000000000000000000')
            elif param_type == 'bool':
                args.append(True)
            elif param_type == 'string':
                args.append('test')
            elif param_type == 'bytes':
                args.append(b'')
            elif param_type.startswith('bytes'):
                args.append(b'\x00' * int(param_type[5:]))
            else:
                args.append(0)
        
        return args

    async def _analyze_function_vulnerabilities(self, w3: Web3, contract, function_name: str, inputs: List[Dict[str, Any]], contract_info: ContractInfo) -> List[ContractVulnerability]:
        vulnerabilities = []
        
        # Test for common vulnerabilities
        if function_name in ['mint', 'claim', 'withdraw', 'transfer', 'approve']:
            # Test for parameter validation
            vulnerabilities.extend(await self._test_parameter_validation(w3, contract, function_name, inputs, contract_info))
            
            # Test for access control
            vulnerabilities.extend(await self._test_access_control_vulnerabilities(w3, contract, function_name, inputs, contract_info))
            
            # Test for business logic flaws
            vulnerabilities.extend(await self._test_business_logic_vulnerabilities(w3, contract, function_name, inputs, contract_info))
        
        # Test for reentrancy (if function makes external calls)
        if any(external_call_pattern in function_name.lower() for external_call_pattern in ['transfer', 'withdraw', 'send']):
            vulnerabilities.extend(await self._test_reentrancy_vulnerability(w3, contract, function_name, inputs, contract_info))
        
        return vulnerabilities

    async def _test_parameter_validation(self, w3: Web3, contract, function_name: str, inputs: List[Dict[str, Any]], contract_info: ContractInfo) -> List[ContractVulnerability]:
        vulnerabilities = []
        
        if not inputs:
            return vulnerabilities
        
        # Test with invalid parameters
        invalid_params = [
            {'type': 'zero_address', 'value': '0x0000000000000000000000000000000000000000'},
            {'type': 'negative_amount', 'value': -1},
            {'type': 'overflow_amount', 'value': 2**256 - 1},
            {'type': 'empty_string', 'value': ''}
        ]
        
        for param in invalid_params:
            try:
                function = getattr(contract.functions, function_name)
                
                # Build args with invalid parameter
                args = []
                for i, inp in enumerate(inputs):
                    if i == 0 and param['type'] in ['zero_address', 'empty_string']:
                        args.append(param['value'])
                    elif i == 1 and param['type'] in ['negative_amount', 'overflow_amount']:
                        args.append(param['value'])
                    else:
                        args.append(self._build_dummy_args([inp])[0])
                
                # Try to call function
                result = function(*args).call()
                
                # If call succeeds, there might be insufficient validation
                vulnerabilities.append(ContractVulnerability(
                    vulnerability_type='Insufficient Parameter Validation',
                    severity='MEDIUM',
                    description=f'Function {function_name} accepts invalid parameters without proper validation',
                    contract_address=contract_info.address,
                    function_name=function_name,
                    parameter=param['type'],
                    payload=str(param['value']),
                    impact='Potential business logic manipulation',
                    recommendation='Add proper parameter validation checks'
                ))
                
            except Exception as e:
                # Function properly reverted, which is good
                pass
        
        return vulnerabilities

    async def _test_access_control_vulnerabilities(self, w3: Web3, contract, function_name: str, inputs: List[Dict[str, Any]], contract_info: ContractInfo) -> List[ContractVulnerability]:
        vulnerabilities = []
        
        # Test if sensitive functions are properly protected
        sensitive_functions = ['mint', 'burn', 'withdraw', 'pause', 'unpause', 'transferOwnership']
        
        if function_name in sensitive_functions:
            try:
                # Try to call from a non-owner account
                accounts = w3.eth.accounts
                if len(accounts) > 1:
                    test_account = accounts[1]
                    args = self._build_dummy_args(inputs)
                    
                    function = getattr(contract.functions, function_name)
                    
                    # Try to transact from non-owner
                    if inputs:
                        tx_hash = function(*args).transact({'from': test_account})
                    else:
                        tx_hash = function().transact({'from': test_account})
                    
                    # If transaction succeeds, access control is broken
                    vulnerabilities.append(ContractVulnerability(
                        vulnerability_type='Broken Access Control',
                        severity='CRITICAL',
                        description=f'Sensitive function {function_name} can be called by non-owner accounts',
                        contract_address=contract_info.address,
                        function_name=function_name,
                        impact='Unauthorized access to sensitive operations',
                        recommendation='Implement proper access control with onlyOwner modifier'
                    ))
                    
            except Exception as e:
                # Function properly reverted, which is good
                pass
        
        return vulnerabilities

    async def _test_business_logic_vulnerabilities(self, w3: Web3, contract, function_name: str, inputs: List[Dict[str, Any]], contract_info: ContractInfo) -> List[ContractVulnerability]:
        vulnerabilities = []
        
        # Test claim-specific vulnerabilities
        if 'claim' in function_name.lower():
            # Test for claim frequency bypass
            try:
                args = self._build_dummy_args(inputs)
                function = getattr(contract.functions, function_name)
                
                # Try to claim multiple times quickly
                for i in range(3):
                    try:
                        result = function(*args).call()
                        # If claim succeeds multiple times, there might be a frequency issue
                        if i > 0:
                            vulnerabilities.append(ContractVulnerability(
                                vulnerability_type='Claim Frequency Bypass',
                                severity='HIGH',
                                description=f'Function {function_name} allows multiple claims without proper frequency control',
                                contract_address=contract_info.address,
                                function_name=function_name,
                                impact='Multiple claims can be made without restrictions',
                                recommendation='Implement proper claim frequency validation'
                            ))
                            break
                    except:
                        break
                        
            except Exception as e:
                pass
        
        return vulnerabilities

    async def _test_reentrancy_vulnerability(self, w3: Web3, contract, function_name: str, inputs: List[Dict[str, Any]], contract_info: ContractInfo) -> List[ContractVulnerability]:
        vulnerabilities = []
        
        # Check if function makes external calls
        if any(pattern in function_name.lower() for pattern in ['transfer', 'withdraw', 'send']):
            try:
                # Analyze bytecode for reentrancy patterns
                if self._has_reentrancy_pattern(contract_info.bytecode):
                    vulnerabilities.append(ContractVulnerability(
                        vulnerability_type='Reentrancy Vulnerability',
                        severity='HIGH',
                        description=f'Function {function_name} may be vulnerable to reentrancy attacks',
                        contract_address=contract_info.address,
                        function_name=function_name,
                        impact='Funds can be drained through reentrancy attacks',
                        recommendation='Implement reentrancy guards (Checks-Effects-Interactions pattern)'
                    ))
            except Exception as e:
                pass
        
        return vulnerabilities

    def _has_reentrancy_pattern(self, bytecode: str) -> bool:
        patterns = [
            r'40.*11.*11',  # call before storage update
            r'40.*11.*55',  # call before selfdestruct
            r'11.*40.*11'   # call after another call
        ]
        
        for pattern in patterns:
            if re.search(pattern, bytecode, re.IGNORECASE):
                return True
        
        return False

    async def _analyze_bytecode(self, w3: Web3, bytecode: str) -> Dict[str, Any]:
        analysis = {
            'bytecode_length': len(bytecode),
            'has_constructor': False,
            'has_selfdestruct': False,
            'has_delegatecall': False,
            'has_call': False,
            'has_create': False,
            'has_create2': False,
            'library_usage': False,
            'proxy_pattern': False,
            'vulnerability_patterns': []
        }
        
        try:
            # Analyze bytecode for patterns
            analysis['has_selfdestruct'] = 'ff' in bytecode.lower()
            analysis['has_delegatecall'] = 'f4' in bytecode.lower()
            analysis['has_call'] = 'f1' in bytecode.lower()
            analysis['has_create'] = 'f0' in bytecode.lower()
            analysis['has_create2'] = 'f5' in bytecode.lower()
            
            # Check for vulnerability patterns
            for vuln_type, pattern in self.vulnerability_patterns.items():
                if re.search(pattern, bytecode, re.IGNORECASE):
                    analysis['vulnerability_patterns'].append(vuln_type)
            
        except Exception as e:
            logger.error(f"Error analyzing bytecode: {e}")
        
        return analysis

    async def _analyze_gas_usage(self, w3: Web3, contract_info: ContractInfo, functions_analysis: List[FunctionAnalysis]) -> Dict[str, Any]:
        gas_analysis = {
            'total_functions': len(functions_analysis),
            'expensive_functions': [],
            'optimized_functions': [],
            'gas_limits': {}
        }
        
        for function in functions_analysis:
            if function.is_public:
                try:
                    contract = w3.eth.contract(address=contract_info.address, abi=contract_info.abi)
                    function_obj = getattr(contract.functions, function.name)
                    args = self._build_dummy_args(function.inputs)
                    
                    # Estimate gas
                    if function.inputs:
                        gas_estimate = function_obj(*args).estimate_gas({'from': w3.eth.accounts[0]})
                    else:
                        gas_estimate = function_obj().estimate_gas({'from': w3.eth.accounts[0]})
                    
                    gas_analysis['gas_limits'][function.name] = gas_estimate
                    
                    # Flag expensive functions
                    if gas_estimate > 100000:  # 100k gas
                        gas_analysis['expensive_functions'].append({
                            'name': function.name,
                            'gas_estimate': gas_estimate,
                            'severity': 'MEDIUM' if gas_estimate > 500000 else 'LOW'
                        })
                    
                except Exception as e:
                    pass
        
        return gas_analysis

    async def _analyze_access_control(self, w3: Web3, contract_info: ContractInfo, functions_analysis: List[FunctionAnalysis]) -> Dict[str, Any]:
        access_control = {
            'owner_functions': [],
            'public_functions': [],
            'protected_functions': [],
            'access_control_issues': []
        }
        
        for function in functions_analysis:
            if function.is_owner_only:
                access_control['owner_functions'].append(function.name)
            elif function.is_public:
                access_control['public_functions'].append(function.name)
            else:
                access_control['protected_functions'].append(function.name)
            
            # Check for access control issues
            if function.vulnerabilities:
                for vuln in function.vulnerabilities:
                    if vuln.vulnerability_type == 'Broken Access Control':
                        access_control['access_control_issues'].append({
                            'function': function.name,
                            'severity': vuln.severity,
                            'description': vuln.description
                        })
        
        return access_control

    async def _analyze_business_logic(self, w3: Web3, contract_info: ContractInfo, functions_analysis: List[FunctionAnalysis]) -> Dict[str, Any]:
        business_logic = {
            'claim_functions': [],
            'mint_functions': [],
            'transfer_functions': [],
            'approval_functions': [],
            'logic_issues': []
        }
        
        for function in functions_analysis:
            # Categorize functions
            if 'claim' in function.name.lower():
                business_logic['claim_functions'].append(function.name)
            elif 'mint' in function.name.lower():
                business_logic['mint_functions'].append(function.name)
            elif 'transfer' in function.name.lower():
                business_logic['transfer_functions'].append(function.name)
            elif 'approve' in function.name.lower():
                business_logic['approval_functions'].append(function.name)
            
            # Check for business logic issues
            for vuln in function.vulnerabilities:
                if vuln.vulnerability_type in ['Claim Frequency Bypass', 'Insufficient Parameter Validation']:
                    business_logic['logic_issues'].append({
                        'function': function.name,
                        'severity': vuln.severity,
                        'description': vuln.description
                    })
        
        return business_logic

    async def _analyze_contract_vulnerabilities(self, w3: Web3, contract_info: ContractInfo, functions_analysis: List[FunctionAnalysis]) -> List[ContractVulnerability]:
        all_vulnerabilities = []
        
        # Collect all function vulnerabilities
        for function in functions_analysis:
            all_vulnerabilities.extend(function.vulnerabilities)
        
        # Analyze contract-level vulnerabilities
        # Check for ownership issues
        if not contract_info.owner:
            all_vulnerabilities.append(ContractVulnerability(
                vulnerability_type='Missing Owner',
                severity='MEDIUM',
                description='Contract does not have an owner address',
                contract_address=contract_info.address,
                function_name='N/A',
                impact='Contract lacks ownership control',
                recommendation='Implement ownership pattern for better control'
            ))
        
        # Check for supply issues
        if contract_info.total_supply == 0 and contract_info.contract_type == 'erc20':
            all_vulnerabilities.append(ContractVulnerability(
                vulnerability_type='Zero Supply',
                severity='LOW',
                description='Token contract has zero total supply',
                contract_address=contract_info.address,
                function_name='N/A',
                impact='Token has no initial supply',
                recommendation='Consider if zero supply is intended'
            ))
        
        return all_vulnerabilities

    def _calculate_security_score(self, vulnerabilities: List[ContractVulnerability], functions_analysis: List[FunctionAnalysis]) -> int:
        base_score = 100
        
        # Deduct points for vulnerabilities
        severity_weights = {
            'CRITICAL': 20,
            'HIGH': 15,
            'MEDIUM': 10,
            'LOW': 5
        }
        
        for vuln in vulnerabilities:
            base_score -= severity_weights.get(vuln.severity, 5)
        
        # Add points for good practices
        if functions_analysis:
            owner_protected = len([f for f in functions_analysis if f.is_owner_only])
            if owner_protected > 0:
                base_score += 5
        
        # Ensure score is within bounds
        return max(0, min(100, base_score))

    async def generate_report(self, analysis_results: List[ContractAnalysisResult]) -> Dict[str, Any]:
        report = {
            'contract_analysis_summary': {
                'total_contracts': len(analysis_results),
                'vulnerable_contracts': len([r for r in analysis_results if r.vulnerabilities]),
                'average_security_score': sum(r.security_score for r in analysis_results) / len(analysis_results) if analysis_results else 0,
                'critical_vulnerabilities': sum(len([v for v in r.vulnerabilities if v.severity == 'CRITICAL']) for r in analysis_results),
                'high_vulnerabilities': sum(len([v for v in r.vulnerabilities if v.severity == 'HIGH']) for r in analysis_results)
            },
            'contracts': []
        }
        
        for result in analysis_results:
            contract_report = {
                'address': result.contract_info.address,
                'name': result.contract_info.name,
                'symbol': result.contract_info.symbol,
                'contract_type': result.contract_info.contract_type,
                'security_score': result.security_score,
                'total_vulnerabilities': len(result.vulnerabilities),
                'functions_count': len(result.functions_analysis),
                'vulnerabilities': [
                    {
                        'type': vuln.vulnerability_type,
                        'severity': vuln.severity,
                        'description': vuln.description,
                        'function': vuln.function_name,
                        'impact': vuln.impact,
                        'recommendation': vuln.recommendation
                    }
                    for vuln in result.vulnerabilities
                ],
                'gas_analysis': result.gas_analysis,
                'access_control': result.access_control_analysis,
                'business_logic': result.business_logic_analysis,
                'recommendations': self._generate_contract_recommendations(result)
            }
            
            report['contracts'].append(contract_report)
        
        return report

    def _generate_contract_recommendations(self, result: ContractAnalysisResult) -> List[str]:
        recommendations = []
        
        # Vulnerability-based recommendations
        if result.vulnerabilities:
            critical_vulns = [v for v in result.vulnerabilities if v.severity == 'CRITICAL']
            if critical_vulns:
                recommendations.append("Address critical vulnerabilities immediately")
            
            high_vulns = [v for v in result.vulnerabilities if v.severity == 'HIGH']
            if high_vulns:
                recommendations.append("Address high-severity vulnerabilities as soon as possible")
        
        # Security score based recommendations
        if result.security_score < 50:
            recommendations.append("Contract has significant security issues - consider redeployment")
        elif result.security_score < 80:
            recommendations.append("Contract has moderate security issues - review and patch")
        else:
            recommendations.append("Contract has good security - continue monitoring")
        
        # Gas optimization recommendations
        expensive_functions = result.gas_analysis.get('expensive_functions', [])
        if expensive_functions:
            recommendations.append("Consider gas optimization for expensive functions")
        
        # Access control recommendations
        access_issues = result.access_control_analysis.get('access_control_issues', [])
        if access_issues:
            recommendations.append("Review and improve access control mechanisms")
        
        # Business logic recommendations
        logic_issues = result.business_logic_analysis.get('logic_issues', [])
        if logic_issues:
            recommendations.append("Review business logic for potential exploits")
        
        return recommendations

async def analyze_contracts_from_website(target_url: str, network: str = 'bsc') -> Dict[str, Any]:
    """
    Analyze smart contracts found on a website
    """
    analyzer = SmartContractAnalyzer()
    
    # Extract contract addresses from website (would need web scraping)
    # For now, return empty analysis
    try:
        # This would need web scraping to find contract addresses
        contract_addresses = []
        
        if contract_addresses:
            results = await analyzer.analyze_smart_contracts(contract_addresses, network)
            report = await analyzer.generate_report(results)
            return report
        else:
            return {
                'contract_analysis_summary': {
                    'total_contracts': 0,
                    'vulnerable_contracts': 0,
                    'average_security_score': 0,
                    'critical_vulnerabilities': 0,
                    'high_vulnerabilities': 0,
                    'message': 'No contract addresses found on website'
                },
                'contracts': []
            }
    except Exception as e:
        logger.error(f"Error analyzing contracts from website: {e}")
        return {'error': str(e)}

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        contract_address = sys.argv[1]
        network = sys.argv[2] if len(sys.argv) > 2 else 'bsc'
        
        async def run_test():
            analyzer = SmartContractAnalyzer()
            results = await analyzer.analyze_smart_contracts([contract_address], network)
            report = await analyzer.generate_report(results)
            print(json.dumps(report, indent=2))
        
        asyncio.run(run_test())
    else:
        print("Usage: python smart_contract_analyzer.py <contract_address> [network]")