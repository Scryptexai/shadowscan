#!/usr/bin/env python3
"""
Modular Blockchain Interface for GhostScan
Support for multiple blockchain environments with real execution
"""

import json
import os
import time
from web3 import Web3
from typing import Dict, List, Any, Optional, Union
from web3.exceptions import ContractLogicError, TransactionNotFound
from pathlib import Path
from .database import database
from .config_loader import config_loader

class BlockchainInterface:
    """Modular blockchain interface supporting multiple environments"""

    def __init__(self):
        self.web3_instances = {}
        self.contracts = {}
        self.config = config_loader

    def get_web3_instance(self, chain_id: Union[str, int], rpc_url: str = None) -> Optional[Web3]:
        """Get or create Web3 instance for a specific chain"""
        chain_id_str = str(chain_id)

        # Check if we already have this instance
        if chain_id_str in self.web3_instances:
            return self.web3_instances[chain_id_str]

        try:
            # Use provided RPC URL or get from configuration
            if not rpc_url:
                chain_config = self.config.get_chain(chain_id)
                if not chain_config:
                    print(f"⚠️ Chain configuration not found for ID: {chain_id}")
                    return None

                rpc_url = chain_config.get("rpc_url")
                if not rpc_url:
                    print(f"⚠️ RPC URL not found for chain: {chain_id}")
                    return None

            # Create Web3 instance
            web3 = Web3(Web3.HTTPProvider(rpc_url, request_timeout=30))

            # Test connection
            if not web3.is_connected():
                print(f"⚠️ Failed to connect to {rpc_url}")
                return None

            # Validate chain ID
            try:
                actual_chain_id = web3.eth.chain_id
                if int(chain_id) != actual_chain_id:
                    print(f"⚠️ Chain ID mismatch. Expected: {chain_id}, Got: {actual_chain_id}")
                    web3 = None
            except Exception as e:
                print(f"⚠️ Error validating chain ID: {e}")

            if web3:
                self.web3_instances[chain_id_str] = web3
                print(f"✅ Connected to chain {chain_id} at {rpc_url}")

            return web3

        except Exception as e:
            print(f"⚠️ Error creating Web3 instance for chain {chain_id}: {e}")
            return None

    def get_contract(self, chain_id: Union[str, int], contract_address: str, abi: List[Dict[str, Any]]) -> Optional[Any]:
        """Get contract instance for a specific chain"""
        contract_key = f"{chain_id}_{contract_address}"

        if contract_key in self.contracts:
            return self.contracts[contract_key]

        try:
            web3 = self.get_web3_instance(chain_id)
            if not web3:
                return None

            # Create contract instance
            contract = web3.eth.contract(
                address=web3.to_checksum_address(contract_address),
                abi=abi
            )

            self.contracts[contract_key] = contract
            print(f"✅ Contract initialized: {contract_address} on chain {chain_id}")

            return contract

        except Exception as e:
            print(f"⚠️ Error initializing contract {contract_address}: {e}")
            return None

    def execute_transaction(self, chain_id: Union[str, int], private_key: str, function_name: str,
                          contract_address: str, args: List, abi: List[Dict[str, Any]],
                          value: int = 0, gas_limit: int = 300000) -> Optional[str]:
        """Execute transaction on specific blockchain"""
        try:
            web3 = self.get_web3_instance(chain_id)
            if not web3:
                return None

            contract = self.get_contract(chain_id, contract_address, abi)
            if not contract:
                return None

            # Get account from private key
            account = web3.eth.account.from_private_key(private_key)
            sender_address = account.address

            # Check balance
            balance = web3.eth.get_balance(web3.to_checksum_address(sender_address))
            if balance == 0:
                print(f"⚠️ No balance in account: {sender_address}")
                return None

            # Build transaction
            func = getattr(contract.functions, function_name)
            transaction = func(*args).build_transaction({
                'from': web3.to_checksum_address(sender_address),
                'value': value,
                'gas': gas_limit,
                'gasPrice': web3.to_wei(20, 'gwei'),
                'nonce': web3.eth.get_transaction_count(web3.to_checksum_address(sender_address)),
                'chainId': int(chain_id)
            })

            # Sign transaction
            signed_txn = web3.eth.account.sign_transaction(transaction, private_key)

            # Send transaction
            tx_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)
            return tx_hash.hex()

        except Exception as e:
            print(f"⚠️ Error executing transaction: {e}")
            return None

    def wait_for_transaction(self, chain_id: Union[str, int], tx_hash: str, timeout: int = 120) -> Optional[Dict[str, Any]]:
        """Wait for transaction confirmation"""
        try:
            web3 = self.get_web3_instance(chain_id)
            if not web3:
                return None

            receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
            return {
                'status': receipt.status,
                'transaction_hash': tx_hash,
                'block_number': receipt.blockNumber,
                'gas_used': receipt.gasUsed,
                'cumulative_gas_used': receipt.cumulativeGasUsed,
                'effective_gas_price': receipt.effectiveGasPrice,
                'contract_address': receipt.contractAddress,
                'logs': receipt.logs
            }

        except TransactionNotFound:
            print(f"⚠️ Transaction not found: {tx_hash}")
            return None
        except Exception as e:
            print(f"⚠️ Error waiting for transaction: {e}")
            return None

    def get_balance(self, chain_id: Union[str, int], address: str) -> Optional[int]:
        """Get balance of an address"""
        try:
            web3 = self.get_web3_instance(chain_id)
            if not web3:
                return None

            balance = web3.eth.get_balance(web3.to_checksum_address(address))
            return balance

        except Exception as e:
            print(f"⚠️ Error getting balance: {e}")
            return None

    def get_token_balance(self, chain_id: Union[str, int], token_address: str, user_address: str,
                         token_abi: List[Dict[str, Any]]) -> Optional[int]:
        """Get token balance using ERC20 standard"""
        try:
            web3 = self.get_web3_instance(chain_id)
            if not web3:
                return None

            contract = self.get_contract(chain_id, token_address, token_abi)
            if not contract:
                return None

            balance = contract.functions.balanceOf(web3.to_checksum_address(user_address)).call()
            return balance

        except Exception as e:
            print(f"⚠️ Error getting token balance: {e}")
            return None

    def get_contract_info(self, chain_id: Union[str, int], contract_address: str,
                         minimal_abi: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get basic contract information"""
        try:
            web3 = self.get_web3_instance(chain_id)
            if not web3:
                return {}

            contract = self.get_contract(chain_id, contract_address, minimal_abi)
            if not contract:
                return {}

            info = {
                'name': contract.functions.name().call(),
                'symbol': contract.functions.symbol().call(),
                'decimals': contract.functions.decimals().call(),
                'total_supply': contract.functions.totalSupply().call(),
                'balance_of_attacker': contract.functions.balanceOf(
                    web3.to_checksum_address(config_loader.get_default_attacker_config().get("default_address", ""))
                ).call(),
                'allowance': contract.functions.allowance(
                    web3.to_checksum_address(config_loader.get_default_attacker_config().get("default_address", "")),
                    web3.to_checksum_address(config_loader.get_default_attacker_config().get("default_address", ""))
                ).call()
            }

            # Convert readable values
            decimals = info['decimals']
            info['total_supply_readable'] = info['total_supply'] / (10 ** decimals)
            info['balance_of_attacker_readable'] = info['balance_of_attacker'] / (10 ** decimals)
            info['allowance_readable'] = info['allowance'] / (10 ** decimals)

            return info

        except Exception as e:
            print(f"⚠️ Error getting contract info: {e}")
            return {}

    def check_contract_exists(self, chain_id: Union[str, int], contract_address: str) -> bool:
        """Check if contract exists on blockchain"""
        try:
            web3 = self.get_web3_instance(chain_id)
            if not web3:
                return False

            # Try to get contract code
            bytecode = web3.eth.get_code(web3.to_checksum_address(contract_address))
            return len(bytecode) > 0

        except Exception as e:
            print(f"⚠️ Error checking contract existence: {e}")
            return False

    def get_transaction_history(self, chain_id: Union[str, int], address: str,
                               limit: int = 10) -> List[Dict[str, Any]]:
        """Get transaction history for an address"""
        try:
            web3 = self.get_web3_instance(chain_id)
            if not web3:
                return []

            # This is a simplified implementation
            # In a real implementation, you would use a blockchain explorer API
            return []

        except Exception as e:
            print(f"⚠️ Error getting transaction history: {e}")
            return []

    def estimate_gas(self, chain_id: Union[str, int], private_key: str, function_name: str,
                    contract_address: str, args: List, abi: List[Dict[str, Any]],
                    value: int = 0) -> Optional[int]:
        """Estimate gas cost for transaction"""
        try:
            web3 = self.get_web3_instance(chain_id)
            if not web3:
                return None

            contract = self.get_contract(chain_id, contract_address, abi)
            if not contract:
                return None

            account = web3.eth.account.from_private_key(private_key)
            sender_address = account.address

            func = getattr(contract.functions, function_name)
            gas_estimate = func(*args).estimate_gas({
                'from': web3.to_checksum_address(sender_address),
                'value': value,
                'chainId': int(chain_id)
            })

            return gas_estimate

        except Exception as e:
            print(f"⚠️ Error estimating gas: {e}")
            return None

    def get_block_number(self, chain_id: Union[str, int]) -> Optional[int]:
        """Get current block number"""
        try:
            web3 = self.get_web3_instance(chain_id)
            if not web3:
                return None

            return web3.eth.block_number

        except Exception as e:
            print(f"⚠️ Error getting block number: {e}")
            return None

    def get_gas_price(self, chain_id: Union[str, int]) -> Optional[int]:
        """Get current gas price"""
        try:
            web3 = self.get_web3_instance(chain_id)
            if not web3:
                return None

            return web3.eth.gas_price

        except Exception as e:
            print(f"⚠️ Error getting gas price: {e}")
            return None

    def add_custom_chain(self, chain_config: Dict[str, Any]) -> bool:
        """Add custom chain configuration"""
        try:
            # Validate chain configuration
            required_fields = ["name", "environment", "rpc_url", "chain_id"]
            for field in required_fields:
                if field not in chain_config:
                    print(f"⚠️ Missing required field '{field}' in chain configuration")
                    return False

            # Add to configuration
            if self.config.add_chain_config(chain_config):
                # Reload configurations
                self.config.reload_configs()
                # Clear cache to force reload
                self.web3_instances.clear()
                self.contracts.clear()
                return True

            return False

        except Exception as e:
            print(f"⚠️ Error adding custom chain: {e}")
            return False

    def test_connection(self, chain_id: Union[str, int]) -> bool:
        """Test connection to a specific chain"""
        try:
            web3 = self.get_web3_instance(chain_id)
            if not web3:
                return False

            # Test basic operations
            block_number = web3.eth.block_number
            if block_number > 0:
                print(f"✅ Connection successful to chain {chain_id}")
                print(f"   Current block: {block_number}")
                return True
            else:
                print(f"⚠️ Chain {chain_id} appears to be down or empty")
                return False

        except Exception as e:
            print(f"⚠️ Connection test failed: {e}")
            return False

    def get_environment_type(self, chain_id: Union[str, int]) -> str:
        """Get environment type for a chain"""
        chain_config = self.config.get_chain(chain_id)
        if chain_config:
            return chain_config.get("environment", "unknown")
        return "unknown"

    def cleanup(self):
        """Clean up resources"""
        self.web3_instances.clear()
        self.contracts.clear()

# Global blockchain interface instance
blockchain_interface = BlockchainInterface()

# Minimal ERC20 ABI for basic token operations
MINIMAL_ERC20_ABI = [
    {"constant": True, "inputs": [{"name": "_owner", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "balance", "type": "uint256"}], "payable": False, "stateMutability": "view", "type": "function"},
    {"constant": True, "inputs": [{"name": "_owner", "type": "address"}, {"name": "_spender", "type": "address"}], "name": "allowance", "outputs": [{"name": "remaining", "type": "uint256"}], "payable": False, "stateMutability": "view", "type": "function"},
    {"constant": True, "inputs": [], "name": "name", "outputs": [{"name": "", "type": "string"}], "payable": False, "stateMutability": "view", "type": "function"},
    {"constant": True, "inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "payable": False, "stateMutability": "view", "type": "function"},
    {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "payable": False, "stateMutability": "view", "type": "function"},
    {"constant": True, "inputs": [], "name": "totalSupply", "outputs": [{"name": "", "type": "uint256"}], "payable": False, "stateMutability": "view", "type": "function"},
    {"constant": False, "inputs": [{"name": "_spender", "type": "address"}, {"name": "_value", "type": "uint256"}], "name": "approve", "outputs": [{"name": "success", "type": "bool"}], "payable": False, "stateMutability": "nonpayable", "type": "function"},
    {"constant": False, "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}], "name": "transfer", "outputs": [{"name": "success", "type": "bool"}], "payable": False, "stateMutability": "nonpayable", "type": "function"},
    {"constant": False, "inputs": [{"name": "_from", "type": "address"}, {"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}], "name": "transferFrom", "outputs": [{"name": "success", "type": "bool"}], "payable": False, "stateMutability": "nonpayable", "type": "function"},
]

if __name__ == "__main__":
    # Test the blockchain interface
    print("🔗 Testing Blockchain Interface...")

    # Test Story Protocol connection
    story_chain_id = 1511
    if blockchain_interface.test_connection(story_chain_id):
        print(f"✅ Story Protocol connection successful")

    # Test getting contract info
    larry_contract = "0x693c7acf65e52c71bafe555bc22d69cb7f8a78a2"
    contract_info = blockchain_interface.get_contract_info(
        story_chain_id, larry_contract, MINIMAL_ERC20_ABI
    )

    if contract_info:
        print(f"📊 Contract Info:")
        for key, value in contract_info.items():
            if 'readable' in key:
                print(f"   {key}: {value}")
    else:
        print(f"⚠️ Failed to get contract info")