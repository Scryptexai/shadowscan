"""
ShadowScan EVM Chain Provider

Chain-agnostic EVM adapter for RPC interactions, tracing, and fork management.
Supports Ethereum, L2s (Arbitrum, Optimism), and other EVM-compatible chains.
"""

import asyncio
import json
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from web3 import Web3
from web3.exceptions import ContractLogicError
import requests

@dataclass
class ChainConfig:
    name: str
    chain_id: int
    rpc_url: str
    block_explorer: str
    native_token: str
    has_tracing: bool = True
    fork_supported: bool = True

@dataclass
class ContractInfo:
    address: str
    bytecode: str
    abi: Optional[List[Dict]] = None
    is_proxy: bool = False
    implementation: Optional[str] = None
    source_verified: bool = False


class EVMProvider:
    """EVM chain provider with RPC, tracing, and simulation capabilities."""
    
    CHAIN_CONFIGS = {
        "ethereum": ChainConfig(
            name="Ethereum Mainnet",
            chain_id=1,
            rpc_url="https://eth.llamarpc.com",
            block_explorer="https://api.etherscan.io",
            native_token="ETH"
        ),
        "polygon": ChainConfig(
            name="Polygon",
            chain_id=137,
            rpc_url="https://polygon.llamarpc.com", 
            block_explorer="https://api.polygonscan.com",
            native_token="MATIC"
        ),
        "arbitrum": ChainConfig(
            name="Arbitrum One",
            chain_id=42161,
            rpc_url="https://arb1.arbitrum.io/rpc",
            block_explorer="https://api.arbiscan.io",
            native_token="ETH"
        ),
        "optimism": ChainConfig(
            name="Optimism",
            chain_id=10,
            rpc_url="https://mainnet.optimism.io",
            block_explorer="https://api-optimistic.etherscan.io",
            native_token="ETH"
        ),
        "bsc": ChainConfig(
            name="BNB Smart Chain",
            chain_id=56,
            rpc_url="https://bsc-dataseed1.binance.org",
            block_explorer="https://api.bscscan.com",
            native_token="BNB"
        )
    }
    
    def __init__(self, chain: str = "ethereum", custom_rpc: Optional[str] = None):
        self.chain = chain
        self.config = self.CHAIN_CONFIGS.get(chain)
        if not self.config:
            raise ValueError(f"Unsupported chain: {chain}")
        
        # Use custom RPC if provided
        rpc_url = custom_rpc or self.config.rpc_url
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        if not self.w3.is_connected():
            raise ConnectionError(f"Failed to connect to {chain} RPC: {rpc_url}")
            
        # Verify chain ID
        try:
            connected_chain_id = self.w3.eth.chain_id
            if connected_chain_id != self.config.chain_id:
                print(f"Warning: Expected chain {self.config.chain_id}, got {connected_chain_id}")
        except Exception:
            pass  # Some RPCs don't support chain_id
    
    async def get_contract_info(self, address: str) -> ContractInfo:
        """Get comprehensive contract information."""
        address = self.w3.to_checksum_address(address)
        
        # Get bytecode
        bytecode = self.w3.eth.get_code(address)
        
        if not bytecode or bytecode == b'\x00':
            raise ValueError(f"No contract found at {address}")
        
        # Check if it's a proxy (basic detection)
        is_proxy = await self._detect_proxy(address)
        implementation = None
        
        if is_proxy:
            implementation = await self._get_implementation(address)
        
        # Try to fetch ABI from block explorer
        abi = await self._fetch_abi(address)
        
        return ContractInfo(
            address=address,
            bytecode=bytecode.hex(),
            abi=abi,
            is_proxy=is_proxy,
            implementation=implementation,
            source_verified=abi is not None
        )
    
    async def _detect_proxy(self, address: str) -> bool:
        """Detect if contract is a proxy (EIP-1967, EIP-1822)."""
        try:
            # Check EIP-1967 implementation slot
            impl_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
            impl_data = self.w3.eth.get_storage_at(address, impl_slot)
            
            if impl_data != b'\x00' * 32:
                return True
            
            # Check EIP-1822 proxiable slot
            proxiable_slot = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"
            proxiable_data = self.w3.eth.get_storage_at(address, proxiable_slot)
            
            return proxiable_data != b'\x00' * 32
            
        except Exception:
            return False
    
    async def _get_implementation(self, address: str) -> Optional[str]:
        """Get implementation address from proxy."""
        try:
            # Try EIP-1967 slot
            impl_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
            impl_data = self.w3.eth.get_storage_at(address, impl_slot)
            
            if impl_data != b'\x00' * 32:
                # Extract address from last 20 bytes
                impl_address = self.w3.to_checksum_address(impl_data[-20:])
                return impl_address
                
        except Exception:
            pass
        
        return None
    
    async def _fetch_abi(self, address: str) -> Optional[List[Dict]]:
        """Fetch ABI from block explorer if available."""
        if not hasattr(self, '_etherscan_key'):
            return None
            
        try:
            url = f"{self.config.block_explorer}/api"
            params = {
                "module": "contract",
                "action": "getabi", 
                "address": address,
                "apikey": getattr(self, '_etherscan_key', 'YourApiKeyToken')
            }
            
            response = requests.get(url, params=params, timeout=10)
            data = response.json()
            
            if data.get("status") == "1":
                return json.loads(data["result"])
                
        except Exception:
            pass
        
        return None
    
    async def simulate_transaction(self, 
                                  from_address: str,
                                  to_address: str,
                                  data: str = "0x",
                                  value: int = 0,
                                  block_number: Optional[int] = None) -> Dict[str, Any]:
        """Simulate transaction and return result."""
        
        transaction = {
            "from": from_address,
            "to": to_address,
            "data": data,
            "value": value
        }
        
        try:
            # Use eth_call for read operations
            if block_number:
                result = self.w3.eth.call(transaction, block_number)
            else:
                result = self.w3.eth.call(transaction)
            
            return {
                "success": True,
                "return_data": result.hex(),
                "gas_used": None  # eth_call doesn't return gas
            }
            
        except ContractLogicError as e:
            return {
                "success": False,
                "error": str(e),
                "revert_reason": self._decode_revert_reason(str(e))
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "revert_reason": None
            }
    
    def _decode_revert_reason(self, error_str: str) -> Optional[str]:
        """Extract revert reason from error string."""
        try:
            # Look for revert reason in error message
            if "revert" in error_str.lower():
                # Try to extract reason string
                import re
                reason_match = re.search(r"revert (.+)", error_str)
                if reason_match:
                    return reason_match.group(1)
        except Exception:
            pass
        
        return None
    
    async def get_transaction_trace(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """Get transaction trace if supported by RPC."""
        if not self.config.has_tracing:
            return None
            
        try:
            # Try debug_traceTransaction
            trace = self.w3.manager.request_blocking(
                "debug_traceTransaction", 
                [tx_hash, {"tracer": "callTracer"}]
            )
            return trace
            
        except Exception:
            # Fallback: try getting transaction receipt
            try:
                receipt = self.w3.eth.get_transaction_receipt(tx_hash)
                tx = self.w3.eth.get_transaction(tx_hash)
                
                return {
                    "type": "receipt",
                    "transaction": dict(tx),
                    "receipt": dict(receipt)
                }
            except Exception:
                return None
    
    async def get_balance(self, address: str, token_address: Optional[str] = None) -> int:
        """Get native or token balance."""
        address = self.w3.to_checksum_address(address)
        
        if token_address is None:
            # Native token balance
            return self.w3.eth.get_balance(address)
        else:
            # ERC20 token balance
            token_address = self.w3.to_checksum_address(token_address)
            
            # balanceOf(address) selector
            data = "0x70a08231" + address[2:].zfill(64)
            
            result = await self.simulate_transaction(
                from_address=address,
                to_address=token_address,
                data=data
            )
            
            if result["success"]:
                return int(result["return_data"], 16)
            else:
                return 0
    
    async def get_block_info(self, block_number: Optional[int] = None) -> Dict[str, Any]:
        """Get block information."""
        if block_number is None:
            block_number = self.w3.eth.block_number
            
        block = self.w3.eth.get_block(block_number)
        
        return {
            "number": block.number,
            "hash": block.hash.hex(),
            "timestamp": block.timestamp,
            "miner": block.miner,
            "gas_limit": block.gasLimit,
            "gas_used": block.gasUsed,
            "base_fee": getattr(block, 'baseFeePerGas', None)
        }
    
    async def get_storage_at(self, address: str, slot: Union[int, str]) -> str:
        """Get storage value at specific slot."""
        address = self.w3.to_checksum_address(address)
        
        if isinstance(slot, int):
            slot = hex(slot)
        
        storage = self.w3.eth.get_storage_at(address, slot)
        return storage.hex()
    
    async def estimate_gas(self, transaction: Dict[str, Any]) -> int:
        """Estimate gas for transaction."""
        try:
            return self.w3.eth.estimate_gas(transaction)
        except Exception:
            return 21000  # Fallback to minimum gas
    
    def create_contract_instance(self, address: str, abi: List[Dict]):
        """Create web3 contract instance."""
        return self.w3.eth.contract(
            address=self.w3.to_checksum_address(address),
            abi=abi
        )
    
    async def health_check(self) -> Dict[str, Any]:
        """Check provider health and capabilities."""
        try:
            latest_block = self.w3.eth.block_number
            chain_id = self.w3.eth.chain_id
            
            # Test tracing capability
            has_debug = False
            try:
                self.w3.manager.request_blocking("debug_traceBlockByNumber", ["latest", False])
                has_debug = True
            except Exception:
                pass
            
            return {
                "connected": True,
                "chain_id": chain_id,
                "latest_block": latest_block,
                "has_tracing": has_debug,
                "config": {
                    "name": self.config.name,
                    "chain_id": self.config.chain_id,
                    "native_token": self.config.native_token
                }
            }
            
        except Exception as e:
            return {
                "connected": False,
                "error": str(e)
            }
