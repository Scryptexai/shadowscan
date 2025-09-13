# shadowscan/collectors/evm/abi_fetcher.py
"""Enhanced ABI fetcher with caching and fallback strategies."""

import json
import os
import time
import requests
from pathlib import Path
from typing import Optional, List, Dict, Any
from web3 import Web3
import logging

logger = logging.getLogger(__name__)

class ABIFetcher:
    """Enhanced ABI fetcher with caching and multiple fallback strategies."""
    
    def __init__(self, cache_dir: str = "reports/findings", etherscan_api_key: Optional[str] = None):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "abi_cache.json"
        self.etherscan_api_key = etherscan_api_key
        
        # Load cache
        self._cache = self._load_cache()
        
        # API endpoints by chain
        self.api_endpoints = {
            'ethereum': 'https://api.etherscan.io/api',
            'polygon': 'https://api.polygonscan.com/api',
            'bsc': 'https://api.bscscan.com/api',
            'arbitrum': 'https://api.arbiscan.io/api'
        }
    
    def get_abi(self, address: str, chain: str = 'ethereum', cache: bool = True) -> Optional[List[Dict[str, Any]]]:
        """
        Get contract ABI with caching and fallback strategies.
        
        Args:
            address: Contract address
            chain: Blockchain network
            cache: Whether to use cache
            
        Returns:
            ABI as list or None if not found
        """
        address = Web3.to_checksum_address(address)
        cache_key = f"{chain}:{address}"
        
        # Check cache first
        if cache and cache_key in self._cache:
            cached_entry = self._cache[cache_key]
            # Check if cache is still valid (24h TTL)
            if time.time() - cached_entry.get('timestamp', 0) < 86400:
                logger.debug(f"ABI cache hit for {address}")
                return cached_entry.get('abi')
        
        # Try to fetch ABI
        abi = None
        
        # 1. Try blockchain explorer API
        if self.etherscan_api_key:
            abi = self._fetch_from_explorer(address, chain)
        
        # 2. Try known contract signatures
        if not abi:
            abi = self._try_standard_interfaces(address)
        
        # Cache result
        if cache:
            self._cache[cache_key] = {
                'abi': abi,
                'timestamp': time.time(),
                'source': 'explorer' if abi else 'none'
            }
            self._save_cache()
        
        return abi
    
    def _load_cache(self) -> Dict[str, Any]:
        """Load ABI cache from disk."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load ABI cache: {e}")
        return {}
    
    def _save_cache(self):
        """Save ABI cache to disk."""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self._cache, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save ABI cache: {e}")
    
    def _fetch_from_explorer(self, address: str, chain: str) -> Optional[List[Dict[str, Any]]]:
        """Fetch ABI from blockchain explorer API."""
        endpoint = self.api_endpoints.get(chain)
        if not endpoint:
            logger.warning(f"No API endpoint for chain: {chain}")
            return None
        
        try:
            params = {
                'module': 'contract',
                'action': 'getabi',
                'address': address,
                'apikey': self.etherscan_api_key
            }
            
            response = requests.get(endpoint, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == '1' and data.get('result'):
                abi = json.loads(data['result'])
                logger.info(f"Fetched ABI from {chain} explorer for {address}")
                return abi
            else:
                logger.debug(f"No ABI found on {chain} explorer for {address}")
                
        except Exception as e:
            logger.error(f"Error fetching ABI from {chain} explorer: {e}")
        
        return None
    
    def _try_standard_interfaces(self, address: str) -> Optional[List[Dict[str, Any]]]:
        """Try to detect standard interfaces (ERC20, ERC721, etc.)."""
        # ERC20 standard ABI
        erc20_abi = [
            {
                "type": "function",
                "name": "totalSupply",
                "inputs": [],
                "outputs": [{"name": "", "type": "uint256"}],
                "constant": True
            },
            {
                "type": "function", 
                "name": "balanceOf",
                "inputs": [{"name": "account", "type": "address"}],
                "outputs": [{"name": "", "type": "uint256"}],
                "constant": True
            },
            {
                "type": "function",
                "name": "transfer", 
                "inputs": [
                    {"name": "to", "type": "address"},
                    {"name": "amount", "type": "uint256"}
                ],
                "outputs": [{"name": "", "type": "bool"}],
                "constant": False
            },
            {
                "type": "event",
                "name": "Transfer",
                "inputs": [
                    {"name": "from", "type": "address", "indexed": True},
                    {"name": "to", "type": "address", "indexed": True},
                    {"name": "value", "type": "uint256", "indexed": False}
                ]
            }
        ]
        
        # For now, return ERC20 as fallback - in production, this would
        # include bytecode analysis to detect interface compliance
        logger.info(f"Using standard ERC20 ABI fallback for {address}")
        return erc20_abi
