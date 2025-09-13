# shadowscan/collectors/evm/state_fetcher.py
"""Comprehensive contract state fetcher and analyzer."""

from web3 import Web3
from typing import Dict, Any, List, Optional, Set, Tuple
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from shadowscan.utils.schema import StateSnapshot, Balance, Allowance, StorageSample
from shadowscan.utils.helpers import format_wei, is_contract_address

logger = logging.getLogger(__name__)

class StateFetcher:
    """Comprehensive state fetcher for contract analysis."""
    
    def __init__(self, web3: Web3, max_workers: int = 8):
        self.web3 = web3
        self.max_workers = max_workers
        
        # Standard storage slot mappings for common patterns
        self.common_slots = {
            # ERC20 standard slots
            'total_supply': '0x2',           # Usually slot 2
            'owner': '0x0',                  # Usually slot 0 for owner
            'paused': '0x5',                 # Common pause state slot
            
            # Proxy patterns
            'proxy_admin': '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',
            'implementation': '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
            
            # OpenZeppelin AccessControl
            'role_admin': '0x0',
            'default_admin_role': '0x0',
        }
        
        # Standard function selectors for balance/allowance queries
        self.selectors = {
            'balanceOf': '0x70a08231',
            'allowance': '0xdd62ed3e',
            'totalSupply': '0x18160ddd',
            'decimals': '0x313ce567',
            'symbol': '0x95d89b41',
            'name': '0x06fdde03',
            'owner': '0x8da5cb5b',
            'paused': '0x5c975abb'
        }
    
    def fetch_state(self, address: str, provider, samples: Optional[List[str]] = None, 
                   fetch_balances: bool = True, fetch_allowances: bool = True,
                   top_holders_count: int = 10) -> StateSnapshot:
        """
        Fetch comprehensive contract state snapshot.
        
        Args:
            address: Contract address
            provider: Web3 provider (for compatibility)
            samples: List of specific storage slots to read
            fetch_balances: Whether to fetch token balances
            fetch_allowances: Whether to fetch allowances
            top_holders_count: Number of top holders to analyze
            
        Returns:
            StateSnapshot with comprehensive state information
        """
        try:
            checksum_addr = Web3.to_checksum_address(address)
            
            logger.info(f"Fetching state snapshot for {address}")
            
            # Initialize state snapshot
            state_snapshot = StateSnapshot()
            
            # Fetch basic contract state
            basic_state = self._get_basic_contract_state(checksum_addr)
            
            # Fetch storage samples
            storage_samples = self._fetch_storage_samples(checksum_addr, samples)
            state_snapshot.storage_samples = storage_samples
            
            # Detect if contract is ERC20-like and fetch token state
            if self._is_erc20_like(checksum_addr):
                logger.info("Detected ERC20-like contract, fetching token state")
                
                if fetch_balances:
                    balances = self._fetch_token_balances(checksum_addr, top_holders_count)
                    state_snapshot.balances = balances
                
                if fetch_allowances:
                    allowances = self._fetch_token_allowances(checksum_addr)
                    state_snapshot.allowances = allowances
            
            # Add basic state info to storage samples
            for key, value in basic_state.items():
                state_snapshot.storage_samples.append(
                    StorageSample(slot=key, value=value, interpreted=f"basic_state_{key}")
                )
            
            logger.info(f"State snapshot complete: {len(state_snapshot.storage_samples)} storage samples, "
                       f"{len(state_snapshot.balances)} balances, {len(state_snapshot.allowances)} allowances")
            
            return state_snapshot
            
        except Exception as e:
            logger.error(f"Error fetching state for {address}: {e}")
            return StateSnapshot()
    
    def _get_basic_contract_state(self, address: str) -> Dict[str, str]:
        """Get basic contract state information."""
        basic_state = {}
        
        try:
            # Contract balance
            balance = self.web3.eth.get_balance(address)
            basic_state['eth_balance'] = hex(balance)
            
            # Contract nonce (for contract accounts)
            nonce = self.web3.eth.get_transaction_count(address)
            basic_state['nonce'] = hex(nonce)
            
            # Code size
            code = self.web3.eth.get_code(address)
            basic_state['code_size'] = hex(len(code))
            
        except Exception as e:
            logger.debug(f"Error getting basic state: {e}")
        
        return basic_state
    
    def _fetch_storage_samples(self, address: str, custom_slots: Optional[List[str]] = None) -> List[StorageSample]:
        """Fetch storage slot samples for analysis."""
        storage_samples = []
        
        # Combine common slots with custom slots
        slots_to_check = list(self.common_slots.keys())
        if custom_slots:
            slots_to_check.extend(custom_slots)
        
        # Add sequential slots for discovery
        sequential_slots = [hex(i) for i in range(20)]  # Check first 20 slots
        slots_to_check.extend(sequential_slots)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_slots = []
        for slot in slots_to_check:
            if slot not in seen:
                seen.add(slot)
                unique_slots.append(slot)
        
        # Fetch slots in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_slot = {
                executor.submit(self._read_storage_slot, address, slot): slot
                for slot in unique_slots
            }
            
            for future in as_completed(future_to_slot):
                slot = future_to_slot[future]
                try:
                    value = future.result()
                    if value and value != '0x' + '00' * 32:  # Skip empty slots
                        interpretation = self._interpret_storage_value(slot, value)
                        storage_samples.append(
                            StorageSample(slot=slot, value=value, interpreted=interpretation)
                        )
                except Exception as e:
                    logger.debug(f"Error reading storage slot {slot}: {e}")
        
        return storage_samples
    
    def _read_storage_slot(self, address: str, slot: str) -> Optional[str]:
        """Read a single storage slot."""
        try:
            # Normalize slot format
            if not slot.startswith('0x'):
                slot = '0x' + slot
            
            value = self.web3.eth.get_storage_at(address, slot)
            return value.hex()
            
        except Exception as e:
            logger.debug(f"Error reading slot {slot}: {e}")
            return None
    
    def _interpret_storage_value(self, slot: str, value: str) -> str:
        """Interpret storage slot value based on known patterns."""
        # Check if it's a known common slot
        for name, common_slot in self.common_slots.items():
            if slot.lower() == common_slot.lower():
                return f"common_slot_{name}"
        
        # Try to interpret the value
        if len(value) == 66:  # 0x + 64 hex chars = 32 bytes
            # Check if it looks like an address (last 20 bytes)
            potential_addr = value[-40:]  # Last 40 hex chars = 20 bytes
            if potential_addr != '00' * 20:
                try:
                    addr = Web3.to_checksum_address('0x' + potential_addr)
                    if is_contract_address(self.web3, addr):
                        return f"possible_address_{addr}"
                except Exception:
                    pass
            
            # Check if it's a small integer (could be a counter, flag, etc.)
            try:
                int_value = int(value, 16)
                if int_value < 1000000:  # Arbitrary threshold for "small" numbers
                    return f"small_int_{int_value}"
                elif int_value > 10**15:  # Large number, could be wei amount
                    return f"large_int_possibly_wei_{int_value}"
            except ValueError:
                pass
        
        return "unknown"
    
    def _is_erc20_like(self, address: str) -> bool:
        """Check if contract implements ERC20-like interface."""
        try:
            # Try calling totalSupply() - most ERC20 tokens have this
            result = self.web3.eth.call({
                'to': address,
                'data': self.selectors['totalSupply']
            })
            
            # If call succeeds and returns 32 bytes, likely ERC20
            return len(result) == 32
            
        except Exception:
            return False
    
    def _fetch_token_balances(self, address: str, top_count: int) -> List[Balance]:
        """Fetch token balances for top holders."""
        balances = []
        
        try:
            # Get decimals for proper formatting
            decimals = self._get_token_decimals(address)
            
            # Get total supply
            total_supply = self._get_total_supply(address)
            if not total_supply:
                return balances
            
            # For now, we'll check some common addresses that often hold tokens
            # In a full implementation, this would involve analyzing Transfer events
            # to find actual holders
            common_addresses = [
                '0x0000000000000000000000000000000000000000',  # Zero address
                '0x000000000000000000000000000000000000dead',  # Burn address
                '0xd8da6bf26964af9d7eed9e03e53415d37aa96045',  # Vitalik
                '0x47ac0fb4f2d84898e4d9e7b4dab3c24507a6d503',  # Binance hot wallet
                '0x8894e0a0c962cb723c1976a4421c95949be2d4e3',  # Binance hot wallet 2
            ]
            
            # Add the contract itself
            common_addresses.append(address)
            
            for addr in common_addresses:
                try:
                    balance_wei = self._get_balance_of(address, addr)
                    if balance_wei and balance_wei > 0:
                        balances.append(Balance(
                            address=addr,
                            balance=str(balance_wei),
                            token_address=address,
                            decimals=decimals
                        ))
                except Exception as e:
                    logger.debug(f"Error getting balance for {addr}: {e}")
            
            # Sort by balance descending
            balances.sort(key=lambda b: int(b.balance), reverse=True)
            
            return balances[:top_count]
            
        except Exception as e:
            logger.error(f"Error fetching token balances: {e}")
            return []
    
    def _fetch_token_allowances(self, address: str) -> List[Allowance]:
        """Fetch significant token allowances."""
        allowances = []
        
        try:
            # This is a simplified implementation
            # In practice, you'd analyze Approval events to find actual allowances
            
            # Check allowances from the contract to common DEX routers
            common_spenders = [
                '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',  # Uniswap V2 Router
                '0xE592427A0AEce92De3Edee1F18E0157C05861564',  # Uniswap V3 Router
                '0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F',  # SushiSwap Router
            ]
            
            for spender in common_spenders:
                try:
                    allowance_amount = self._get_allowance(address, address, spender)
                    if allowance_amount and allowance_amount > 0:
                        allowances.append(Allowance(
                            owner=address,
                            spender=spender,
                            amount=str(allowance_amount),
                            token_address=address
                        ))
                except Exception as e:
                    logger.debug(f"Error getting allowance for {spender}: {e}")
            
            return allowances
            
        except Exception as e:
            logger.error(f"Error fetching allowances: {e}")
            return []
    
    def _get_token_decimals(self, address: str) -> int:
        """Get token decimals."""
        try:
            result = self.web3.eth.call({
                'to': address,
                'data': self.selectors['decimals']
            })
            return int.from_bytes(result, byteorder='big')
        except Exception:
            return 18  # Default to 18 decimals
    
    def _get_total_supply(self, address: str) -> Optional[int]:
        """Get token total supply."""
        try:
            result = self.web3.eth.call({
                'to': address,
                'data': self.selectors['totalSupply']
            })
            return int.from_bytes(result, byteorder='big')
        except Exception:
            return None
    
    def _get_balance_of(self, token_address: str, holder_address: str) -> Optional[int]:
        """Get token balance for specific holder."""
        try:
            # Encode balanceOf(address) call
            call_data = self.selectors['balanceOf'] + holder_address[2:].zfill(64)
            
            result = self.web3.eth.call({
                'to': token_address,
                'data': call_data
            })
            
            return int.from_bytes(result, byteorder='big')
            
        except Exception:
            return None
    
    def _get_allowance(self, token_address: str, owner: str, spender: str) -> Optional[int]:
        """Get allowance amount."""
        try:
            # Encode allowance(address,address) call
            call_data = (self.selectors['allowance'] + 
                        owner[2:].zfill(64) + 
                        spender[2:].zfill(64))
            
            result = self.web3.eth.call({
                'to': token_address,
                'data': call_data
            })
            
            return int.from_bytes(result, byteorder='big')
            
        except Exception:
            return None
    
    def analyze_state_changes(self, address: str, from_block: int, to_block: int) -> Dict[str, Any]:
        """Analyze state changes between two blocks."""
        try:
            logger.info(f"Analyzing state changes from block {from_block} to {to_block}")
            
            # Get state at both blocks
            state_before = self._get_state_at_block(address, from_block)
            state_after = self._get_state_at_block(address, to_block)
            
            changes = {
                'block_range': f"{from_block}-{to_block}",
                'storage_changes': [],
                'balance_changes': {},
                'summary': {
                    'slots_changed': 0,
                    'new_slots': 0,
                    'removed_slots': 0
                }
            }
            
            # Compare storage slots
            all_slots = set(state_before.keys()) | set(state_after.keys())
            
            for slot in all_slots:
                before_value = state_before.get(slot, '0x' + '00' * 32)
                after_value = state_after.get(slot, '0x' + '00' * 32)
                
                if before_value != after_value:
                    changes['storage_changes'].append({
                        'slot': slot,
                        'before': before_value,
                        'after': after_value,
                        'interpretation': self._interpret_storage_value(slot, after_value)
                    })
                    changes['summary']['slots_changed'] += 1
                
                if slot not in state_before:
                    changes['summary']['new_slots'] += 1
                elif slot not in state_after:
                    changes['summary']['removed_slots'] += 1
            
            return changes
            
        except Exception as e:
            logger.error(f"Error analyzing state changes: {e}")
            return {}
    
    def _get_state_at_block(self, address: str, block_number: int) -> Dict[str, str]:
        """Get contract storage state at specific block."""
        state = {}
        
        # Read common slots at specific block
        for name, slot in self.common_slots.items():
            try:
                value = self.web3.eth.get_storage_at(address, slot, block_number)
                if value != b'\x00' * 32:
                    state[slot] = value.hex()
            except Exception as e:
                logger.debug(f"Error reading slot {slot} at block {block_number}: {e}")
        
        return state
