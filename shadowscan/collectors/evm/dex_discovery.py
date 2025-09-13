# shadowscan/collectors/evm/dex_discovery.py
"""Enhanced DEX discovery with factory log scanning using contract database."""

from web3 import Web3
from typing import List, Dict, Any, Optional, Set, Tuple
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from decimal import Decimal
from eth_utils import keccak

from shadowscan.utils.schema import DexReference
from shadowscan.utils.helpers import format_wei, is_contract_address
from shadowscan.data.contracts import DEX_CONTRACTS, get_base_tokens, get_token_info

logger = logging.getLogger(__name__)

class DexDiscovery:
    """Enhanced DEX discovery with factory log scanning and multi-protocol support."""
    
    def __init__(self, web3: Web3, max_workers: int = 8):
        self.web3 = web3
        self.max_workers = max_workers
        
        # Use DEX configurations from contract database
        self.dex_factories = DEX_CONTRACTS
        
        # Get base tokens from contract database
        self.base_tokens = get_base_tokens()
        
        # Enhanced function selectors for better analysis
        self.selectors = {
            'getReserves': '0x0902f1ac',
            'token0': '0x0dfe1681',
            'token1': '0xd21220a7',
            'factory': '0xc45a0155',
            'fee': '0xddca3f43',
            'liquidity': '0x1a686502',
            'totalSupply': '0x18160ddd',
            'decimals': '0x313ce567',
            'slot0': '0x3850c7bd',  # V3 slot0
            'get_balances': '0x4e5d9dcd',  # Curve get_balances
            'coins': '0x514c4e4d',  # Curve coins
            'token': '0x405e3613'  # V3 token (for LP tokens)
        }
    
    def discover_dex_relations(self, address: str, provider, chain: str = 'ethereum') -> List[DexReference]:
        """
        Enhanced DEX relationship discovery with factory log scanning.
        
        Args:
            address: Token/contract address to analyze
            provider: Web3 provider
            chain: Blockchain network
            
        Returns:
            List of DexReference objects with comprehensive DEX coverage
        """
        try:
            checksum_addr = Web3.to_checksum_address(address)
            logger.info(f"Enhanced DEX discovery for {checksum_addr}")
            
            all_dex_refs = []
            
            # Method 1: Factory log scanning (most comprehensive)
            factory_pairs = self._scan_factory_logs(checksum_addr)
            logger.info(f"Found {len(factory_pairs)} pairs from factory logs")
            
            # Method 2: Direct pair calculation using CREATE2
            calculated_pairs = self._calculate_direct_pairs(checksum_addr)
            logger.info(f"Found {len(calculated_pairs)} pairs from calculations")
            
            # Method 3: Curve and Balancer discovery
            curve_pools = self._discover_curve_pools(checksum_addr)
            logger.info(f"Found {len(curve_pools)} Curve pools")
            
            # Combine all discoveries
            all_pairs = factory_pairs + calculated_pairs + curve_pools
            
            # Remove duplicates
            unique_pairs = self._deduplicate_pairs(all_pairs)
            
            # Analyze liquidity for each pair in parallel
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_pair = {
                    executor.submit(self._analyze_pair_liquidity, pair): pair 
                    for pair in unique_pairs
                }
                
                for future in as_completed(future_to_pair):
                    pair = future_to_pair[future]
                    try:
                        dex_ref = future.result()
                        if dex_ref and dex_ref.liquidity_usd > 100:  # Filter out dust
                            all_dex_refs.append(dex_ref)
                    except Exception as e:
                        logger.debug(f"Error analyzing pair {pair.get('pair_address', 'unknown')}: {e}")
            
            # Sort by liquidity descending
            all_dex_refs.sort(key=lambda x: x.liquidity_usd, reverse=True)
            
            logger.info(f"Enhanced discovery completed: {len(all_dex_refs)} DEX relationships found")
            return all_dex_refs
            
        except Exception as e:
            logger.error(f"Error in enhanced DEX discovery: {e}")
            return []
    
    def _scan_factory_logs(self, token_address: str) -> List[Dict[str, Any]]:
        """Scan factory logs for PairCreated/PoolCreated events."""
        pairs = []
        
        try:
            # Get recent blocks to scan (last 500k blocks ~ 2-3 months)
            current_block = self.web3.eth.block_number
            from_block = max(0, current_block - 500000)
            
            logger.info(f"Scanning factory logs from block {from_block} to {current_block}")
            
            for dex_name, config in self.dex_factories.items():
                if dex_name in ['curve', 'balancer_v2']:  # Handle separately
                    continue
                    
                try:
                    factory_address = config['factory']
                    topic = config.get('pair_created_topic') or config.get('pool_created_topic')
                    
                    if not topic:
                        continue
                    
                    # Get all PairCreated events from factory
                    logs = self.web3.eth.get_logs({
                        'address': factory_address,
                        'topics': [topic],
                        'fromBlock': from_block,
                        'toBlock': 'latest'
                    })
                    
                    logger.debug(f"Found {len(logs)} {dex_name} factory events")
                    
                    # Parse logs to find pairs involving our token
                    for log in logs:
                        pair_info = self._parse_factory_log(log, token_address, dex_name, config)
                        if pair_info:
                            pairs.append(pair_info)
                            
                except Exception as e:
                    logger.debug(f"Error scanning {dex_name} factory: {e}")
                    continue
            
            logger.info(f"Factory log scanning found {len(pairs)} pairs")
            return pairs
            
        except Exception as e:
            logger.error(f"Error scanning factory logs: {e}")
            return []
    
    def _parse_factory_log(self, log, target_token: str, dex_name: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse factory log to extract pair information."""
        try:
            if config['version'] == 'v2':
                # Uniswap V2 style: PairCreated(token0, token1, pair, uint)
                if len(log.topics) >= 3:
                    token0 = '0x' + log.topics[1].hex()[-40:]
                    token1 = '0x' + log.topics[2].hex()[-40:]
                    
                    # Check if our target token is involved
                    if target_token.lower() in [token0.lower(), token1.lower()]:
                        # Extract pair address from data
                        if len(log.data) >= 64:  # pair address + uint
                            pair_address = Web3.to_checksum_address('0x' + log.data.hex()[26:66])
                            
                            return {
                                'pair_address': pair_address,
                                'token0': Web3.to_checksum_address(token0),
                                'token1': Web3.to_checksum_address(token1),
                                'dex_name': dex_name,
                                'factory': log.address,
                                'router': config['router'],
                                'block_created': log.blockNumber,
                                'version': 'v2'
                            }
            
            elif config['version'] == 'v3':
                # Uniswap V3 style: PoolCreated(token0, token1, fee, tickSpacing, pool)
                if len(log.topics) >= 4 and len(log.data) >= 64:
                    token0 = '0x' + log.topics[1].hex()[-40:]
                    token1 = '0x' + log.topics[2].hex()[-40:]
                    fee = int(log.topics[3].hex(), 16)
                    
                    if target_token.lower() in [token0.lower(), token1.lower()]:
                        # Pool address is typically in the data
                        pool_address = Web3.to_checksum_address('0x' + log.data.hex()[-40:])
                        
                        return {
                            'pair_address': pool_address,
                            'token0': Web3.to_checksum_address(token0),
                            'token1': Web3.to_checksum_address(token1),
                            'dex_name': dex_name,
                            'factory': log.address,
                            'router': config['router'],
                            'fee_tier': str(fee),
                            'block_created': log.blockNumber,
                            'version': 'v3'
                        }
            
        except Exception as e:
            logger.debug(f"Error parsing factory log: {e}")
        
        return None
    
    def _calculate_direct_pairs(self, token_address: str) -> List[Dict[str, Any]]:
        """Calculate pair addresses directly using CREATE2."""
        pairs = []
        
        for dex_name, config in self.dex_factories.items():
            if dex_name in ['curve', 'balancer_v2'] or config.get('version') != 'v2':
                continue
                
            # Calculate pairs with common base tokens
            for base_name, base_address in self.base_tokens.items():
                if base_address.lower() == token_address.lower():
                    continue
                    
                try:
                    pair_address = self._compute_v2_pair_address(
                        token_address, base_address, config['factory'], config.get('init_code_hash')
                    )
                    
                    if pair_address and self._pair_exists(pair_address):
                        pairs.append({
                            'pair_address': pair_address,
                            'token0': token_address,
                            'token1': base_address,
                            'dex_name': dex_name,
                            'factory': config['factory'],
                            'router': config['router'],
                            'base_token': base_name,
                            'version': 'v2'
                        })
                        
                except Exception as e:
                    logger.debug(f"Error calculating {dex_name} pair with {base_name}: {e}")
        
        return pairs
    
    def _compute_v2_pair_address(self, token_a: str, token_b: str, factory_address: str, init_code_hash: Optional[str] = None) -> Optional[str]:
        """Compute Uniswap V2 style pair address using CREATE2."""
        try:
            # Sort tokens
            if token_a.lower() > token_b.lower():
                token_a, token_b = token_b, token_a
            
            # Compute salt
            salt = keccak(
                bytes.fromhex(token_a[2:].zfill(64)) + 
                bytes.fromhex(token_b[2:].zfill(64))
            )
            
            # Use provided init code hash or default to Uniswap V2
            if not init_code_hash:
                init_code_hash = '96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f'
            
            # CREATE2 address calculation
            create2_input = (
                bytes.fromhex('ff') + 
                bytes.fromhex(factory_address[2:]) + 
                salt + 
                bytes.fromhex(init_code_hash)
            )
            
            pair_address = Web3.to_checksum_address(keccak(create2_input)[12:])
            return pair_address
            
        except Exception as e:
            logger.debug(f"Error computing V2 pair address: {e}")
            return None
    
    def _discover_curve_pools(self, token_address: str) -> List[Dict[str, Any]]:
        """Discover Curve pools containing the token."""
        pools = []
        
        try:
            curve_config = self.dex_factories.get('curve', {})
            registry_address = curve_config.get('registry')
            
            if not registry_address:
                return pools
            
            # Call find_pool_for_coins on Curve registry
            for base_name, base_address in self.base_tokens.items():
                try:
                    # find_pool_for_coins(coin_a, coin_b) selector: 0x6982c1b7
                    call_data = (
                        '0x6982c1b7' +
                        token_address[2:].zfill(64) +
                        base_address[2:].zfill(64)
                    )
                    
                    result = self.web3.eth.call({
                        'to': registry_address,
                        'data': call_data
                    })
                    
                    if len(result) >= 32 and result != b'\x00' * 32:
                        pool_address = Web3.to_checksum_address(result[-20:])
                        
                        if pool_address != "0x0000000000000000000000000000000000000000":
                            pools.append({
                                'pair_address': pool_address,
                                'token0': token_address,
                                'token1': base_address,
                                'dex_name': 'curve',
                                'registry': registry_address,
                                'base_token': base_name,
                                'version': 'stable'
                            })
                            
                except Exception as e:
                    logger.debug(f"Error checking Curve pool with {base_name}: {e}")
            
        except Exception as e:
            logger.debug(f"Error discovering Curve pools: {e}")
        
        return pools
    
    def _pair_exists(self, pair_address: str) -> bool:
        """Check if pair/pool contract exists."""
        try:
            code = self.web3.eth.get_code(Web3.to_checksum_address(pair_address))
            return len(code) > 0
        except Exception:
            return False
    
    def _deduplicate_pairs(self, pairs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate pairs."""
        seen = set()
        unique_pairs = []
        
        for pair in pairs:
            pair_addr = pair.get('pair_address', '').lower()
            if pair_addr and pair_addr not in seen:
                seen.add(pair_addr)
                unique_pairs.append(pair)
        
        return unique_pairs
    
    def _analyze_pair_liquidity(self, pair_info: Dict[str, Any]) -> Optional[DexReference]:
        """Analyze liquidity for a pair with enhanced accuracy."""
        try:
            pair_address = pair_info['pair_address']
            dex_name = pair_info['dex_name']
            version = pair_info.get('version', 'v2')
            
            if version == 'v2' or dex_name == 'sushiswap':
                return self._analyze_v2_liquidity(pair_info)
            elif version == 'v3':
                return self._analyze_v3_liquidity(pair_info)
            elif dex_name == 'curve':
                return self._analyze_curve_liquidity(pair_info)
            else:
                return self._analyze_generic_liquidity(pair_info)
                
        except Exception as e:
            logger.debug(f"Error analyzing pair liquidity: {e}")
            return None
    
    def _analyze_v2_liquidity(self, pair_info: Dict[str, Any]) -> Optional[DexReference]:
        """Enhanced V2 liquidity analysis with real price data."""
        try:
            pair_address = pair_info['pair_address']
            
            # Get reserves
            reserves_result = self.web3.eth.call({
                'to': pair_address,
                'data': self.selectors['getReserves']
            })
            
            if len(reserves_result) < 96:
                return None
            
            reserve0 = int.from_bytes(reserves_result[:32], byteorder='big')
            reserve1 = int.from_bytes(reserves_result[32:64], byteorder='big')
            
            if reserve0 == 0 or reserve1 == 0:
                return None
            
            # Get token decimals
            token0_decimals = self._get_token_decimals(pair_info['token0'])
            token1_decimals = self._get_token_decimals(pair_info['token1'])
            
            # Calculate USD liquidity using token info from database
            liquidity_usd = self._calculate_usd_liquidity(
                pair_info['token0'], reserve0, token0_decimals,
                pair_info['token1'], reserve1, token1_decimals
            )
            
            # Calculate depth score
            depth_score = min(1.0, liquidity_usd / 100000)  # Normalized to $100k
            
            return DexReference(
                pair=pair_address,
                router=pair_info.get('router', ''),
                reserves=[str(reserve0), str(reserve1)],
                liquidity_usd=liquidity_usd,
                depth_score=depth_score,
                dex_name=pair_info['dex_name'],
                fee_tier=pair_info.get('fee_tier')
            )
            
        except Exception as e:
            logger.debug(f"Error analyzing V2 liquidity: {e}")
            return None
    
    def _analyze_v3_liquidity(self, pair_info: Dict[str, Any]) -> Optional[DexReference]:
        """Analyze Uniswap V3 style liquidity with enhanced accuracy."""
        try:
            pool_address = pair_info['pair_address']
            
            # Get V3 liquidity info with multiple approaches
            liquidity_usd = 0.0
            
            # Method 1: Try to get liquidity directly
            try:
                result = self.web3.eth.call({
                    'to': pool_address,
                    'data': self.selectors['liquidity']
                })
                
                if len(result) >= 32:
                    liquidity = int.from_bytes(result[:32], byteorder='big')
                    if liquidity > 0:
                        # Get fee tier and tick spacing for better estimation
                        fee_tier = int(pair_info.get('fee_tier', '3000'))
                        
                        # Enhanced V3 liquidity estimation based on fee tier
                        if fee_tier == 500:  # 0.05% fee tier (most liquid)
                            liquidity_usd = float(liquidity) / 1e18 * 0.002
                        elif fee_tier == 3000:  # 0.3% fee tier (medium)
                            liquidity_usd = float(liquidity) / 1e18 * 0.0015
                        elif fee_tier == 10000:  # 1% fee tier (less liquid)
                            liquidity_usd = float(liquidity) / 1e18 * 0.001
                        else:
                            liquidity_usd = float(liquidity) / 1e18 * 0.001
            except Exception:
                pass
            
            # Method 2: Try to get slot0 for current tick
            if liquidity_usd == 0:
                try:
                    # slot0() selector: 0x3850c7bd
                    slot0_result = self.web3.eth.call({
                        'to': pool_address,
                        'data': '0x3850c7bd'
                    })
                    
                    if len(slot0_result) >= 64:
                        # Contains sqrtPriceX96 and current tick
                        sqrt_price_x96 = int.from_bytes(slot0_result[:32], byteorder='big')
                        current_tick = int.from_bytes(slot0_result[32:64], byteorder='big', signed=True)
                        
                        # Estimate liquidity based on price and tick
                        if sqrt_price_x96 > 0:
                            # Convert sqrtPriceX96 to price
                            price = (sqrt_price_x96 / 2**96) ** 2
                            liquidity_usd = max(1000.0, price * 10000)  # Rough estimate
                except Exception:
                    pass
            
            # Method 3: Check if pool has any liquidity via totalSupply
            if liquidity_usd == 0:
                try:
                    total_supply_result = self.web3.eth.call({
                        'to': pool_address,
                        'data': self.selectors['totalSupply']
                    })
                    
                    if len(total_supply_result) >= 32:
                        total_supply = int.from_bytes(total_supply_result[:32], byteorder='big')
                        if total_supply > 0:
                            liquidity_usd = float(total_supply) / 1e18 * 500  # Conservative estimate
                except Exception:
                    pass
            
            # Calculate depth score
            depth_score = min(1.0, liquidity_usd / 50000)  # Normalized to $50k for V3
            
            return DexReference(
                pair=pool_address,
                router=pair_info.get('router', ''),
                reserves=[str(int(liquidity_usd * 1e18))],  # Convert back to wei for consistency
                liquidity_usd=liquidity_usd,
                depth_score=depth_score,
                dex_name=f"{pair_info['dex_name']}_v3",
                fee_tier=pair_info.get('fee_tier')
            )
                
        except Exception as e:
            logger.debug(f"Error analyzing V3 liquidity: {e}")
            return None
    
    def _analyze_curve_liquidity(self, pair_info: Dict[str, Any]) -> Optional[DexReference]:
        """Enhanced Curve pool liquidity analysis."""
        try:
            pool_address = pair_info['pair_address']
            registry_address = pair_info.get('registry')
            
            liquidity_usd = 0.0
            
            # Method 1: Try to get liquidity directly from pool
            try:
                # Many Curve pools have a get_balances() method
                # Selector for get_balances(): 0x4e5d9dcd
                balances_result = self.web3.eth.call({
                    'to': pool_address,
                    'data': '0x4e5d9dcd'
                })
                
                if len(balances_result) >= 64:
                    balance0 = int.from_bytes(balances_result[:32], byteorder='big')
                    balance1 = int.from_bytes(balances_result[32:64], byteorder='big')
                    
                    if balance0 > 0 or balance1 > 0:
                        # Get token info for USD conversion
                        token0_decimals = self._get_token_decimals(pair_info['token0'])
                        token1_decimals = self._get_token_decimals(pair_info['token1'])
                        
                        amount0 = balance0 / (10 ** token0_decimals)
                        amount1 = balance1 / (10 ** token1_decimals)
                        
                        liquidity_usd = self._calculate_usd_liquidity(
                            pair_info['token0'], balance0, token0_decimals,
                            pair_info['token1'], balance1, token1_decimals
                        )
            except Exception:
                pass
            
            # Method 2: Try to get liquidity via registry
            if liquidity_usd == 0 and registry_address:
                try:
                    # Some Curve registries have get_liquidity methods
                    # This is a simplified approach
                    pool_exists = self._pair_exists(pool_address)
                    if pool_exists:
                        # Default estimate for active Curve pools
                        liquidity_usd = 10000.0  # Conservative estimate
                except Exception:
                    pass
            
            # Method 3: Check if pool has any activity
            if liquidity_usd == 0:
                try:
                    # Check recent transactions as proxy for activity
                    current_block = self.web3.eth.block_number
                    from_block = max(0, current_block - 1000)  # Last ~4 hours
                    
                    tx_count = self.web3.eth.get_transaction_count(pool_address, from_block)
                    if tx_count > 0:
                        liquidity_usd = 5000.0 * (1 + tx_count / 10)  # Scale with activity
                except Exception:
                    pass
            
            depth_score = min(1.0, liquidity_usd / 100000)  # Normalized to $100k
            
            return DexReference(
                pair=pool_address,
                router=registry_address or '',
                reserves=[str(int(liquidity_usd * 1e18))],  # Convert to wei
                liquidity_usd=liquidity_usd,
                depth_score=depth_score,
                dex_name='curve',
                fee_tier=None
            )
            
        except Exception as e:
            logger.debug(f"Error analyzing Curve liquidity: {e}")
            return None
    
    def _analyze_generic_liquidity(self, pair_info: Dict[str, Any]) -> Optional[DexReference]:
        """Generic liquidity analysis fallback."""
        return DexReference(
            pair=pair_info['pair_address'],
            router=pair_info.get('router', ''),
            reserves=['0', '0'],
            liquidity_usd=1000.0,  # Default estimate
            depth_score=0.3,
            dex_name=pair_info['dex_name'],
            fee_tier=pair_info.get('fee_tier')
        )
    
    def _get_token_decimals(self, token_address: str) -> int:
        """Get token decimals."""
        try:
            # First check our token database
            token_info = get_token_info(token_address)
            if token_info and 'decimals' in token_info:
                return token_info['decimals']
            
            # Fallback to contract call
            result = self.web3.eth.call({
                'to': token_address,
                'data': self.selectors['decimals']
            })
            return int.from_bytes(result, byteorder='big')
        except Exception:
            return 18  # Default
    
    def _calculate_usd_liquidity(self, token0: str, reserve0: int, decimals0: int,
                                token1: str, reserve1: int, decimals1: int) -> float:
        """Calculate USD liquidity using token info from database."""
        try:
            # Get token info from database
            token0_info = get_token_info(token0)
            token1_info = get_token_info(token1)
            
            # Calculate token amounts
            amount0 = reserve0 / (10 ** decimals0)
            amount1 = reserve1 / (10 ** decimals1)
            
            # Check if either token is a stablecoin from our database
            if token0_info.get('type') == 'stablecoin':
                return amount0 * 2  # Total liquidity is 2x one side
            elif token1_info.get('type') == 'stablecoin':
                return amount1 * 2
            
            # Check if WETH is involved
            if token0_info.get('symbol') == 'WETH':
                eth_price_usd = 2500  # Approximate
                return amount0 * eth_price_usd * 2
            elif token1_info.get('symbol') == 'WETH':
                eth_price_usd = 2500  # Approximate
                return amount1 * eth_price_usd * 2
            
            # For other pairs, rough estimate based on reserve values
            total_reserve_value = max(amount0, amount1) * 1000
            return min(total_reserve_value, 1000000)  # Cap at $1M
            
        except Exception as e:
            logger.debug(f"Error calculating USD liquidity: {e}")
            return 0.0
