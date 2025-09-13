# shadowscan/collectors/evm/oracle_intel.py (Fixed Version)
"""Oracle intelligence gathering and TWAP analysis - Fixed method names."""

from web3 import Web3
from typing import Dict, Any, List, Optional, Set
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from eth_utils import keccak

from shadowscan.utils.schema import OracleInfo
from shadowscan.utils.helpers import is_contract_address, calculate_risk_score
from shadowscan.data.contracts import DEFI_PROTOCOLS, ORACLE_CONTRACTS, get_chainlink_feeds

logger = logging.getLogger(__name__)

class OracleIntel:
    """Oracle intelligence gathering with multi-protocol asset detection."""
    
    def __init__(self, web3: Web3, max_workers: int = 4):
        self.web3 = web3
        self.max_workers = max_workers
        
        # Use contracts from data file
        self.defi_protocols = DEFI_PROTOCOLS
        self.oracle_contracts = ORACLE_CONTRACTS
        
        # Oracle function selectors
        self.oracle_selectors = {
            # Chainlink
            '0x50d25bcd': 'latestAnswer',
            '0xfeaf968c': 'latestRoundData', 
            '0x313ce567': 'decimals',
            '0x7284e416': 'description',
            
            # TWAP
            '0x0902f1ac': 'getReserves',
            '0x5909c0d5': 'price0CumulativeLast',
            '0x5a3d5493': 'price1CumulativeLast',
            '0x3850c7bd': 'slot0',
            '0x883bdbfd': 'observe',
            
            # Compound
            '0xfc57d4df': 'getUnderlyingPrice',
            '0x46d15f5a': 'getPriceFromAsset',
            
            # MakerDAO  
            '0x91afdfce': 'peek',
            '0x29ae8114': 'read',
            
            # Custom oracles
            '0x98d5fdca': 'getPrice',
            '0xe7c46d1b': 'latestPrice',
            '0xa035b1fe': 'price'
        }
        
        # Risk scoring weights
        self.risk_weights = {
            'twap_window': 0.4,
            'source_diversity': 0.3,
            'protocol_reliability': 0.2,
            'update_frequency': 0.1
        }
    
    def gather_oracle_info(self, target_session: Dict[str, Any], provider) -> OracleInfo:
        """
        Gather oracle information from session data.
        
        Args:
            target_session: Session data containing contract info
            provider: Web3 provider
            
        Returns:
            OracleInfo with oracle analysis
        """
        try:
            target_address = target_session.get('target')
            if not target_address:
                return OracleInfo()
            
            logger.info(f"Gathering oracle intelligence for {target_address}")
            
            oracle_info = OracleInfo()
            
            # Direct oracle usage analysis
            direct_usage = self._analyze_direct_oracle_usage(target_session)
            oracle_info.type = direct_usage.get('type', 'unknown')
            oracle_info.sources.extend(direct_usage.get('sources', []))
            oracle_info.price_feeds.extend(direct_usage.get('price_feeds', []))
            
            # Protocol asset usage detection
            protocol_usage = self._detect_protocol_asset_usage(target_address)
            oracle_info.sources.extend(protocol_usage.get('oracle_sources', []))
            oracle_info.price_feeds.extend(protocol_usage.get('price_feeds', []))
            
            # DEX oracle relationships
            dex_oracle_data = self._analyze_dex_oracle_relationships(target_session)
            if dex_oracle_data:
                oracle_info.type = dex_oracle_data.get('type', oracle_info.type)
                oracle_info.sources.extend(dex_oracle_data.get('sources', []))
                oracle_info.twap_window = dex_oracle_data.get('twap_window')
            
            # Remove duplicates
            oracle_info.sources = list(set(oracle_info.sources))
            oracle_info.price_feeds = list(set(oracle_info.price_feeds))
            
            # Calculate risk score
            oracle_info.twap_risk_score = self._calculate_oracle_risk_score(oracle_info, target_session)
            
            logger.info(f"Oracle analysis complete: type={oracle_info.type}, "
                       f"sources={len(oracle_info.sources)}, risk={oracle_info.twap_risk_score:.2f}")
            
            return oracle_info
            
        except Exception as e:
            logger.error(f"Error gathering oracle info: {e}")
            return OracleInfo()
    
    def _analyze_direct_oracle_usage(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze contract for direct oracle usage patterns."""
        oracle_usage = {
            'type': 'unknown',
            'sources': [],
            'price_feeds': []
        }
        
        try:
            target_address = session.get('target')
            abi = session.get('abi', [])
            bytecode = session.get('bytecode')
            
            if not target_address:
                return oracle_usage
            
            # Analyze ABI for oracle functions
            if abi:
                abi_analysis = self._analyze_abi_oracle_patterns(abi)
                oracle_usage['type'] = abi_analysis.get('type', 'unknown')
                oracle_usage['sources'].extend(abi_analysis.get('sources', []))
            
            # Analyze bytecode for oracle calls
            if bytecode:
                bytecode_analysis = self._analyze_bytecode_oracle_patterns(bytecode, target_address)
                if bytecode_analysis.get('type') != 'unknown':
                    oracle_usage['type'] = bytecode_analysis['type']
                oracle_usage['sources'].extend(bytecode_analysis.get('sources', []))
            
            return oracle_usage
            
        except Exception as e:
            logger.debug(f"Error analyzing direct oracle usage: {e}")
            return oracle_usage
    
    def _analyze_abi_oracle_patterns(self, abi: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze ABI for oracle-related functions."""
        analysis = {
            'type': 'unknown',
            'sources': [],
            'functions': []
        }
        
        try:
            for item in abi:
                if item.get('type') != 'function':
                    continue
                
                func_name = item.get('name', '').lower()
                
                # Chainlink patterns
                if func_name in ['latestanswer', 'latestrounddata', 'getrounddata']:
                    analysis['type'] = 'chainlink'
                    analysis['functions'].append(func_name)
                
                # TWAP patterns
                elif func_name in ['price0cumulativelast', 'price1cumulativelast', 'observe']:
                    analysis['type'] = 'twap'
                    analysis['functions'].append(func_name)
                
                # Custom oracle patterns
                elif any(pattern in func_name for pattern in ['price', 'oracle', 'feed']):
                    if analysis['type'] == 'unknown':
                        analysis['type'] = 'custom'
                    analysis['functions'].append(func_name)
            
            return analysis
            
        except Exception as e:
            logger.debug(f"Error analyzing ABI oracle patterns: {e}")
            return analysis
    
    def _analyze_bytecode_oracle_patterns(self, bytecode: str, contract_address: str) -> Dict[str, Any]:
        """Analyze bytecode for oracle addresses and call patterns."""
        analysis = {
            'type': 'unknown',
            'sources': []
        }
        
        try:
            if not bytecode or len(bytecode) < 10:
                return analysis
            
            bytecode_hex = bytecode.lower().replace('0x', '')
            
            # Look for hardcoded addresses
            address_pattern = r'[a-f0-9]{40}'
            potential_addresses = re.findall(address_pattern, bytecode_hex)
            
            # Check potential oracle addresses
            for addr_hex in set(potential_addresses):
                if len(addr_hex) == 40 and not addr_hex.startswith('00000'):
                    try:
                        address = Web3.to_checksum_address('0x' + addr_hex)
                        
                        if address.lower() == contract_address.lower():
                            continue
                        
                        if is_contract_address(self.web3, address):
                            oracle_type = self._identify_oracle_contract_type(address)
                            if oracle_type != 'unknown':
                                analysis['sources'].append(f"{oracle_type}:{address}")
                                if analysis['type'] == 'unknown':
                                    analysis['type'] = oracle_type
                    
                    except Exception:
                        continue
            
            # Check for function call patterns
            function_patterns = {
                '50d25bcd': 'chainlink',  # latestAnswer()
                'feaf968c': 'chainlink',  # latestRoundData() 
                '0902f1ac': 'twap',       # getReserves()
                '5909c0d5': 'twap',       # price0CumulativeLast()
                '3850c7bd': 'twap'        # slot0()
            }
            
            for selector, oracle_type in function_patterns.items():
                if selector in bytecode_hex:
                    if analysis['type'] == 'unknown':
                        analysis['type'] = oracle_type
            
            return analysis
            
        except Exception as e:
            logger.debug(f"Error analyzing bytecode oracle patterns: {e}")
            return analysis
    
    def _identify_oracle_contract_type(self, address: str) -> str:
        """Identify oracle contract type by testing function calls."""
        try:
            # Test Chainlink aggregator
            try:
                result = self.web3.eth.call({
                    'to': address,
                    'data': self.oracle_selectors.get('0x50d25bcd', '0x50d25bcd')  # latestAnswer
                })
                if len(result) > 0:
                    return 'chainlink'
            except Exception:
                pass
            
            # Test Uniswap V2 pair
            try:
                result = self.web3.eth.call({
                    'to': address, 
                    'data': '0x0902f1ac'  # getReserves
                })
                if len(result) >= 96:
                    return 'uniswap_v2'
            except Exception:
                pass
            
            # Test Uniswap V3 pool
            try:
                result = self.web3.eth.call({
                    'to': address,
                    'data': '0x3850c7bd'  # slot0
                })
                if len(result) >= 32:
                    return 'uniswap_v3'
            except Exception:
                pass
            
            return 'unknown'
            
        except Exception as e:
            logger.debug(f"Error identifying oracle contract type: {e}")
            return 'unknown'
    
    def _detect_protocol_asset_usage(self, target_address: str) -> Dict[str, List[str]]:
        """Detect if target token is used as oracle asset in DeFi protocols."""
        results = {
            'oracle_sources': [],
            'price_feeds': [],
            'protocol_usage': []
        }
        
        try:
            checksum_addr = Web3.to_checksum_address(target_address)
            
            # Check Compound
            compound_usage = self._check_compound_usage(checksum_addr)
            results['oracle_sources'].extend(compound_usage.get('oracles', []))
            
            # Check Aave
            aave_usage = self._check_aave_usage(checksum_addr)
            results['oracle_sources'].extend(aave_usage.get('oracles', []))
            
            # Check Chainlink feeds
            chainlink_usage = self._check_chainlink_feeds(checksum_addr)
            results['price_feeds'].extend(chainlink_usage.get('feeds', []))
            results['oracle_sources'].extend(chainlink_usage.get('sources', []))
            
            return results
            
        except Exception as e:
            logger.debug(f"Error detecting protocol asset usage: {e}")
            return results
    
    def _check_compound_usage(self, target_address: str) -> Dict[str, List[str]]:
        """Check if token is used in Compound protocol."""
        results = {'oracles': []}
        
        try:
            compound_config = self.defi_protocols['compound_v2']
            oracle_address = compound_config['price_oracle']
            
            for market_name, market_addr in compound_config['markets'].items():
                try:
                    # Get underlying asset
                    underlying_result = self.web3.eth.call({
                        'to': market_addr,
                        'data': '0x6f307dc3'  # underlying()
                    })
                    
                    if len(underlying_result) >= 32:
                        underlying = Web3.to_checksum_address(underlying_result[-20:])
                        
                        if underlying.lower() == target_address.lower():
                            results['oracles'].append(f"compound_v2_oracle:{oracle_address}")
                            
                except Exception as e:
                    logger.debug(f"Error checking Compound market {market_name}: {e}")
            
            return results
            
        except Exception as e:
            logger.debug(f"Error checking Compound usage: {e}")
            return results
    
    def _check_aave_usage(self, target_address: str) -> Dict[str, List[str]]:
        """Check if token is used in Aave protocol."""
        results = {'oracles': []}
        
        try:
            for version in ['aave_v2', 'aave_v3']:
                if version not in self.defi_protocols:
                    continue
                    
                aave_config = self.defi_protocols[version]
                oracle_address = aave_config['price_oracle']
                
                try:
                    # Check asset price
                    price_result = self.web3.eth.call({
                        'to': oracle_address,
                        'data': '0xb3596f07' + target_address[2:].zfill(64)  # getAssetPrice(asset)
                    })
                    
                    if len(price_result) >= 32:
                        price = int.from_bytes(price_result, byteorder='big')
                        if price > 0:
                            results['oracles'].append(f"{version}_oracle:{oracle_address}")
                            
                except Exception as e:
                    logger.debug(f"Error checking {version} usage: {e}")
            
            return results
            
        except Exception as e:
            logger.debug(f"Error checking Aave usage: {e}")
            return results
    
    def _check_chainlink_feeds(self, target_address: str) -> Dict[str, List[str]]:
        """Check if token has Chainlink price feeds."""
        results = {'feeds': [], 'sources': []}
        
        try:
            chainlink_feeds = get_chainlink_feeds()
            
            for pair_name, aggregator in chainlink_feeds.items():
                try:
                    # Check if feed exists and is active
                    result = self.web3.eth.call({
                        'to': aggregator,
                        'data': '0x50d25bcd'  # latestAnswer()
                    })
                    
                    if len(result) > 0:
                        results['feeds'].append(f"chainlink_feed:{aggregator}")
                        results['sources'].append(f"chainlink:{aggregator}")
                        
                except Exception as e:
                    logger.debug(f"Error checking Chainlink feed {pair_name}: {e}")
            
            return results
            
        except Exception as e:
            logger.debug(f"Error checking Chainlink feeds: {e}")
            return results
    
    def _analyze_dex_oracle_relationships(self, session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze DEX oracle relationships from session data."""
        try:
            dex_refs = session.get('dex_refs', [])
            if not dex_refs:
                return None
            
            analysis = {
                'type': 'twap',
                'sources': [],
                'twap_window': None
            }
            
            total_liquidity = 0.0
            weighted_windows = []
            
            for dex_ref in dex_refs:
                pair_address = dex_ref.get('pair')
                dex_name = dex_ref.get('dex_name', 'unknown')
                liquidity_usd = dex_ref.get('liquidity_usd', 0)
                
                if pair_address:
                    analysis['sources'].append(f"dex_pair:{pair_address}")
                    
                    # Estimate TWAP window
                    estimated_window = self._estimate_twap_window(dex_name, liquidity_usd)
                    if estimated_window:
                        weighted_windows.append((estimated_window, liquidity_usd))
                    
                    total_liquidity += liquidity_usd
            
            # Calculate liquidity-weighted TWAP window
            if weighted_windows:
                total_weight = sum(weight for _, weight in weighted_windows)
                if total_weight > 0:
                    weighted_avg = sum(window * weight for window, weight in weighted_windows) / total_weight
                    analysis['twap_window'] = int(weighted_avg)
            
            return analysis if analysis['sources'] else None
            
        except Exception as e:
            logger.debug(f"Error analyzing DEX oracle relationships: {e}")
            return None
    
    def _estimate_twap_window(self, dex_name: str, liquidity_usd: float) -> Optional[int]:
        """Estimate TWAP window based on DEX type and liquidity."""
        try:
            base_windows = {
                'uniswap_v2': 1800,    # 30 minutes
                'uniswap_v3': 900,     # 15 minutes  
                'sushiswap': 1800,     # 30 minutes
                'curve': 3600,         # 1 hour
                'balancer': 2400       # 40 minutes
            }
            
            base_window = base_windows.get(dex_name, 1800)
            
            # Adjust based on liquidity
            if liquidity_usd > 10000000:      # > $10M
                return max(300, base_window // 2)
            elif liquidity_usd > 1000000:     # > $1M
                return base_window
            elif liquidity_usd > 100000:      # > $100k
                return base_window * 2
            else:
                return base_window * 4
                
        except Exception:
            return 1800
    
    def _calculate_oracle_risk_score(self, oracle_info: OracleInfo, session: Dict[str, Any]) -> float:
        """Calculate oracle risk score."""
        try:
            risk_factors = {}
            
            # Source diversity factor
            source_count = len(oracle_info.sources)
            if source_count == 0:
                risk_factors['source_diversity'] = 1.0
            elif source_count == 1:
                risk_factors['source_diversity'] = 0.8
            elif source_count == 2:
                risk_factors['source_diversity'] = 0.5
            else:
                risk_factors['source_diversity'] = 0.2
            
            # TWAP window factor
            if oracle_info.twap_window:
                if oracle_info.twap_window < 300:        # < 5 min
                    risk_factors['twap_window'] = 0.9
                elif oracle_info.twap_window < 900:      # < 15 min
                    risk_factors['twap_window'] = 0.7
                elif oracle_info.twap_window < 1800:     # < 30 min
                    risk_factors['twap_window'] = 0.5
                else:
                    risk_factors['twap_window'] = 0.2
            else:
                risk_factors['twap_window'] = 0.5
            
            # Protocol reliability factor
            protocol_risk = self._assess_protocol_reliability(oracle_info.sources)
            risk_factors['protocol_reliability'] = protocol_risk
            
            # Update frequency (placeholder)
            risk_factors['update_frequency'] = 0.3
            
            # Calculate weighted risk score
            risk_score = calculate_risk_score(risk_factors, self.risk_weights)
            return min(1.0, risk_score)
            
        except Exception as e:
            logger.debug(f"Error calculating oracle risk score: {e}")
            return 0.5
    
    def _assess_protocol_reliability(self, sources: List[str]) -> float:
        """Assess protocol reliability based on sources."""
        if not sources:
            return 1.0
        
        protocol_scores = {
            'chainlink': 0.1,
            'compound_v2': 0.2,
            'aave_v2': 0.2,
            'aave_v3': 0.25,
            'makerdao': 0.15,
            'dex_pair': 0.6,
            'custom': 0.8,
            'unknown': 0.9
        }
        
        total_score = 0.0
        for source in sources:
            protocol = source.split(':')[0]
            score = protocol_scores.get(protocol, 0.9)
            total_score += score
        
        return total_score / len(sources)
