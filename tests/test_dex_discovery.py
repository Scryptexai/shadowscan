"""
Unit tests for DEX discovery functionality.
Tests factory log scanning, pair calculation, and liquidity analysis.
"""

import pytest
import tempfile
import shutil
from unittest.mock import Mock, MagicMock, patch
from web3 import Web3
from web3.datastructures import AttributeDict

from shadowscan.collectors.evm.dex_discovery import DexDiscovery
from shadowscan.utils.schema import DexReference
from shadowscan.data.contracts import DEX_CONTRACTS, get_base_tokens, get_token_info


class TestDexDiscovery:
    """Test suite for DEX discovery functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        self.web3 = Mock(spec=Web3)
        self.web3.eth.block_number = 15000
        
        # Mock provider
        self.provider = Mock()
        
        # Initialize DEX discovery with test data
        self.dex_discovery = DexDiscovery(self.web3, max_workers=2)
        
        # Test addresses
        self.test_token = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        self.test_weth = "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"  # WETH
        
        # Override DEX factories for testing
        self.dex_discovery.dex_factories = {
            'uniswap_v2': {
                'factory': '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f',
                'router': '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',
                'version': 'v2',
                'init_code_hash': '96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f',
                'pair_created_topic': '0x0d3648bd0f6ba8012a7ba936c6c88ff6a969d9d6abb4fb87974bc3c3b9f8bfa0'
            },
            'uniswap_v3': {
                'factory': '0x1F98431c8aD98523631AE4a59f267346ea31F984',
                'router': '0xE592427A0AEce92De3Edee1F18E0157C05861564',
                'version': 'v3',
                'pool_created_topic': '0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118'
            },
            'curve': {
                'registry': '0x7D86446dDb609eD0F5f8684AcF30380a356b2B4c',
                'version': 'stable'
            }
        }
        
        # Override base tokens for testing
        self.dex_discovery.base_tokens = {
            'WETH': self.test_weth,
            'USDT': '0xdac17f958d2ee523a2206206994597c13d831ec7'
        }
    
    def test_initialization(self):
        """Test DEX discovery initialization."""
        assert self.dex_discovery.web3 == self.web3
        assert self.dex_discovery.max_workers == 2
        assert len(self.dex_discovery.dex_factories) > 0
        assert len(self.dex_discovery.base_tokens) > 0
        assert len(self.dex_discovery.selectors) > 0
    
    def test_compute_v2_pair_address(self):
        """Test V2 pair address calculation using CREATE2."""
        token_a = self.test_token
        token_b = self.test_weth
        factory = '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f'
        init_hash = '96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f'
        
        pair_address = self.dex_discovery._compute_v2_pair_address(
            token_a, token_b, factory, init_hash
        )
        
        assert pair_address is not None
        assert Web3.is_address(pair_address)
        assert pair_address.startswith('0x')
    
    def test_pair_exists_success(self):
        """Test pair existence check when pair exists."""
        pair_address = "0x1234567890123456789012345678901234567890"
        
        # Mock successful code retrieval
        self.web3.eth.get_code.return_value = b'0x608060405234801561001057600080fd5b50'  # Non-empty code
        
        result = self.dex_discovery._pair_exists(pair_address)
        
        assert result is True
        self.web3.eth.get_code.assert_called_once_with(Web3.to_checksum_address(pair_address))
    
    def test_pair_exists_failure(self):
        """Test pair existence check when pair doesn't exist."""
        pair_address = "0x1234567890123456789012345678901234567890"
        
        # Mock empty code (contract doesn't exist)
        self.web3.eth.get_code.return_value = b''
        
        result = self.dex_discovery._pair_exists(pair_address)
        
        assert result is False
    
    def test_deduplicate_pairs(self):
        """Test pair deduplication."""
        pairs = [
            {'pair_address': '0x1234567890123456789012345678901234567890'},
            {'pair_address': '0x1234567890123456789012345678901234567890'},  # Duplicate
            {'pair_address': '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'},
            {'pair_address': ''},  # Empty address should be filtered out
            {'pair_address': '0x1111111111111111111111111111111111111111'}
        ]
        
        unique_pairs = self.dex_discovery._deduplicate_pairs(pairs)
        
        assert len(unique_pairs) == 3
        addresses = [p['pair_address'] for p in unique_pairs]
        assert '0x1234567890123456789012345678901234567890' in addresses
        assert '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd' in addresses
        assert '0x1111111111111111111111111111111111111111' in addresses
    
    def test_get_token_decimals_from_database(self):
        """Test getting token decimals from database."""
        token_address = "0xdac17f958d2ee523a2206206994597c13d831ec7"  # USDT
        
        # Mock token info from database
        with patch('shadowscan.collectors.evm.dex_discovery.get_token_info') as mock_get_token_info:
            mock_get_token_info.return_value = {'decimals': 6, 'symbol': 'USDT'}
            
            decimals = self.dex_discovery._get_token_decimals(token_address)
            
            assert decimals == 6
            mock_get_token_info.assert_called_once_with(token_address)
    
    def test_get_token_decimals_fallback(self):
        """Test getting token decimals fallback to contract call."""
        token_address = "0x1234567890123456789012345678901234567890"
        
        # Mock database lookup failure and successful contract call
        with patch('shadowscan.collectors.evm.dex_discovery.get_token_info') as mock_get_token_info:
            mock_get_token_info.return_value = None
            
            self.web3.eth.call.return_value = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12'  # 18
            
            decimals = self.dex_discovery._get_token_decimals(token_address)
            
            assert decimals == 18
            self.web3.eth.call.assert_called_once()
    
    def test_analyze_v2_liquidity_success(self):
        """Test V2 liquidity analysis with successful data."""
        pair_info = {
            'pair_address': '0x1234567890123456789012345678901234567890',
            'token0': self.test_token,
            'token1': self.test_weth,
            'dex_name': 'uniswap_v2',
            'router': '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D'
        }
        
        # Mock reserves call
        reserves_data = b'\x00' * 32 + b'\x00' * 31 + b'\x64' + b'\x00' * 32 + b'\x00' * 31 + b'\xc8'  # 100 and 200
        self.web3.eth.call.return_value = reserves_data
        
        # Mock token decimals
        with patch.object(self.dex_discovery, '_get_token_decimals') as mock_decimals:
            mock_decimals.return_value = 18
            
            # Mock USD calculation
            with patch.object(self.dex_discovery, '_calculate_usd_liquidity') as mock_usd:
                mock_usd.return_value = 1000.0
                
                dex_ref = self.dex_discovery._analyze_v2_liquidity(pair_info)
                
                assert dex_ref is not None
                assert isinstance(dex_ref, DexReference)
                assert dex_ref.dex_name == 'uniswap_v2'
                assert dex_ref.liquidity_usd == 1000.0
                assert len(dex_ref.reserves) == 2
    
    def test_analyze_v2_liquidity_empty_reserves(self):
        """Test V2 liquidity analysis with empty reserves."""
        pair_info = {
            'pair_address': '0x1234567890123456789012345678901234567890',
            'token0': self.test_token,
            'token1': self.test_weth,
            'dex_name': 'uniswap_v2'
        }
        
        # Mock empty reserves
        self.web3.eth.call.return_value = b'\x00' * 96
        
        dex_ref = self.dex_discovery._analyze_v2_liquidity(pair_info)
        
        assert dex_ref is None
    
    def test_calculate_usd_liquidity_stablecoin(self):
        """Test USD liquidity calculation with stablecoin."""
        token0 = self.test_token
        reserve0 = 1000000  # 1 USDT
        decimals0 = 6
        token1 = self.test_weth
        reserve1 = 1 * 10**18  # 1 WETH
        decimals1 = 18
        
        # Mock token info with stablecoin
        with patch('shadowscan.collectors.evm.dex_discovery.get_token_info') as mock_get_token_info:
            mock_get_token_info.side_effect = [
                {'type': 'stablecoin', 'symbol': 'USDT'},
                {'symbol': 'WETH'}
            ]
            
            usd_liquidity = self.dex_discovery._calculate_usd_liquidity(
                token0, reserve0, decimals0, token1, reserve1, decimals1
            )
            
            assert usd_liquidity == 2.0  # 2x the stablecoin amount
    
    def test_parse_factory_log_v2(self):
        """Test parsing V2 factory log."""
        from eth_utils import keccak
        
        # Create mock V2 log data
        token0_bytes = bytes.fromhex(self.test_token[2:].zfill(64))
        token1_bytes = bytes.fromhex(self.test_weth[2:].zfill(64))
        pair_bytes = bytes.fromhex('1234567890123456789012345678901234567890'[2:].zfill(64))
        uint_bytes = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
        
        log = AttributeDict({
            'topics': [
                '0x0d3648bd0f6ba8012a7ba936c6c88ff6a969d9d6abb4fb87974bc3c3b9f8bfa0',  # PairCreated topic
                keccak(token0_bytes),
                keccak(token1_bytes)
            ],
            'data': pair_bytes + uint_bytes,
            'address': '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f',
            'blockNumber': 15000
        })
        
        config = {
            'version': 'v2',
            'router': '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D'
        }
        
        pair_info = self.dex_discovery._parse_factory_log(log, self.test_token, 'uniswap_v2', config)
        
        assert pair_info is not None
        assert pair_info['pair_address'] == '0x1234567890123456789012345678901234567890'
        assert pair_info['dex_name'] == 'uniswap_v2'
        assert pair_info['version'] == 'v2'
    
    def test_parse_factory_log_v3(self):
        """Test parsing V3 factory log."""
        from eth_utils import keccak
        
        # Create mock V3 log data
        token0_bytes = bytes.fromhex(self.test_token[2:].zfill(64))
        token1_bytes = bytes.fromhex(self.test_weth[2:].zfill(64))
        fee_bytes = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000bb8')  # 3000 fee
        pool_bytes = bytes.fromhex('2222222222222222222222222222222222222222'[2:].zfill(64))
        
        log = AttributeDict({
            'topics': [
                '0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118',  # PoolCreated topic
                keccak(token0_bytes),
                keccak(token1_bytes),
                fee_bytes
            ],
            'data': pool_bytes,
            'address': '0x1F98431c8aD98523631AE4a59f267346ea31F984',
            'blockNumber': 15000
        })
        
        config = {
            'version': 'v3',
            'router': '0xE592427A0AEce92De3Edee1F18E0157C05861564'
        }
        
        pair_info = self.dex_discovery._parse_factory_log(log, self.test_token, 'uniswap_v3', config)
        
        assert pair_info is not None
        assert pair_info['pair_address'] == '0x2222222222222222222222222222222222222222'
        assert pair_info['dex_name'] == 'uniswap_v3'
        assert pair_info['version'] == 'v3'
        assert pair_info['fee_tier'] == '3000'
    
    def test_discover_dex_relations_integration(self):
        """Test complete DEX discovery integration."""
        # Mock all the dependencies
        with patch.object(self.dex_discovery, '_scan_factory_logs') as mock_factory_logs, \
             patch.object(self.dex_discovery, '_calculate_direct_pairs') as mock_direct_pairs, \
             patch.object(self.dex_discovery, '_discover_curve_pools') as mock_curve_pools, \
             patch.object(self.dex_discovery, '_analyze_pair_liquidity') as mock_analyze:
            
            # Setup mock returns
            mock_factory_logs.return_value = [
                {
                    'pair_address': '0x1111111111111111111111111111111111111111',
                    'token0': self.test_token,
                    'token1': self.test_weth,
                    'dex_name': 'uniswap_v2',
                    'factory': '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f',
                    'router': '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',
                    'version': 'v2'
                }
            ]
            
            mock_direct_pairs.return_value = []
            mock_curve_pools.return_value = []
            
            # Mock successful liquidity analysis
            mock_analyze.return_value = DexReference(
                pair='0x1111111111111111111111111111111111111111',
                router='0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',
                reserves=['1000000', '2000000'],
                liquidity_usd=5000.0,
                depth_score=0.8,
                dex_name='uniswap_v2'
            )
            
            dex_refs = self.dex_discovery.discover_dex_relations(self.test_token, self.provider)
            
            assert len(dex_refs) == 1
            assert dex_refs[0].dex_name == 'uniswap_v2'
            assert dex_refs[0].liquidity_usd == 5000.0


class TestDexDiscoveryEdgeCases:
    """Test edge cases and error conditions."""
    
    def setup_method(self):
        """Set up test environment."""
        self.web3 = Mock(spec=Web3)
        self.dex_discovery = DexDiscovery(self.web3)
    
    def test_compute_v2_pair_address_error_handling(self):
        """Test CREATE2 calculation error handling."""
        # Mock keccak to raise an exception
        with patch('shadowscan.collectors.evm.dex_discovery.keccak') as mock_keccak:
            mock_keccak.side_effect = Exception("Hash error")
            
            pair_address = self.dex_discovery._compute_v2_pair_address(
                '0x123', '0x456', '0x789', 'abc'
            )
            
            assert pair_address is None
    
    def test_analyze_pair_liquidity_unknown_version(self):
        """Test liquidity analysis with unknown version."""
        pair_info = {
            'pair_address': '0x1234567890123456789012345678901234567890',
            'dex_name': 'unknown_dex',
            'version': 'v1'
        }
        
        dex_ref = self.dex_discovery._analyze_pair_liquidity(pair_info)
        
        assert dex_ref is not None
        assert dex_ref.dex_name == 'unknown_dex'
        assert dex_ref.liquidity_usd == 1000.0  # Default estimate
    
    def test_scan_factory_logs_error_handling(self):
        """Test factory log scanning error handling."""
        # Mock web3 to raise exception
        self.web3.eth.block_number = 15000
        self.web3.eth.get_logs.side_effect = Exception("RPC error")
        
        pairs = self.dex_discovery._scan_factory_logs(self.test_token)
        
        assert pairs == []  # Should return empty list on error
    
    def test_get_token_decimals_default_fallback(self):
        """Test token decimals default fallback."""
        # Mock both database and contract call to fail
        with patch('shadowscan.collectors.evm.dex_discovery.get_token_info') as mock_get_token_info:
            mock_get_token_info.return_value = None
            self.web3.eth.call.side_effect = Exception("Contract call failed")
            
            decimals = self.dex_discovery._get_token_decimals(self.test_token)
            
            assert decimals == 18  # Default fallback
    
    def test_analyze_v3_liquidity_fallback_methods(self):
        """Test V3 liquidity analysis with fallback methods."""
        pair_info = {
            'pair_address': '0x1234567890123456789012345678901234567890',
            'dex_name': 'uniswap_v3',
            'router': '0xE592427A0AEce92De3Edee1F18E0157C05861564',
            'fee_tier': '3000',
            'version': 'v3'
        }
        
        # Mock primary method to fail, but totalSupply to succeed
        self.web3.eth.call.side_effect = [
            Exception("Liquidity call failed"),  # liquidity() call fails
            b'\x00' * 31 + b'\x10'  # totalSupply returns 16
        ]
        
        dex_ref = self.dex_discovery._analyze_v3_liquidity(pair_info)
        
        assert dex_ref is not None
        assert dex_ref.liquidity_usd > 0  # Should use fallback estimation