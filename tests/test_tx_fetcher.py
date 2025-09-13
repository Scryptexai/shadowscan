"""
Unit tests for enhanced TxFetcher functionality.
Tests chunking, concurrency, retries, and provider fallback.
"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from web3 import Web3
from concurrent.futures import ThreadPoolExecutor

from shadowscan.collectors.evm.tx_fetcher import TxFetcher
from shadowscan.utils.schema import Transaction


class TestTxFetcher:
    """Test suite for enhanced TxFetcher functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        # Mock Web3 instance
        self.mock_web3 = Mock(spec=Web3)
        self.mock_web3.is_connected.return_value = True
        self.mock_web3.eth.block_number = 15000
        
        # Create tx_fetcher instance
        self.tx_fetcher = TxFetcher(
            web3=self.mock_web3,
            max_workers=4,
            chunk_size=50,
            timeout=60
        )
    
    def test_initialization(self):
        """Test TxFetcher initialization."""
        assert self.tx_fetcher.web3 == self.mock_web3
        assert self.tx_fetcher.max_workers == 4
        assert self.tx_fetcher.chunk_size == 50
        assert self.tx_fetcher.timeout == 60
        assert self.tx_fetcher._cancelled is False
        assert self.tx_fetcher._stats['rpc_calls'] == 0
    
    def test_initialization_with_fallback_providers(self):
        """Test TxFetcher initialization with fallback providers."""
        fallback_urls = [
            "https://fallback1.example.com",
            "https://fallback2.example.com"
        ]
        
        with patch('shadowscan.collectors.evm.tx_fetcher.Web3') as mock_web3_class:
            # Mock successful connection for fallback providers
            mock_fallback_web3 = Mock(spec=Web3)
            mock_fallback_web3.is_connected.return_value = True
            mock_web3_class.return_value = mock_fallback_web3
            
            tx_fetcher = TxFetcher(
                web3=self.mock_web3,
                provider_fallback=fallback_urls
            )
            
            assert len(tx_fetcher.fallback_providers) == 2
    
    def test_get_current_block_with_fallback_success(self):
        """Test getting current block with successful primary provider."""
        self.mock_web3.eth.block_number = 15000
        
        result = self.tx_fetcher._get_current_block_with_fallback()
        
        assert result == 15000
        assert self.tx_fetcher._stats['rpc_calls'] == 1
    
    def test_get_current_block_with_fallback_failover(self):
        """Test getting current block with fallback to secondary provider."""
        # Make primary provider fail
        self.mock_web3.eth.block_number = 0
        
        # Add fallback provider
        fallback_web3 = Mock(spec=Web3)
        fallback_web3.eth.block_number = 15000
        self.tx_fetcher.fallback_providers = [fallback_web3]
        
        result = self.tx_fetcher._get_current_block_with_fallback()
        
        assert result == 15000
        assert self.tx_fetcher._stats['fallbacks_used'] == 1
    
    def test_get_current_block_all_providers_fail(self):
        """Test failure when all providers fail to get current block."""
        # Make all providers fail
        self.mock_web3.eth.block_number = 0
        self.tx_fetcher.fallback_providers = []
        
        with pytest.raises(RuntimeError, match="All providers failed to get current block"):
            self.tx_fetcher._get_current_block_with_fallback()
    
    def test_create_block_chunks(self):
        """Test block chunk creation."""
        current_block = 1000
        blocks_to_scan = 500
        chunk_size = 100
        
        chunks = self.tx_fetcher._create_block_chunks(current_block, blocks_to_scan, chunk_size)
        
        assert len(chunks) == 5  # 500 blocks / 100 chunk size
        
        # Verify first chunk
        first_chunk = chunks[0]
        assert first_chunk[0] == 501  # start_block
        assert first_chunk[1] == 600  # end_block
        
        # Verify last chunk
        last_chunk = chunks[-1]
        assert last_chunk[0] == 1    # start_block
        assert last_chunk[1] == 100  # end_block
    
    def test_create_block_chunks_edge_case(self):
        """Test block chunk creation with edge case (smaller than chunk size)."""
        current_block = 100
        blocks_to_scan = 50
        chunk_size = 100
        
        chunks = self.tx_fetcher._create_block_chunks(current_block, blocks_to_scan, chunk_size)
        
        assert len(chunks) == 1
        assert chunks[0][0] == 51   # start_block
        assert chunks[0][1] == 100  # end_block
    
    def test_is_target_transaction_to_address(self):
        """Test target transaction detection for 'to' address."""
        mock_tx = Mock()
        mock_tx.to = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        mock_tx.creates = None
        
        result = self.tx_fetcher._is_target_transaction(
            mock_tx, "0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"
        )
        
        assert result is True
    
    def test_is_target_transaction_creates_address(self):
        """Test target transaction detection for contract creation."""
        mock_tx = Mock()
        mock_tx.to = None
        mock_tx.creates = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        
        result = self.tx_fetcher._is_target_transaction(
            mock_tx, "0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"
        )
        
        assert result is True
    
    def test_is_target_transaction_from_address(self):
        """Test target transaction detection for 'from' address."""
        mock_tx = Mock()
        mock_tx.to = "0xother"
        mock_tx.creates = None
        mock_tx.__getitem__ = lambda self, key: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd" if key == 'from' else None
        
        result = self.tx_fetcher._is_target_transaction(
            mock_tx, "0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"
        )
        
        assert result is True
    
    def test_create_transaction_object(self):
        """Test transaction object creation."""
        mock_tx = Mock()
        mock_tx.hash.hex.return_value = "0x1234567890123456789012345678901234567890123456789012345678901234"
        mock_tx.__getitem__ = lambda self, key: "0xfromaddress" if key == 'from' else Mock()
        mock_tx.to = "0xtoaddress"
        mock_tx.input.hex.return_value = "0xabcd"
        mock_tx.value = 1000
        mock_tx.blockNumber = 12345
        
        mock_block = Mock()
        mock_block.timestamp = 1640995200
        
        result = self.tx_fetcher._create_transaction_object(mock_tx, mock_block)
        
        assert isinstance(result, Transaction)
        assert result.hash == "0x1234567890123456789012345678901234567890123456789012345678901234"
        assert result.from_addr == "0xfromaddress"
        assert result.to == "0xtoaddress"
        assert result.input == "0xabcd"
        assert result.value == "1000"
        assert result.block == 12345
        assert result.timestamp == 1640995200
    
    def test_cancel(self):
        """Test operation cancellation."""
        self.tx_fetcher.cancel()
        
        assert self.tx_fetcher._cancelled is True
    
    def test_get_stats(self):
        """Test getting operation statistics."""
        # Modify some stats
        self.tx_fetcher._stats['rpc_calls'] = 10
        self.tx_fetcher._stats['retries'] = 2
        
        stats = self.tx_fetcher.get_stats()
        
        assert stats['rpc_calls'] == 10
        assert stats['retries'] == 2
        # Should be a copy, not the original
        assert stats is not self.tx_fetcher._stats
    
    def test_reset_stats(self):
        """Test resetting operation statistics."""
        # Modify some stats
        self.tx_fetcher._stats['rpc_calls'] = 10
        self.tx_fetcher._stats['retries'] = 2
        
        self.tx_fetcher.reset_stats()
        
        assert self.tx_fetcher._stats['rpc_calls'] == 0
        assert self.tx_fetcher._stats['retries'] == 0
    
    @patch('shadowscan.collectors.evm.tx_fetcher.time.sleep')
    def test_rate_limiting(self, mock_sleep):
        """Test rate limiting for RPC calls."""
        # Set last call time in the past
        self.tx_fetcher.last_rpc_call = time.time() - 1.0
        
        # First call should not sleep
        self.tx_fetcher._rate_limit_rpc()
        mock_sleep.assert_not_called()
        
        # Second immediate call should sleep
        self.tx_fetcher._rate_limit_rpc()
        mock_sleep.assert_called_once()
    
    def test_scan_chunk_with_retry_success(self):
        """Test chunk scanning with successful retry."""
        address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        
        # Mock successful scan
        with patch.object(self.tx_fetcher, '_scan_block_chunk_enhanced') as mock_scan:
            mock_scan.return_value = {
                'success': True,
                'transactions': [Mock(spec=Transaction)]
            }
            
            result = self.tx_fetcher._scan_chunk_with_retry(
                address, 100, 200, 10, max_retries=2
            )
            
            assert result['success'] is True
            assert len(result['transactions']) == 1
            mock_scan.assert_called_once()
    
    @patch('shadowscan.collectors.evm.tx_fetcher.time.sleep')
    def test_scan_chunk_with_retry_failure_then_success(self, mock_sleep):
        """Test chunk scanning with failure then success."""
        address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        
        # Mock scan that fails first, then succeeds
        with patch.object(self.tx_fetcher, '_scan_block_chunk_enhanced') as mock_scan:
            mock_scan.side_effect = [
                {'success': False, 'error': 'First failure'},
                {'success': True, 'transactions': [Mock(spec=Transaction)]}
            ]
            
            result = self.tx_fetcher._scan_chunk_with_retry(
                address, 100, 200, 10, max_retries=2
            )
            
            assert result['success'] is True
            assert mock_scan.call_count == 2
            mock_sleep.assert_called_once()  # Should sleep between retries
    
    @patch('shadowscan.collectors.evm.tx_fetcher.time.sleep')
    def test_scan_chunk_with_retry_all_failures(self, mock_sleep):
        """Test chunk scanning with all retries failing."""
        address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        
        # Mock scan that always fails
        with patch.object(self.tx_fetcher, '_scan_block_chunk_enhanced') as mock_scan:
            mock_scan.return_value = {'success': False, 'error': 'Persistent failure'}
            
            result = self.tx_fetcher._scan_chunk_with_retry(
                address, 100, 200, 10, max_retries=2
            )
            
            assert result['success'] is False
            assert result['error'] == 'Persistent failure'
            assert mock_scan.call_count == 3  # Initial + 2 retries
            assert mock_sleep.call_count == 2  # Sleep between each retry
    
    def test_scan_chunk_with_retry_cancelled(self):
        """Test chunk scanning with cancellation."""
        address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        
        # Cancel before scanning
        self.tx_fetcher._cancelled = True
        
        result = self.tx_fetcher._scan_chunk_with_retry(
            address, 100, 200, 10, max_retries=2
        )
        
        assert result['success'] is False
        assert result['error'] == 'Operation cancelled'
    
    def test_get_transaction_trace_with_timeout_success(self):
        """Test successful transaction trace retrieval."""
        tx_hash = "0x1234567890123456789012345678901234567890123456789012345678901234"
        
        # Mock successful receipt
        mock_receipt = Mock()
        mock_receipt.get.side_effect = lambda key: {
            'gasUsed': 50000,
            'status': 1,
            'logs': [Mock(), Mock()],
            'contractAddress': None
        }.get(key)
        
        self.mock_web3.eth.get_transaction_receipt.return_value = mock_receipt
        
        result = self.tx_fetcher._get_transaction_trace_with_timeout(tx_hash, timeout=10)
        
        assert result is not None
        assert result['type'] == 'receipt_analysis'
        assert result['gas_used'] == 50000
        assert result['status'] == 1
        assert result['logs_count'] == 2
        assert result['failed'] is False
    
    def test_get_transaction_trace_with_timeout_failure(self):
        """Test failed transaction trace retrieval."""
        tx_hash = "0x1234567890123456789012345678901234567890123456789012345678901234"
        
        # Mock failed receipt
        self.mock_web3.eth.get_transaction_receipt.side_effect = Exception("RPC error")
        
        result = self.tx_fetcher._get_transaction_trace_with_timeout(tx_hash, timeout=10)
        
        assert result is None
    
    def test_get_transaction_trace_with_timeout_fallback(self):
        """Test transaction trace retrieval with fallback provider."""
        tx_hash = "0x1234567890123456789012345678901234567890123456789012345678901234"
        
        # Mock primary provider failure
        self.mock_web3.eth.get_transaction_receipt.side_effect = Exception("Primary failed")
        
        # Mock fallback provider success
        fallback_web3 = Mock(spec=Web3)
        mock_receipt = Mock()
        mock_receipt.get.side_effect = lambda key: {'gasUsed': 30000, 'status': 1, 'logs': []}.get(key)
        fallback_web3.eth.get_transaction_receipt.return_value = mock_receipt
        
        self.tx_fetcher.fallback_providers = [fallback_web3]
        
        result = self.tx_fetcher._get_transaction_trace_with_timeout(tx_hash, timeout=10)
        
        assert result is not None
        assert result['gas_used'] == 30000
        assert self.tx_fetcher._stats['fallbacks_used'] == 1


class TestTxFetcherIntegration:
    """Integration tests for TxFetcher with mocked blockchain data."""
    
    def setup_method(self):
        """Set up test environment with mocked blockchain."""
        self.mock_web3 = Mock(spec=Web3)
        self.mock_web3.is_connected.return_value = True
        self.mock_web3.eth.block_number = 15000
        
        self.tx_fetcher = TxFetcher(
            web3=self.mock_web3,
            max_workers=2,
            chunk_size=10,
            timeout=30
        )
    
    def create_mock_block(self, block_number, transactions=None):
        """Create a mock block with transactions."""
        if transactions is None:
            transactions = []
        
        mock_block = Mock()
        mock_block.number = block_number
        mock_block.timestamp = 1640995200 + block_number
        
        # Create mock transactions
        mock_txs = []
        for i, tx_data in enumerate(transactions):
            mock_tx = Mock()
            mock_tx.hash = Mock()
            mock_tx.hash.hex.return_value = f"0x{block_number:08d}{i:08d}"
            mock_tx.__getitem__ = lambda self, key: tx_data.get(key, Mock())
            mock_tx.to = tx_data.get('to')
            mock_tx.creates = tx_data.get('creates')
            mock_tx.input = Mock()
            mock_tx.input.hex.return_value = tx_data.get('input', '0x')
            mock_tx.value = tx_data.get('value', 0)
            mock_tx.blockNumber = block_number
            mock_txs.append(mock_tx)
        
        mock_block.transactions = mock_txs
        return mock_block
    
    def test_fetch_recent_txs_enhanced_success(self):
        """Test successful enhanced transaction fetching."""
        address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        
        # Mock blocks with target transactions
        mock_blocks = {}
        for block_num in range(14990, 15001):  # 10 most recent blocks
            transactions = []
            if block_num % 2 == 0:  # Every other block has a transaction
                transactions.append({
                    'to': address,
                    'input': '0xabcd1234',
                    'value': 1000
                })
            
            mock_blocks[block_num] = self.create_mock_block(block_num, transactions)
        
        def mock_get_block(block_num, full_transactions=False):
            return mock_blocks.get(block_num)
        
        self.mock_web3.eth.get_block.side_effect = mock_get_block
        
        result = self.tx_fetcher.fetch_recent_txs_enhanced(
            address, limit=10, depth='shallow'
        )
        
        assert result['success'] is not False  # Should not have fatal error
        assert 'transactions' in result
        assert 'partial' in result
        assert 'stats' in result
        assert 'errors' in result
        
        # Should find transactions in every other block (5 blocks)
        assert len(result['transactions']) == 5
        
        # Verify transactions are sorted by block (newest first)
        for i in range(len(result['transactions']) - 1):
            assert result['transactions'][i].block >= result['transactions'][i + 1].block
    
    def test_fetch_recent_txs_enhanced_partial_results(self):
        """Test enhanced transaction fetching with partial results."""
        address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        
        # Mock some blocks to fail
        def mock_get_block_with_failures(block_num, full_transactions=False):
            if block_num == 14995:  # This block fails
                raise Exception("Block not found")
            return self.create_mock_block(block_num, [{
                'to': address,
                'input': '0xabcd1234',
                'value': 1000
            }])
        
        self.mock_web3.eth.get_block.side_effect = mock_get_block_with_failures
        
        result = self.tx_fetcher.fetch_recent_txs_enhanced(
            address, limit=20, depth='shallow'
        )
        
        assert result['partial'] is True
        assert len(result['errors']) > 0
        # Should still get some transactions from successful blocks
        assert len(result['transactions']) > 0
    
    def test_fetch_recent_txs_enhanced_cancellation(self):
        """Test enhanced transaction fetching with cancellation."""
        address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        
        # Mock blocks that take time (simulate slow provider)
        def slow_get_block(block_num, full_transactions=False):
            time.sleep(0.1)  # Simulate slow operation
            return self.create_mock_block(block_num, [{
                'to': address,
                'input': '0xabcd1234',
                'value': 1000
            }])
        
        self.mock_web3.eth.get_block.side_effect = slow_get_block
        
        # Start fetching in background
        import threading
        def cancel_after_delay():
            time.sleep(0.05)
            self.tx_fetcher.cancel()
        
        cancel_thread = threading.Thread(target=cancel_after_delay)
        cancel_thread.start()
        
        result = self.tx_fetcher.fetch_recent_txs_enhanced(
            address, limit=20, depth='shallow'
        )
        
        cancel_thread.join()
        
        assert result['partial'] is True
        # Should have some transactions from before cancellation
        assert len(result['transactions']) >= 0
    
    def test_fetch_recent_txs_enhanced_timeout(self):
        """Test enhanced transaction fetching with timeout."""
        address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        
        # Mock very slow blocks
        def very_slow_get_block(block_num, full_transactions=False):
            time.sleep(1.0)  # Very slow
            return self.create_mock_block(block_num, [{
                'to': address,
                'input': '0xabcd1234',
                'value': 1000
            }])
        
        self.mock_web3.eth.get_block.side_effect = very_slow_get_block
        
        # Set very short timeout for testing
        self.tx_fetcher.timeout = 0.1
        
        result = self.tx_fetcher.fetch_recent_txs_enhanced(
            address, limit=20, depth='shallow'
        )
        
        assert result['partial'] is True
        assert self.tx_fetcher._stats['timeouts'] > 0