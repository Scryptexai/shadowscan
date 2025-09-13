# shadowscan/collectors/evm/tx_fetcher.py (Enhanced Robust Version)
'Enhanced transaction fetcher with chunking, concurrency, retries, and provider fallback.'

import asyncio
import aiohttp
import requests
from typing import List, Dict, Any, Optional, Tuple
from web3 import Web3
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
import time
from collections import defaultdict
from decimal import Decimal
import threading

from shadowscan.utils.schema import Transaction
from shadowscan.utils.helpers import extract_function_signature

logger = logging.getLogger(__name__)

class TxFetcher:
    'Enhanced transaction fetcher with chunking, concurrency, retries, and provider fallback.'
    
    def __init__(self, web3: Web3, etherscan_api_key: Optional[str] = None, 
                 max_workers: int = 8, chunk_size: int = 100, timeout: int = 300,
                 provider_fallback: Optional[List[str]] = None):
        """Initialize enhanced transaction fetcher.
        
        Args:
            web3: Primary Web3 instance
            etherscan_api_key: Etherscan API key for enhanced data
            max_workers: Maximum concurrent workers
            chunk_size: Block chunk size for scanning
            timeout: Default timeout for operations
            provider_fallback: List of fallback RPC URLs
        """
        self.web3 = web3
        self.etherscan_api_key = etherscan_api_key
        self.max_workers = max_workers
        self.chunk_size = chunk_size
        self.timeout = timeout
        
        # API endpoints
        self.api_endpoints = {
            'ethereum': 'https://api.etherscan.io/api',
            'polygon': 'https://api.polygonscan.com/api',
            'bsc': 'https://api.bscscan.com/api',
            'arbitrum': 'https://api.arbiscan.io/api'
        }
        
        # Provider fallback setup
        self.primary_provider = web3
        self.fallback_providers = []
        if provider_fallback:
            for fallback_url in provider_fallback:
                try:
                    fallback_web3 = Web3(Web3.HTTPProvider(fallback_url))
                    if fallback_web3.is_connected():
                        self.fallback_providers.append(fallback_web3)
                        logger.info(f"Added fallback provider: {fallback_url}")
                except Exception as e:
                    logger.warning(f"Failed to connect to fallback provider {fallback_url}: {e}")
        
        # Rate limiting
        self.last_api_call = 0
        self.api_delay = 0.2
        self.last_rpc_call = 0
        self.rpc_delay = 0.1
        
        # Threading and state
        self._lock = threading.RLock()
        self._cancelled = False
        self._stats = {
            'rpc_calls': 0,
            'api_calls': 0,
            'retries': 0,
            'fallbacks_used': 0,
            'timeouts': 0
        }
    
    def fetch_recent_txs_enhanced(self, address: str, limit: int = 200, 
                            chain: str = 'ethereum', include_traces: bool = True, 
                            depth: str = 'shallow') -> Dict[str, Any]:
        """
        Enhanced transaction fetching with chunking, retries, and partial results.
        
        Args:
            address: Contract address
            limit: Maximum transactions to fetch
            chain: Blockchain network
            include_traces: Whether to include transaction traces
            depth: Analysis depth ('shallow' or 'full')
            
        Returns:
            Dictionary with:
            - 'transactions': List of Transaction objects
            - 'partial': Boolean indicating if results are partial
            - 'stats': Dictionary with operation statistics
            - 'errors': List of encountered errors
        '
        start_time = time.time()
        logger.info(f"🔍 Enhanced TX fetch for {address[:10]}... (limit: {limit}, depth: {depth})")
        
        result = {
            'transactions': [],
            'partial': False,
            'stats': dict(self._stats),
            'errors': []
        }
        
        try:
            # Reset cancellation flag
            self._cancelled = False
            
            # Determine block range based on depth
            current_block = self._get_current_block_with_fallback()
            if depth == 'shallow':
                blocks_to_scan = min(500, current_block)
            else:
                blocks_to_scan = min(2000, current_block)
            
            logger.info(f"📊 Scanning {blocks_to_scan} blocks with chunk_size={self.chunk_size}")
            
            # Create block chunks
            block_chunks = self._create_block_chunks(current_block, blocks_to_scan, self.chunk_size)
            
            # Execute chunked scanning with retries
            chunk_results = self._execute_chunked_scan(address, block_chunks, limit)
            
            # Process results
            successful_chunks = [r for r in chunk_results if r['success']]
            failed_chunks = [r for r in chunk_results if not r['success']]
            
            # Collect transactions from successful chunks
            for chunk_result in successful_chunks:
                result['transactions'].extend(chunk_result['transactions'])
            
            # Sort by block number (newest first)
            result['transactions'].sort(key=lambda tx: tx.block, reverse=True)
            
            # Limit to requested amount
            if len(result['transactions']) > limit:
                result['transactions'] = result['transactions'][:limit]
            
            # Mark as partial if we had failures or cancellations
            if failed_chunks or self._cancelled:
                result['partial'] = True
                result['errors'].extend([f"Failed chunks: {len(failed_chunks)}"])
            
            # Add traces if requested and we have reasonable number of transactions
            if include_traces and len(result['transactions']) <= 50:
                result['transactions'] = self._add_traces_with_timeout(result['transactions'])
            
            # Update final stats
            result['stats'] = dict(self._stats)
            result['execution_time'] = time.time() - start_time
            
            logger.info(f"✅ Enhanced fetch complete: {len(result['transactions'])} txs "
                       f"(partial: {result['partial']}, time: {result['execution_time']:.1f}s)")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Enhanced transaction fetch failed: {e}")
            result['errors'].append(str(e))
            result['partial'] = True
            return result
    
    def cancel(self):
        'Cancel ongoing operations.'
        with self._lock:
            self._cancelled = True
        logger.info("🛑 Transaction fetcher cancelled")
    
    def get_stats(self) -> Dict[str, Any]:
        'Get operation statistics.'
        with self._lock:
            return dict(self._stats)
    
    def reset_stats(self):
        'Reset operation statistics.'
        with self._lock:
            self._stats = {
                'rpc_calls': 0,
                'api_calls': 0,
                'retries': 0,
                'fallbacks_used': 0,
                'timeouts': 0
            }
    
    def _get_current_block_with_fallback(self) -> int:
        'Get current block number with provider fallback.'
        providers = [self.primary_provider] + self.fallback_providers
        
        for provider in providers:
            try:
                block = provider.eth.block_number
                if block > 0:
                    return block
            except Exception as e:
                logger.debug(f"Failed to get block from provider: {e}")
                if provider != self.primary_provider:
                    with self._lock:
                        self._stats['fallbacks_used'] += 1
                continue
        
        raise RuntimeError("All providers failed to get current block")
    
    def _create_block_chunks(self, current_block: int, blocks_to_scan: int, chunk_size: int) -> List[Tuple[int, int]]:
        'Create block chunks for scanning.'
        chunks = []
        
        for i in range(0, blocks_to_scan, chunk_size):
            start_block = current_block - i - chunk_size + 1
            end_block = current_block - i
            
            if start_block <= 0:
                start_block = 1
            
            chunks.append((start_block, end_block))
            
            if start_block == 1:
                break
        
        return chunks
    
    def _execute_chunked_scan(self, address: str, chunks: List[Tuple[int, int]], limit: int) -> List[Dict[str, Any]]:
        'Execute chunked scanning with concurrency and retries.'
        results = []
        checksum_addr = Web3.to_checksum_address(address)
        
        # Limit concurrent chunks to avoid overwhelming
        max_concurrent = min(self.max_workers, len(chunks), 4)
        
        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            # Submit chunk tasks with retry wrapper
            future_to_chunk = {}
            for chunk_idx, (start_block, end_block) in enumerate(chunks):
                if self._cancelled:
                    break
                
                future = executor.submit(
                    self._scan_chunk_with_retry,
                    checksum_addr, start_block, end_block, limit
                )
                future_to_chunk[future] = (start_block, end_block, chunk_idx)
            
            # Collect results with timeout
            for future in as_completed(future_to_chunk, timeout=self.timeout):
                if self._cancelled:
                    # Cancel remaining futures
                    for f in future_to_chunk:
                        if not f.done():
                            f.cancel()
                    break
                
                start_block, end_block, chunk_idx = future_to_chunk[future]
                try:
                    chunk_result = future.result()
                    results.append(chunk_result)
                    
                    logger.debug(f"📦 Chunk {start_block}-{end_block}: "
                               f"{len(chunk_result['transactions'])} txs "
                               f"(success: {chunk_result['success']})")
                    
                    # Early exit if we have enough transactions
                    total_txs = sum(len(r['transactions']) for r in results if r['success'])
                    if total_txs >= limit:
                        logger.info(f"✅ Early exit: Found {total_txs} transactions")
                        break
                        
                except Exception as e:
                    logger.warning(f"⚠️  Chunk {start_block}-{end_block} failed: {e}")
                    results.append({
                        'start_block': start_block,
                        'end_block': end_block,
                        'success': False,
                        'error': str(e),
                        'transactions': []
                    })
        
        return results
    
    def _scan_chunk_with_retry(self, address: str, start_block: int, end_block: int, 
                              limit: int, max_retries: int = 3) -> Dict[str, Any]:
        'Scan a block chunk with retry logic.'
        last_error = None
        
        for attempt in range(max_retries + 1):
            if self._cancelled:
                return {
                    'start_block': start_block,
                    'end_block': end_block,
                    'success': False,
                    'error': 'Operation cancelled',
                    'transactions': []
                }
            
            try:
                result = self._scan_block_chunk_enhanced(address, start_block, end_block, limit)
                if result['success']:
                    return result
                
                last_error = result.get('error', 'Unknown error')
                
                # Exponential backoff
                if attempt < max_retries:
                    backoff_time = (2 ** attempt) * 0.5
                    logger.debug(f"⏳ Retry {attempt + 1}/{max_retries} in {backoff_time}s...")
                    time.sleep(backoff_time)
                    with self._lock:
                        self._stats['retries'] += 1
                
            except Exception as e:
                last_error = str(e)
                logger.debug(f"⚠️  Attempt {attempt + 1} failed: {e}")
                
                if attempt < max_retries:
                    time.sleep((2 ** attempt) * 0.5)
                    with self._lock:
                        self._stats['retries'] += 1
        
        # All retries failed
        return {
            'start_block': start_block,
            'end_block': end_block,
            'success': False,
            'error': last_error,
            'transactions': []
        }
    
    def _scan_block_chunk_enhanced(self, address: str, start_block: int, 
                                  end_block: int, limit: int) -> Dict[str, Any]:
        'Enhanced block chunk scanning with provider fallback.'
        chunk_transactions = []
        providers = [self.primary_provider] + self.fallback_providers
        
        for provider_idx, provider in enumerate(providers):
            try:
                if self._cancelled:
                    break
                
                for block_num in range(end_block, start_block - 1, -1):
                    if self._cancelled:
                        break
                    
                    try:
                        # Rate limiting
                        self._rate_limit_rpc()
                        
                        # Get block with transactions
                        block = provider.eth.get_block(block_num, full_transactions=True)
                        
                        with self._lock:
                            self._stats['rpc_calls'] += 1
                        
                        # Scan transactions in block
                        for tx in block.transactions:
                            if self._is_target_transaction(tx, address):
                                transaction = self._create_transaction_object(tx, block)
                                chunk_transactions.append(transaction)
                                
                                # Early exit if limit reached
                                if len(chunk_transactions) >= limit:
                                    break
                        
                        if len(chunk_transactions) >= limit:
                            break
                        
                    except Exception as e:
                        logger.debug(f"⚠️  Error scanning block {block_num}: {e}")
                        continue
                
                # If we got transactions from this provider, return success
                if chunk_transactions:
                    if provider_idx > 0:  # Used fallback
                        with self._lock:
                            self._stats['fallbacks_used'] += 1
                    
                    return {
                        'start_block': start_block,
                        'end_block': end_block,
                        'success': True,
                        'transactions': chunk_transactions
                    }
                
            except Exception as e:
                logger.debug(f"⚠️  Provider {provider_idx} failed for chunk {start_block}-{end_block}: {e}")
                continue
        
        # All providers failed
        return {
            'start_block': start_block,
            'end_block': end_block,
            'success': False,
            'error': 'All providers failed',
            'transactions': []
        }
    
    def _is_target_transaction(self, tx, address: str) -> bool:
        'Check if transaction involves target address.'
        target_lower = address.lower()
        
        # Check 'to' address
        if tx.to and tx.to.lower() == target_lower:
            return True
        
        # Check contract creation
        if hasattr(tx, 'creates') and tx.creates and tx.creates.lower() == target_lower:
            return True
        
        # Check 'from' address (for outgoing transactions)
        if hasattr(tx, 'from') and tx['from'] and tx['from'].lower() == target_lower:
            return True
        
        return False
    
    def _create_transaction_object(self, tx, block) -> Transaction:
        'Create Transaction object from web3 transaction.'
        return Transaction(
            hash=tx.hash.hex(),
            from_addr=tx['from'],
            to=tx.to,
            input=tx.input.hex(),
            value=str(tx.value),
            block=tx.blockNumber,
            timestamp=int(block.timestamp),
            gas_used=None  # Will be filled in trace phase if needed
        )
    
    def _add_traces_with_timeout(self, transactions: List[Transaction], 
                                timeout: int = 30) -> List[Transaction]:
        'Add transaction traces with timeout.'
        if not transactions:
            return transactions
        
        logger.info(f"🔍 Adding traces to {len(transactions)} transactions (timeout: {timeout}s)...")
        
        # Limit traces to avoid excessive calls
        trace_limit = min(20, len(transactions))
        transactions_to_trace = transactions[:trace_limit]
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_tx = {
                executor.submit(self._get_transaction_trace_with_timeout, tx.hash, 10): i
                for i, tx in enumerate(transactions_to_trace)
            }
            
            for future in as_completed(future_to_tx, timeout=timeout):
                tx_index = future_to_tx[future]
                try:
                    trace_data = future.result()
                    if trace_data:
                        transactions_to_trace[tx_index].trace = trace_data
                except Exception as e:
                    logger.debug(f"⚠️  Trace failed: {e}")
                    with self._lock:
                        self._stats['timeouts'] += 1
        
        return transactions
    
    def _get_transaction_trace_with_timeout(self, tx_hash: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
        'Get transaction trace with timeout and fallback.'
        start_time = time.time()
        providers = [self.primary_provider] + self.fallback_providers
        
        for provider in providers:
            try:
                if time.time() - start_time > timeout:
                    break
                
                # Try to get receipt first (faster)
                receipt = provider.eth.get_transaction_receipt(tx_hash)
                
                if receipt:
                    return {
                        'type': 'receipt_analysis',
                        'gas_used': receipt.get('gasUsed'),
                        'status': receipt.get('status', 1),
                        'logs_count': len(receipt.get('logs', [])),
                        'failed': receipt.get('status') == 0,
                        'contract_address': receipt.get('contractAddress'),
                        'logs': [log.hex() for log in receipt.get('logs', [])]
                    }
                
            except Exception as e:
                logger.debug(f"⚠️  Trace failed for {tx_hash[:10]}...: {e}")
                continue
        
        return None
    
    # Legacy method for backward compatibility
    def fetch_recent_txs(self, address: str, provider, limit: int = 200, 
                        chain: str = 'ethereum', include_traces: bool = True, 
                        depth: str = 'shallow') -> List[Transaction]:
        '
        Legacy method - delegates to enhanced version.
        '
        
        Args:
            address: Contract address
            provider: Web3 provider
            limit: Maximum transactions
            chain: Blockchain network
            include_traces: Whether to fetch traces
            depth: Analysis depth (shallow = faster)
            
        Returns:
            List of Transaction objects
        """
        start_time = time.time()
        logger.info(f"🔍 Fetching transactions for {address[:10]}... (depth: {depth})")
        
        transactions = []
        
        try:
            # Strategy 1: API first (fastest)
            if self.etherscan_api_key:
                logger.info("📡 Trying Etherscan API...")
                transactions = self._fetch_from_api_optimized(address, chain, limit)
                
                if transactions:
                    logger.info(f"✅ API: Found {len(transactions)} transactions in {time.time()-start_time:.1f}s")
                    
                    # Add traces only for high-priority transactions if requested
                    if include_traces and depth == 'full':
                        transactions = self._add_traces_selective(transactions[:20])  # Only top 20
                    
                    return transactions[:limit]
            
            # Strategy 2: Smart RPC scanning (fallback)
            logger.info("🔧 Falling back to smart RPC scanning...")
            transactions = self._fetch_from_rpc_optimized(address, limit, depth)
            
            if transactions:
                logger.info(f"✅ RPC: Found {len(transactions)} transactions in {time.time()-start_time:.1f}s")
                
                # Selective trace addition
                if include_traces and depth == 'full' and len(transactions) <= 50:
                    transactions = self._add_traces_selective(transactions)
            
            return transactions[:limit]
            
        except Exception as e:
            logger.error(f"❌ Error fetching transactions: {e}")
            return []
    
    def _fetch_from_api_optimized(self, address: str, chain: str, limit: int) -> List[Transaction]:
        'Optimized API fetching with better error handling.'
        endpoint = self.api_endpoints.get(chain)
        if not endpoint:
            return []
        
        try:
            self._rate_limit_api()
            
            # Optimized parameters
            params = {
                'module': 'account',
                'action': 'txlist',
                'address': address,
                'startblock': 0,
                'endblock': 99999999,
                'page': 1,
                'offset': min(limit, 1000),  # Reduced from 10000
                'sort': 'desc',
                'apikey': self.etherscan_api_key
            }
            
            response = requests.get(endpoint, params=params, timeout=15)  # Reduced timeout
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == '1' and data.get('result'):
                transactions = []
                for tx_data in data['result']:
                    tx = Transaction(
                        hash=tx_data['hash'],
                        from_addr=tx_data['from'],
                        to=tx_data.get('to'),
                        input=tx_data.get('input', '0x'),
                        value=tx_data.get('value', '0'),
                        block=int(tx_data.get('blockNumber', 0)),
                        timestamp=int(tx_data.get('timeStamp', 0)),
                        gas_used=int(tx_data.get('gasUsed', 0)) if tx_data.get('gasUsed') else None
                    )
                    transactions.append(tx)
                
                return transactions
            
            logger.warning(f"⚠️  API returned no results for {address}")
            return []
            
        except Exception as e:
            logger.warning(f"⚠️  API fetch failed: {e}")
            return []
    
    def _fetch_from_rpc_optimized(self, address: str, limit: int, depth: str) -> List[Transaction]:
        'Optimized RPC scanning with smart block selection.'
        transactions = []
        
        try:
            current_block = self.web3.eth.block_number
            checksum_addr = Web3.to_checksum_address(address)
            
            # Smart block range based on depth
            if depth == 'shallow':
                blocks_to_scan = min(500, current_block)  # Much smaller range
                chunk_size = 50
            else:
                blocks_to_scan = min(2000, current_block)
                chunk_size = 100
            
            logger.info(f"🔍 Scanning {blocks_to_scan} blocks in chunks of {chunk_size}")
            
            # Use chunked parallel scanning
            block_chunks = []
            for i in range(0, blocks_to_scan, chunk_size):
                start_block = current_block - i - chunk_size + 1
                end_block = current_block - i
                if start_block <= 0:
                    break
                block_chunks.append((max(1, start_block), end_block))
            
            # Process chunks in parallel
            with ThreadPoolExecutor(max_workers=min(4, len(block_chunks))) as executor:
                future_to_chunk = {
                    executor.submit(self._scan_block_chunk, checksum_addr, start, end): (start, end)
                    for start, end in block_chunks[:8]  # Limit to 8 chunks max
                }
                
                for future in as_completed(future_to_chunk, timeout=30):  # 30s timeout
                    chunk_start, chunk_end = future_to_chunk[future]
                    try:
                        chunk_txs = future.result()
                        transactions.extend(chunk_txs)
                        
                        logger.debug(f"📦 Chunk {chunk_start}-{chunk_end}: {len(chunk_txs)} txs")
                        
                        # Early exit if we have enough
                        if len(transactions) >= limit:
                            logger.info(f"✅ Early exit: Found {len(transactions)} transactions")
                            break
                            
                    except Exception as e:
                        logger.debug(f"⚠️  Chunk {chunk_start}-{chunk_end} failed: {e}")
                        continue
            
            # Sort by block number descending
            transactions.sort(key=lambda tx: tx.block, reverse=True)
            
            logger.info(f"📊 RPC scan complete: {len(transactions)} transactions found")
            return transactions
            
        except Exception as e:
            logger.error(f"❌ RPC scanning failed: {e}")
            return []
    
    def _scan_block_chunk(self, address: str, start_block: int, end_block: int) -> List[Transaction]:
        'Scan a chunk of blocks for transactions.'
        chunk_transactions = []
        
        try:
            for block_num in range(end_block, start_block - 1, -1):
                self._rate_limit_rpc()
                
                try:
                    # Get block with transactions
                    block = self.web3.eth.get_block(block_num, full_transactions=True)
                    
                    for tx in block.transactions:
                        # Check if transaction involves our target address
                        if (tx.to and tx.to.lower() == address.lower()) or \
                           (hasattr(tx, 'creates') and tx.creates and tx.creates.lower() == address.lower()):
                            
                            transaction = Transaction(
                                hash=tx.hash.hex(),
                                from_addr=tx['from'],
                                to=tx.to,
                                input=tx.input.hex(),
                                value=str(tx.value),
                                block=tx.blockNumber,
                                timestamp=int(block.timestamp),
                                gas_used=None
                            )
                            
                            chunk_transactions.append(transaction)
                            
                            # Early exit from chunk if found enough
                            if len(chunk_transactions) >= 20:
                                return chunk_transactions
                    
                except Exception as e:
                    logger.debug(f"⚠️  Error scanning block {block_num}: {e}")
                    continue
            
            return chunk_transactions
            
        except Exception as e:
            logger.debug(f"❌ Chunk scan error: {e}")
            return []
    
    def _add_traces_selective(self, transactions: List[Transaction]) -> List[Transaction]:
        'Add traces only to high-priority transactions.'
        if not transactions:
            return transactions
        
        logger.info(f"🔍 Adding traces to top {min(10, len(transactions))} transactions...")
        
        # Only trace the most recent and high-value transactions
        priority_txs = []
        
        # Sort by recency and value
        sorted_txs = sorted(transactions, key=lambda tx: (tx.block, int(tx.value)), reverse=True)
        priority_txs = sorted_txs[:10]  # Only top 10
        
        # Add traces in parallel with timeout
        with ThreadPoolExecutor(max_workers=3) as executor:  # Limited workers
            future_to_tx = {
                executor.submit(self._get_transaction_trace_fast, tx.hash): i
                for i, tx in enumerate(priority_txs)
            }
            
            for future in as_completed(future_to_tx, timeout=15):  # 15s timeout
                tx_index = future_to_tx[future]
                try:
                    trace_data = future.result()
                    if trace_data:
                        priority_txs[tx_index].trace = trace_data
                except Exception as e:
                    logger.debug(f"⚠️  Trace failed: {e}")
        
        # Update original transactions with traces
        for i, tx in enumerate(transactions):
            for priority_tx in priority_txs:
                if tx.hash == priority_tx.hash:
                    tx.trace = priority_tx.trace
                    break
        
        return transactions
    
    def _get_transaction_trace_fast(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        # Fast transaction trace with fallback
        try:
            # Try to get receipt first (faster than debug trace)
            receipt = self.web3.eth.get_transaction_receipt(tx_hash)
            
            if receipt:
                return {
                    'type': 'receipt_analysis',
                    'gas_used': receipt.get('gasUsed'),
                    'status': receipt.get('status', 1),
                    'logs_count': len(receipt.get('logs', [])),
                    'failed': receipt.get('status') == 0
                }
                
        except Exception as e:
            logger.debug(f"⚠️  Fast trace failed for {tx_hash}: {e}")
        
        return None
    
    def _rate_limit_api(self):
        # Rate limiting for API calls
        current_time = time.time()
        time_since_last_call = current_time - self.last_api_call
        
        if time_since_last_call < self.api_delay:
            time.sleep(self.api_delay - time_since_last_call)
        
        self.last_api_call = time.time()
    
    def _rate_limit_rpc(self):
        # Rate limiting for RPC calls
        current_time = time.time()
        time_since_last_call = current_time - self.last_rpc_call
        
        if time_since_last_call < self.rpc_delay:
            time.sleep(self.rpc_delay - time_since_last_call)
        
        self.last_rpc_call = time.time()
    
