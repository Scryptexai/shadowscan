# shadowscan/core/pipeline/screening_engine.py
"""Main screening engine orchestrating the complete analysis pipeline."""

import time
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import json

from web3 import Web3

from shadowscan.collectors.evm import (
    ABIFetcher, ProxyResolver, TxFetcher, EventFetcher,
    StateFetcher, DexDiscovery, OracleIntel
)
from shadowscan.trackers.graph_builder import GraphBuilder
from shadowscan.trackers.graph_exporter import GraphExporter
from shadowscan.detectors.evm.generic_patterns import PatternDetector as GenericPatternDetector
from shadowscan.data.contracts import ContractRegistry
from shadowscan.utils.schema import (
    ScreeningSession, ScreeningMode, DepthLevel, ProxyInfo,
    FunctionSummary, StateSnapshot, OracleInfo, InteractionGraph
)
from shadowscan.utils.helpers import (
    generate_session_id, format_wei, is_contract_address
)

logger = logging.getLogger(__name__)

class ScreeningEngine:
    """Main screening engine coordinating all analysis components."""
    
    def __init__(self, rpc_url: str, etherscan_api_key: Optional[str] = None):
        """
        Initialize screening engine with web3 connection and API keys.
        
        Args:
            rpc_url: Ethereum RPC endpoint URL
            etherscan_api_key: Optional Etherscan API key for enhanced data
        """
        # Initialize Web3 connection
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        self.etherscan_api_key = etherscan_api_key
        self.rpc_url = rpc_url
        
        # Verify connection
        if not self.web3.is_connected():
            raise ConnectionError(f"Cannot connect to Ethereum RPC at {rpc_url}")
        
        # Initialize all components
        self._initialize_components()
        
        # Initialize ContractRegistry
        self.contract_registry = ContractRegistry()
        
        # Performance tracking
        self.rpc_calls_made = 0
        self.errors_encountered = []
        
        logger.info(f"ScreeningEngine initialized with RPC: {rpc_url}")
    
    def _initialize_components(self):
        """Initialize all collector, tracker, and detector components."""
        # Collectors
        self.abi_fetcher = ABIFetcher(etherscan_api_key=self.etherscan_api_key)
        self.proxy_resolver = ProxyResolver(self.web3)
        self.tx_fetcher = TxFetcher(self.web3, self.etherscan_api_key)
        self.event_fetcher = EventFetcher(self.web3, self.etherscan_api_key)
        self.state_fetcher = StateFetcher(self.web3)
        self.dex_discovery = DexDiscovery(self.web3)
        self.oracle_intel = OracleIntel(self.web3)
        
        # Trackers
        self.graph_builder = GraphBuilder(self.web3)
        self.graph_exporter = GraphExporter()
        
        # Detectors
        self.pattern_detector = GenericPatternDetector(self.web3)
        
        logger.debug("All screening components initialized successfully")
    
    def run_screening(self, target: str, chain: str = 'ethereum', mode: str = 'fork',
                     depth: str = 'full', opts: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run complete screening analysis pipeline.
        
        Args:
            target: Target contract address
            chain: Blockchain network name
            mode: Screening mode ('fork' or 'mainnet')
            depth: Analysis depth ('shallow' or 'full')
            opts: Additional options
                - with_graph: bool = True
                - with_events: bool = True  
                - with_state: bool = True
                - concurrency: int = 8
                - timeout: int = 300
                - output: str = 'reports/findings'
                
        Returns:
            Dictionary with session file path and summary
        """
        start_time = time.time()
        opts = opts or {}
        
        try:
            # Validate inputs
            target_address = Web3.to_checksum_address(target)
            screening_mode = ScreeningMode.FORK if mode.lower() == 'fork' else ScreeningMode.MAINNET
            depth_level = DepthLevel.FULL if depth.lower() == 'full' else DepthLevel.SHALLOW
            
            # Create session
            session_id = generate_session_id(target_address, chain)
            current_block = self.web3.eth.block_number
            
            session = ScreeningSession(
                session_id=session_id,
                target=target_address,
                chain=chain,
                mode=screening_mode,
                depth=depth_level,
                block=current_block,
                timestamp=datetime.now().isoformat()
            )
            
            # Create or load session in ContractRegistry
            try:
                registry_session = self.contract_registry.create_session(target_address, chain, session_id)
                logger.info(f"Created/loaded session in ContractRegistry: {session_id}")
            except Exception as e:
                logger.warning(f"Failed to create ContractRegistry session: {e}")
            
            logger.info(f"Starting screening session: {session_id}")
            logger.info(f"Target: {target_address} | Chain: {chain} | Mode: {mode} | Depth: {depth}")
            
            # Run collection phase
            self._run_collection_phase(session, opts)
            
            # Run tracking phase
            if opts.get('with_graph', True):
                self._run_tracking_phase(session, opts)
            
            # Run detection phase
            self._run_detection_phase(session, opts)
            
            # Save session and generate reports
            session_file, summary = self._save_session_and_generate_reports(session, opts)
            
            # Calculate execution time
            session.execution_time = time.time() - start_time
            session.rpc_calls_made = self.rpc_calls_made
            session.errors = self.errors_encountered
            
            logger.info(f"Screening completed in {session.execution_time:.2f}s with {self.rpc_calls_made} RPC calls")
            
            return {
                'session_file': session_file,
                'summary': summary,
                'session_id': session_id,
                'execution_time': session.execution_time,
                'success': True
            }
            
        except Exception as e:
            logger.error(f"Screening failed: {e}")
            return {
                'session_file': None,
                'summary': {'error': str(e)},
                'session_id': session_id if 'session_id' in locals() else None,
                'execution_time': time.time() - start_time,
                'success': False
            }
    
    def _run_collection_phase(self, session: ScreeningSession, opts: Dict[str, Any]):
        """Run all data collection components in parallel."""
        logger.info("Starting collection phase...")
        
        concurrency = opts.get('concurrency', 8)
        
        # Define collection tasks
        collection_tasks = {
            'basic_info': lambda: self._collect_basic_contract_info(session.target),
            'abi': lambda: self._collect_abi_info(session.target, session.chain),
            'proxy': lambda: self._collect_proxy_info(session.target),
            'transactions': lambda: self._collect_transaction_data(session.target, session.chain, session.depth),
        }
        
        # Add optional heavy tasks for full depth
        if session.depth == DepthLevel.FULL:
            if opts.get('with_events', True):
                collection_tasks['events'] = lambda: self._collect_event_data(session.target)
            if opts.get('with_state', True):
                collection_tasks['state'] = lambda: self._collect_state_data(session.target)
        
        # Execute collection tasks in parallel
        results = {}
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            # Submit all tasks
            future_to_task = {
                executor.submit(task): task_name 
                for task_name, task in collection_tasks.items()
            }
            
            # Collect results
            for future in as_completed(future_to_task, timeout=opts.get('timeout', 300)):
                task_name = future_to_task[future]
                try:
                    results[task_name] = future.result()
                    logger.debug(f"Collection task '{task_name}' completed")
                except Exception as e:
                    logger.error(f"Collection task '{task_name}' failed: {e}")
                    self.errors_encountered.append(f"{task_name}: {str(e)}")
                    results[task_name] = None
        
        # Integrate results into session
        self._integrate_collection_results(session, results)
        
        logger.info(f"Collection phase completed with {len(results)} tasks")
    
    def _collect_basic_contract_info(self, target_address: str) -> Dict[str, Any]:
        """Collect basic contract information."""
        try:
            self.rpc_calls_made += 3
            
            # Get bytecode
            bytecode = self.web3.eth.get_code(target_address)
            
            # Get balance
            balance = self.web3.eth.get_balance(target_address)
            
            # Check if it's a contract
            is_contract = len(bytecode) > 0
            
            return {
                'bytecode': bytecode.hex(),
                'balance': str(balance),
                'is_contract': is_contract,
                'code_size': len(bytecode)
            }
            
        except Exception as e:
            logger.error(f"Error collecting basic contract info: {e}")
            return {}
    
    def _collect_abi_info(self, target_address: str, chain: str) -> Dict[str, Any]:
        """Collect ABI and function information."""
        try:
            # Fetch ABI
            abi = self.abi_fetcher.get_abi(target_address, chain)
            
            if not abi:
                return {'abi': None, 'functions_summary': FunctionSummary()}
            
            # Analyze functions
            functions_summary = self._analyze_functions_from_abi(abi)
            
            return {
                'abi': abi,
                'functions_summary': functions_summary
            }
            
        except Exception as e:
            logger.error(f"Error collecting ABI info: {e}")
            return {'abi': None, 'functions_summary': FunctionSummary()}
    
    def _collect_proxy_info(self, target_address: str) -> ProxyInfo:
        """Collect proxy pattern information."""
        try:
            self.rpc_calls_made += 5  # Approximate RPC calls for proxy detection
            return self.proxy_resolver.resolve_proxy(target_address, self.web3)
        except Exception as e:
            logger.error(f"Error collecting proxy info: {e}")
            return ProxyInfo()
    
    def _collect_transaction_data(self, target_address: str, chain: str, depth: DepthLevel) -> List[Dict[str, Any]]:
        """Collect transaction data."""
        try:
            limit = 200 if depth == DepthLevel.FULL else 50
            include_traces = depth == DepthLevel.FULL
            
            transactions = self.tx_fetcher.fetch_recent_txs_enhanced(
                address=target_address,
                limit=limit,
                chain=chain,
                include_traces=include_traces,
                depth=depth.value
            )
            
            self.rpc_calls_made += len(transactions) if include_traces else 10
            
            return [tx.__dict__ if hasattr(tx, '__dict__') else tx for tx in transactions]
            
        except Exception as e:
            logger.error(f"Error collecting transaction data: {e}")
            return []
    
    def _collect_event_data(self, target_address: str) -> List[Dict[str, Any]]:
        """Collect event data."""
        try:
            self.rpc_calls_made += 15  # Approximate RPC calls for events
            
            events = self.event_fetcher.fetch_events(target_address, self.web3)
            return [event.__dict__ if hasattr(event, '__dict__') else event for event in events]
            
        except Exception as e:
            logger.error(f"Error collecting event data: {e}")
            return []
    
    def _collect_state_data(self, target_address: str) -> StateSnapshot:
        """Collect contract state data."""
        try:
            self.rpc_calls_made += 25  # Approximate RPC calls for state
            
            return self.state_fetcher.fetch_state(target_address, self.web3)
            
        except Exception as e:
            logger.error(f"Error collecting state data: {e}")
            return StateSnapshot()
    
    def _analyze_functions_from_abi(self, abi: List[Dict[str, Any]]) -> FunctionSummary:
        """Analyze functions from ABI to create summary."""
        summary = FunctionSummary()
        
        for item in abi:
            if item.get('type') != 'function':
                continue
            
            func_name = item.get('name', '')
            summary.total += 1
            
            # Check if payable
            if item.get('payable') or item.get('stateMutability') == 'payable':
                summary.payable.append(func_name)
            
            # Check if external
            if item.get('visibility') == 'external':
                summary.external.append(func_name)
            
            # Check if sensitive
            sensitive_patterns = ['owner', 'admin', 'upgrade', 'destroy', 'kill', 'pause', 'mint', 'burn']
            if any(pattern in func_name.lower() for pattern in sensitive_patterns):
                summary.sensitive.append(func_name)
        
        return summary
    
    def _integrate_collection_results(self, session: ScreeningSession, results: Dict[str, Any]):
        """Integrate collection results into session."""
        # Basic info
        basic_info = results.get('basic_info', {})
        session.bytecode = basic_info.get('bytecode')
        
        # ABI info
        abi_info = results.get('abi', {})
        session.abi = abi_info.get('abi')
        session.functions_summary = abi_info.get('functions_summary', FunctionSummary())
        
        # Proxy info
        session.proxy_info = results.get('proxy', ProxyInfo())
        session.is_proxy = session.proxy_info.is_proxy
        
        # Transaction data
        session.txs = [self._dict_to_transaction(tx) for tx in results.get('transactions', [])]
        
        # Event data
        session.events = [self._dict_to_event(event) for event in results.get('events', [])]
        
        # State data
        session.state_snapshot = results.get('state', StateSnapshot())
    
    def _dict_to_transaction(self, tx_dict: Dict[str, Any]):
        """Convert transaction dict to Transaction object."""
        from shadowscan.utils.schema import Transaction
        
        return Transaction(
            hash=tx_dict.get('hash', ''),
            from_addr=tx_dict.get('from_addr', ''),
            to=tx_dict.get('to'),
            input=tx_dict.get('input', '0x'),
            value=tx_dict.get('value', '0'),
            block=tx_dict.get('block', 0),
            timestamp=tx_dict.get('timestamp', 0),
            gas_used=tx_dict.get('gas_used'),
            trace=tx_dict.get('trace')
        )
    
    def _dict_to_event(self, event_dict: Dict[str, Any]):
        """Convert event dict to Event object."""
        from shadowscan.utils.schema import Event
        
        return Event(
            name=event_dict.get('name', ''),
            tx_hash=event_dict.get('tx_hash', ''),
            args=event_dict.get('args', {}),
            block=event_dict.get('block', 0),
            log_index=event_dict.get('log_index', 0),
            address=event_dict.get('address', '')
        )
    
    def _run_tracking_phase(self, session: ScreeningSession, opts: Dict[str, Any]):
        """Run tracking phase to enrich session with intelligence."""
        logger.info("Starting tracking phase...")
        
        try:
            # Discover DEX relationships
            session.dex_refs = self._discover_dex_relationships(session)
            
            # Gather oracle intelligence
            session.oracle = self._gather_oracle_intelligence(session)
            
            # Build interaction graph
            session.interaction_graph = self._build_interaction_graph(session)
            
            logger.info(f"Tracking phase completed: {len(session.dex_refs)} DEX refs, "
                       f"{len(session.oracle.sources)} oracle sources")
            
        except Exception as e:
            logger.error(f"Error in tracking phase: {e}")
            self.errors_encountered.append(f"tracking: {str(e)}")
    
    def _discover_dex_relationships(self, session: ScreeningSession) -> List[Dict[str, Any]]:
        """Discover DEX relationships."""
        try:
            self.rpc_calls_made += 20  # Approximate RPC calls
            
            dex_refs = self.dex_discovery.discover_dex_relations(
                session.target, self.web3, session.chain
            )
            
            return [ref.__dict__ if hasattr(ref, '__dict__') else ref for ref in dex_refs]
            
        except Exception as e:
            logger.error(f"Error discovering DEX relationships: {e}")
            return []
    
    def _gather_oracle_intelligence(self, session: ScreeningSession) -> OracleInfo:
        """Gather oracle intelligence."""
        try:
            self.rpc_calls_made += 10  # Approximate RPC calls
            
            # Convert session to dict for oracle intel
            session_dict = session.to_dict()
            return self.oracle_intel.gather_oracle_info(session_dict, self.web3)
            
        except Exception as e:
            logger.error(f"Error gathering oracle intelligence: {e}")
            return OracleInfo()
    
    def _build_interaction_graph(self, session: ScreeningSession) -> Optional[InteractionGraph]:
        """Build interaction graph."""
        try:
            # Convert session to dict for graph builder
            session_dict = session.to_dict()
            return self.graph_builder.build_graph(session_dict)
            
        except Exception as e:
            logger.error(f"Error building interaction graph: {e}")
            return None
    
    def _run_detection_phase(self, session: ScreeningSession, opts: Dict[str, Any]):
        """Run detection phase to generate vulnerability hypotheses."""
        logger.info("Starting detection phase...")
        
        try:
            # Convert session to dict for pattern detector
            session_dict = session.to_dict()
            
            # Run generic pattern detection
            hypotheses = self.pattern_detector.detect_generic_patterns(session_dict)
            session.hypotheses = hypotheses
            
            logger.info(f"Detection phase completed: {len(hypotheses)} hypotheses generated")
            
        except Exception as e:
            logger.error(f"Error in detection phase: {e}")
            self.errors_encountered.append(f"detection: {str(e)}")
            session.hypotheses = []
    
    def _save_session_and_generate_reports(self, session: ScreeningSession, opts: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        """Save session file and generate reports."""
        output_dir = opts.get('output', 'reports/findings')
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Save main session file
        session_file = Path(output_dir) / f"{session.session_id}.json"
        with open(session_file, 'w') as f:
            f.write(session.to_json())
        
        # Generate graph files if graph was built
        if session.interaction_graph and opts.get('with_graph', True):
            graph_base_path = Path(output_dir) / f"graph_{session.session_id.split('_', 1)[1]}"
            
            # Export JSON graph
            json_path = self.graph_exporter.export_graph(
                session.interaction_graph,
                str(graph_base_path),
                html=opts.get('with_graph_html', False),
                format_type='d3'
            )
            
            session.interaction_graph_path = json_path
            
            # Update session file with graph path
            with open(session_file, 'w') as f:
                f.write(session.to_json())
        
        # Generate summary
        summary = self._generate_session_summary(session)
        
        logger.info(f"Session saved to: {session_file}")
        
        return str(session_file), summary
    
    def _generate_session_summary(self, session: ScreeningSession) -> Dict[str, Any]:
        """Generate session summary for CLI output."""
        # Count vulnerabilities by severity
        vuln_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for hypothesis in session.hypotheses:
            severity = hypothesis.severity.value if hasattr(hypothesis.severity, 'value') else str(hypothesis.severity)
            if severity in vuln_counts:
                vuln_counts[severity] += 1
        
        # Get top hypotheses
        top_hypotheses = sorted(session.hypotheses, key=lambda h: h.confidence, reverse=True)[:5]
        
        return {
            'target_address': session.target,
            'chain': session.chain,
            'mode': session.mode.value if hasattr(session.mode, 'value') else str(session.mode),
            'block_number': session.block,
            'is_verified': bool(session.abi),
            'is_proxy': session.is_proxy,
            'proxy_type': session.proxy_info.proxy_type.value if session.proxy_info.proxy_type and hasattr(session.proxy_info.proxy_type, 'value') else None,
            'function_count': session.functions_summary.total,
            'dex_count': len(session.dex_refs),
            'total_liquidity_usd': sum(ref.get('liquidity_usd', 0) for ref in session.dex_refs) if session.dex_refs else 0,
            'oracle_sources': len(session.oracle.sources),
            'oracle_risk_score': session.oracle.twap_risk_score,
            'total_hypotheses': len(session.hypotheses),
            'vulnerabilities_by_severity': vuln_counts,
            'top_hypotheses': [
                {
                    'category': h.category,
                    'confidence': h.confidence,
                    'severity': h.severity.value if hasattr(h.severity, 'value') else str(h.severity),
                    'description': h.description
                }
                for h in top_hypotheses
            ],
            'execution_time': session.execution_time,
            'rpc_calls': session.rpc_calls_made,
            'errors': len(session.errors)
        }
