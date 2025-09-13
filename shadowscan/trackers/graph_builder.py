# shadowscan/trackers/graph_builder.py
"""Contract relationship graph builder with weighted edge analysis."""

from web3 import Web3
from typing import Dict, Any, List, Optional, Set, Tuple
import logging
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import hashlib

from shadowscan.utils.schema import (
    InteractionGraph, GraphNode, GraphEdge, 
    Transaction, Event, DexReference
)
from shadowscan.utils.helpers import format_address, is_contract_address

logger = logging.getLogger(__name__)

class GraphBuilder:
    """Builds weighted interaction graphs from contract analysis data."""
    
    def __init__(self, web3: Web3):
        self.web3 = web3
        
        # Node type classifications
        self.node_types = {
            'target': {'color': '#ff4444', 'size': 50, 'priority': 10},
            'dex': {'color': '#44ff44', 'size': 40, 'priority': 8},
            'token': {'color': '#4444ff', 'size': 30, 'priority': 6},
            'oracle': {'color': '#ffaa44', 'size': 35, 'priority': 7},
            'proxy': {'color': '#aa44ff', 'size': 25, 'priority': 5},
            'contract': {'color': '#888888', 'size': 20, 'priority': 3},
            'eoa': {'color': '#cccccc', 'size': 15, 'priority': 1}
        }
        
        # Edge type classifications
        self.edge_types = {
            'call': {'color': '#666666', 'width': 2, 'style': 'solid'},
            'transfer': {'color': '#00aa00', 'width': 3, 'style': 'solid'},
            'approval': {'color': '#aa0000', 'width': 2, 'style': 'dashed'},
            'dex_interaction': {'color': '#0088ff', 'width': 4, 'style': 'solid'},
            'oracle_read': {'color': '#ff8800', 'width': 2, 'style': 'dotted'},
            'proxy_call': {'color': '#8800ff', 'width': 3, 'style': 'solid'},
            'admin': {'color': '#ff0000', 'width': 2, 'style': 'dashed'}
        }
        
        # Known contract classifications
        self.known_contracts = {
            # DEX Routers
            '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D': {'type': 'dex', 'label': 'Uniswap V2 Router'},
            '0xE592427A0AEce92De3Edee1F18E0157C05861564': {'type': 'dex', 'label': 'Uniswap V3 Router'},
            '0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F': {'type': 'dex', 'label': 'SushiSwap Router'},
            
            # Tokens
            '0xA0b86a33E6441cF0047f25C4AD19f2c7f84951e5': {'type': 'token', 'label': 'USDC'},
            '0xdAC17F958D2ee523a2206206994597C13D831ec7': {'type': 'token', 'label': 'USDT'},
            '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2': {'type': 'token', 'label': 'WETH'},
            
            # Oracles
            '0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419': {'type': 'oracle', 'label': 'ETH/USD Chainlink'},
        }
    
    def build_graph(self, session_json: Dict[str, Any]) -> InteractionGraph:
        """
        Build comprehensive interaction graph from session data.
        
        Args:
            session_json: Complete session data with transactions, events, DEX info
            
        Returns:
            InteractionGraph with nodes and weighted edges
        """
        try:
            target_address = session_json.get('target')
            if not target_address:
                raise ValueError("No target address in session data")
            
            logger.info(f"Building interaction graph for {target_address}")
            
            # Initialize graph
            graph = InteractionGraph()
            
            # Track all interactions for edge weighting
            interactions = defaultdict(lambda: defaultdict(int))
            
            # Add target node
            target_node = self._create_target_node(target_address, session_json)
            graph.nodes.append(target_node)
            
            # Process transactions for call relationships
            tx_edges = self._process_transactions(
                session_json.get('txs', []), target_address, interactions
            )
            graph.edges.extend(tx_edges)
            
            # Process events for transfer/approval relationships
            event_edges = self._process_events(
                session_json.get('events', []), target_address, interactions
            )
            graph.edges.extend(event_edges)
            
            # Process DEX relationships
            dex_edges = self._process_dex_relationships(
                session_json.get('dex_refs', []), target_address, interactions
            )
            graph.edges.extend(dex_edges)
            
            # Process oracle relationships
            oracle_edges = self._process_oracle_relationships(
                session_json.get('oracle', {}), target_address, interactions
            )
            graph.edges.extend(oracle_edges)
            
            # Process proxy relationships
            proxy_edges = self._process_proxy_relationships(
                session_json.get('proxy_info', {}), target_address, interactions
            )
            graph.edges.extend(proxy_edges)
            
            # Create nodes for all addresses found in edges
            self._create_nodes_from_edges(graph)
            
            # Calculate edge weights and apply clustering
            self._calculate_edge_weights(graph, interactions)
            
            # Apply graph optimizations
            self._optimize_graph(graph)
            
            # Add metadata
            graph.metadata = self._generate_graph_metadata(graph, session_json)
            
            logger.info(f"Graph built: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
            return graph
            
        except Exception as e:
            logger.error(f"Error building graph: {e}")
            return InteractionGraph()
    
    def _create_target_node(self, target_address: str, session_json: Dict[str, Any]) -> GraphNode:
        """Create the main target node with enhanced metadata."""
        proxy_info = session_json.get('proxy_info', {})
        functions_summary = session_json.get('functions_summary', {})
        
        label = f"Target\n{format_address(target_address)}"
        
        # Add proxy info to label
        if proxy_info.get('is_proxy'):
            label += f"\n[{proxy_info.get('proxy_type', 'Proxy')}]"
        
        # Add function count
        if functions_summary.get('total', 0) > 0:
            label += f"\n({functions_summary['total']} funcs)"
        
        metadata = {
            'address': target_address,
            'is_proxy': proxy_info.get('is_proxy', False),
            'proxy_type': proxy_info.get('proxy_type'),
            'function_count': functions_summary.get('total', 0),
            'sensitive_functions': functions_summary.get('sensitive', []),
            'centrality_score': 1.0  # Target has highest centrality
        }
        
        return GraphNode(
            id=target_address,
            label=label,
            type='target',
            metadata=metadata
        )
    
    def _process_transactions(self, transactions: List[Dict[str, Any]], target_address: str, 
                            interactions: Dict[str, Dict[str, int]]) -> List[GraphEdge]:
        """Process transactions to create call edges."""
        edges = []
        
        for tx in transactions:
            try:
                tx_hash = tx.get('hash')
                from_addr = tx.get('from_addr')
                to_addr = tx.get('to')
                input_data = tx.get('input', '0x')
                
                if not all([tx_hash, from_addr, to_addr]):
                    continue
                
                # Determine edge direction and type
                if to_addr.lower() == target_address.lower():
                    # Incoming call to target
                    edge_type = 'call'
                    source = from_addr
                    target = target_address
                    
                elif from_addr.lower() == target_address.lower():
                    # Outgoing call from target
                    edge_type = 'call'
                    source = target_address
                    target = to_addr
                else:
                    continue  # Not directly related to target
                
                # Detect special call types
                if len(input_data) >= 10:
                    func_selector = input_data[:10].lower()
                    edge_type = self._classify_function_call(func_selector, to_addr)
                
                # Record interaction
                interactions[source][target] += 1
                
                # Create edge
                edge = GraphEdge(
                    source=source,
                    target=target,
                    type=edge_type,
                    weight=1.0,  # Will be calculated later
                    metadata={
                        'tx_hash': tx_hash,
                        'function_selector': input_data[:10] if len(input_data) >= 10 else None,
                        'block_number': tx.get('block', 0),
                        'value': tx.get('value', '0')
                    }
                )
                
                edges.append(edge)
                
            except Exception as e:
                logger.debug(f"Error processing transaction: {e}")
                continue
        
        return edges
    
    def _classify_function_call(self, func_selector: str, to_addr: str) -> str:
        """Classify function call type based on selector and target."""
        # Oracle function selectors
        oracle_selectors = {
            '0x50d25bcd': 'oracle_read',  # latestAnswer()
            '0xfeaf968c': 'oracle_read',  # latestRoundData()
            '0x0902f1ac': 'oracle_read',  # getReserves()
        }
        
        # Proxy function selectors
        proxy_selectors = {
            '0x5c60da1b': 'proxy_call',   # implementation()
            '0xf851a440': 'proxy_call',  # admin()
        }
        
        # DEX function selectors
        dex_selectors = {
            '0x7ff36ab5': 'dex_interaction',  # swapExactETHForTokens
            '0x38ed1739': 'dex_interaction',  # swapExactTokensForTokens
            '0x128acb08': 'dex_interaction',  # addLiquidity
        }
        
        if func_selector in oracle_selectors:
            return oracle_selectors[func_selector]
        elif func_selector in proxy_selectors:
            return proxy_selectors[func_selector]
        elif func_selector in dex_selectors:
            return dex_selectors[func_selector]
        
        # Check if target is known contract type
        known_contract = self.known_contracts.get(to_addr.lower())
        if known_contract:
            if known_contract['type'] == 'dex':
                return 'dex_interaction'
            elif known_contract['type'] == 'oracle':
                return 'oracle_read'
        
        return 'call'
    
    def _process_events(self, events: List[Dict[str, Any]], target_address: str,
                       interactions: Dict[str, Dict[str, int]]) -> List[GraphEdge]:
        """Process events to create transfer/approval edges."""
        edges = []
        
        for event in events:
            try:
                event_name = event.get('name')
                args = event.get('args', {})
                tx_hash = event.get('tx_hash')
                
                if not event_name or not args:
                    continue
                
                edge = None
                
                if event_name == 'Transfer':
                    edge = self._create_transfer_edge(args, target_address, tx_hash)
                elif event_name == 'Approval':
                    edge = self._create_approval_edge(args, target_address, tx_hash)
                elif event_name == 'OwnershipTransferred':
                    edge = self._create_admin_edge(args, target_address, tx_hash)
                
                if edge:
                    interactions[edge.source][edge.target] += 1
                    edges.append(edge)
                    
            except Exception as e:
                logger.debug(f"Error processing event: {e}")
                continue
        
        return edges
    
    def _create_transfer_edge(self, args: Dict[str, Any], target_address: str, tx_hash: str) -> Optional[GraphEdge]:
        """Create transfer edge from Transfer event."""
        from_addr = args.get('from')
        to_addr = args.get('to')
        value = args.get('value', 0)
        
        if not all([from_addr, to_addr]) or from_addr == to_addr:
            return None
        
        # Only include transfers involving the target
        if target_address.lower() not in [from_addr.lower(), to_addr.lower()]:
            return None
        
        return GraphEdge(
            source=from_addr,
            target=to_addr,
            type='transfer',
            weight=1.0,
            metadata={
                'tx_hash': tx_hash,
                'value': str(value),
                'value_formatted': f"{float(value) / 1e18:.4f}" if isinstance(value, int) else str(value)
            }
        )
    
    def _create_approval_edge(self, args: Dict[str, Any], target_address: str, tx_hash: str) -> Optional[GraphEdge]:
        """Create approval edge from Approval event."""
        owner = args.get('owner')
        spender = args.get('spender')
        value = args.get('value', 0)
        
        if not all([owner, spender]) or owner == spender:
            return None
        
        # Only include approvals involving the target
        if target_address.lower() not in [owner.lower(), spender.lower()]:
            return None
        
        return GraphEdge(
            source=owner,
            target=spender,
            type='approval',
            weight=1.0,
            metadata={
                'tx_hash': tx_hash,
                'value': str(value),
                'is_max_approval': int(value) >= 2**255 if isinstance(value, int) else False
            }
        )
    
    def _create_admin_edge(self, args: Dict[str, Any], target_address: str, tx_hash: str) -> Optional[GraphEdge]:
        """Create admin edge from OwnershipTransferred event."""
        previous_owner = args.get('previousOwner')
        new_owner = args.get('newOwner')
        
        if not all([previous_owner, new_owner]):
            return None
        
        return GraphEdge(
            source=previous_owner,
            target=new_owner,
            type='admin',
            weight=1.0,
            metadata={
                'tx_hash': tx_hash,
                'event_type': 'OwnershipTransferred'
            }
        )
    
    def _process_dex_relationships(self, dex_refs: List[Dict[str, Any]], target_address: str,
                                 interactions: Dict[str, Dict[str, int]]) -> List[GraphEdge]:
        """Process DEX relationships to create dex_interaction edges."""
        edges = []
        
        for dex_ref in dex_refs:
            try:
                pair_address = dex_ref.get('pair')
                router_address = dex_ref.get('router')
                dex_name = dex_ref.get('dex_name', 'unknown')
                liquidity_usd = dex_ref.get('liquidity_usd', 0)
                
                if not pair_address:
                    continue
                
                # Create edge from target to pair
                pair_edge = GraphEdge(
                    source=target_address,
                    target=pair_address,
                    type='dex_interaction',
                    weight=liquidity_usd / 10000,  # Weight by liquidity (scaled)
                    metadata={
                        'dex_name': dex_name,
                        'liquidity_usd': liquidity_usd,
                        'depth_score': dex_ref.get('depth_score', 0),
                        'reserves': dex_ref.get('reserves', [])
                    }
                )
                edges.append(pair_edge)
                interactions[target_address][pair_address] += 5  # DEX interactions weighted higher
                
                # Create edge to router if different from pair
                if router_address and router_address.lower() != pair_address.lower():
                    router_edge = GraphEdge(
                        source=target_address,
                        target=router_address,
                        type='dex_interaction',
                        weight=liquidity_usd / 20000,  # Lower weight for router
                        metadata={
                            'dex_name': dex_name,
                            'role': 'router',
                            'liquidity_usd': liquidity_usd
                        }
                    )
                    edges.append(router_edge)
                    interactions[target_address][router_address] += 3
                    
            except Exception as e:
                logger.debug(f"Error processing DEX relationship: {e}")
                continue
        
        return edges
    
    def _process_oracle_relationships(self, oracle_info: Dict[str, Any], target_address: str,
                                    interactions: Dict[str, Dict[str, int]]) -> List[GraphEdge]:
        """Process oracle relationships to create oracle_read edges."""
        edges = []
        
        try:
            sources = oracle_info.get('sources', [])
            oracle_type = oracle_info.get('type', 'unknown')
            twap_window = oracle_info.get('twap_window')
            risk_score = oracle_info.get('twap_risk_score', 0.5)
            
            for source in sources:
                try:
                    # Parse source format: "type:address"
                    if ':' in source:
                        source_type, source_address = source.split(':', 1)
                    else:
                        source_type = 'unknown'
                        source_address = source
                    
                    edge = GraphEdge(
                        source=target_address,
                        target=source_address,
                        type='oracle_read',
                        weight=max(0.1, 1.0 - risk_score),  # Lower risk = higher weight
                        metadata={
                            'oracle_type': oracle_type,
                            'source_type': source_type,
                            'twap_window': twap_window,
                            'risk_score': risk_score
                        }
                    )
                    edges.append(edge)
                    interactions[target_address][source_address] += 2
                    
                except Exception as e:
                    logger.debug(f"Error processing oracle source {source}: {e}")
                    continue
                    
        except Exception as e:
            logger.debug(f"Error processing oracle relationships: {e}")
        
        return edges
    
    def _process_proxy_relationships(self, proxy_info: Dict[str, Any], target_address: str,
                                   interactions: Dict[str, Dict[str, int]]) -> List[GraphEdge]:
        """Process proxy relationships to create proxy_call edges."""
        edges = []
        
        try:
            if not proxy_info.get('is_proxy'):
                return edges
            
            implementation = proxy_info.get('implementation')
            admin = proxy_info.get('admin')
            proxy_type = proxy_info.get('proxy_type', 'unknown')
            
            # Create edge to implementation
            if implementation:
                impl_edge = GraphEdge(
                    source=target_address,
                    target=implementation,
                    type='proxy_call',
                    weight=2.0,  # High weight for implementation relationship
                    metadata={
                        'proxy_type': proxy_type,
                        'role': 'implementation',
                        'upgradeability_risk': proxy_info.get('upgradeability_risk', 'medium')
                    }
                )
                edges.append(impl_edge)
                interactions[target_address][implementation] += 10  # Very high weight
            
            # Create edge to admin
            if admin and admin != target_address:
                admin_edge = GraphEdge(
                    source=admin,
                    target=target_address,
                    type='admin',
                    weight=3.0,  # High weight for admin control
                    metadata={
                        'proxy_type': proxy_type,
                        'role': 'admin',
                        'admin_type': proxy_info.get('admin_type', 'unknown')
                    }
                )
                edges.append(admin_edge)
                interactions[admin][target_address] += 8
                
        except Exception as e:
            logger.debug(f"Error processing proxy relationships: {e}")
        
        return edges
    
    def _create_nodes_from_edges(self, graph: InteractionGraph):
        """Create nodes for all addresses found in edges."""
        existing_nodes = {node.id for node in graph.nodes}
        addresses_in_edges = set()
        
        # Collect all unique addresses from edges
        for edge in graph.edges:
            addresses_in_edges.add(edge.source)
            addresses_in_edges.add(edge.target)
        
        # Create nodes for new addresses
        for address in addresses_in_edges:
            if address not in existing_nodes:
                node = self._create_node_for_address(address, graph.edges)
                graph.nodes.append(node)
    
    def _create_node_for_address(self, address: str, edges: List[GraphEdge]) -> GraphNode:
        """Create appropriate node for an address based on its usage."""
        # Check if it's a known contract
        known_contract = self.known_contracts.get(address.lower())
        if known_contract:
            node_type = known_contract['type']
            label = known_contract['label']
        else:
            # Classify based on edge patterns
            node_type = self._classify_address_type(address, edges)
            label = self._generate_node_label(address, node_type)
        
        # Calculate node importance based on edge connections
        importance_score = self._calculate_node_importance(address, edges)
        
        metadata = {
            'address': address,
            'is_contract': is_contract_address(self.web3, address) if hasattr(self, 'web3') else None,
            'importance_score': importance_score,
            'edge_count': len([e for e in edges if e.source == address or e.target == address])
        }
        
        return GraphNode(
            id=address,
            label=label,
            type=node_type,
            metadata=metadata
        )
    
    def _classify_address_type(self, address: str, edges: List[GraphEdge]) -> str:
        """Classify address type based on its edge patterns."""
        # Count edge types involving this address
        edge_type_counts = Counter()
        
        for edge in edges:
            if edge.source == address or edge.target == address:
                edge_type_counts[edge.type] += 1
        
        # Classification logic
        if edge_type_counts.get('dex_interaction', 0) > 0:
            return 'dex'
        elif edge_type_counts.get('oracle_read', 0) > 0:
            return 'oracle'  
        elif edge_type_counts.get('proxy_call', 0) > 0:
            return 'proxy'
        elif edge_type_counts.get('transfer', 0) > edge_type_counts.get('call', 0):
            return 'token'
        elif any(edge_type_counts.values()):
            # Try to determine if it's a contract or EOA
            try:
                if is_contract_address(self.web3, address):
                    return 'contract'
                else:
                    return 'eoa'
            except Exception:
                return 'contract'  # Default assumption
        
        return 'contract'
    
    def _generate_node_label(self, address: str, node_type: str) -> str:
        """Generate appropriate label for a node."""
        short_addr = format_address(address)
        
        type_labels = {
            'dex': f'DEX\n{short_addr}',
            'token': f'Token\n{short_addr}',
            'oracle': f'Oracle\n{short_addr}',
            'proxy': f'Proxy\n{short_addr}',
            'contract': f'Contract\n{short_addr}',
            'eoa': f'EOA\n{short_addr}'
        }
        
        return type_labels.get(node_type, f'{node_type.title()}\n{short_addr}')
    
    def _calculate_node_importance(self, address: str, edges: List[GraphEdge]) -> float:
        """Calculate node importance based on edge weights and types."""
        total_weight = 0.0
        edge_count = 0
        
        for edge in edges:
            if edge.source == address or edge.target == address:
                # Weight different edge types differently
                type_multiplier = {
                    'dex_interaction': 3.0,
                    'oracle_read': 2.5,
                    'proxy_call': 2.0,
                    'admin': 2.0,
                    'transfer': 1.5,
                    'approval': 1.0,
                    'call': 1.0
                }.get(edge.type, 1.0)
                
                total_weight += edge.weight * type_multiplier
                edge_count += 1
        
        # Normalize by edge count to get average importance
        return total_weight / max(1, edge_count)
    
    def _calculate_edge_weights(self, graph: InteractionGraph, interactions: Dict[str, Dict[str, int]]):
        """Calculate final edge weights based on interaction frequency and type."""
        for edge in graph.edges:
            base_frequency = interactions[edge.source].get(edge.target, 1)
            
            # Apply type-specific weight multipliers
            type_multiplier = {
                'dex_interaction': 2.0,
                'oracle_read': 1.8,
                'proxy_call': 1.5,
                'admin': 2.5,
                'transfer': 1.2,
                'approval': 1.0,
                'call': 1.0
            }.get(edge.type, 1.0)
            
            # Calculate final weight (log scale to prevent extreme values)
            import math
            edge.weight = math.log1p(base_frequency) * type_multiplier
            
            # Ensure minimum weight
            edge.weight = max(0.1, edge.weight)
    
    def _optimize_graph(self, graph: InteractionGraph):
        """Apply graph optimizations to improve visualization and analysis."""
        # Remove low-weight edges if graph is too dense
        if len(graph.edges) > 50:
            # Keep only edges with weight above threshold
            weight_threshold = sorted([e.weight for e in graph.edges], reverse=True)[40]
            graph.edges = [e for e in graph.edges if e.weight >= weight_threshold]
        
        # Remove isolated nodes (nodes with no edges)
        connected_addresses = set()
        for edge in graph.edges:
            connected_addresses.add(edge.source)
            connected_addresses.add(edge.target)
        
        graph.nodes = [n for n in graph.nodes if n.id in connected_addresses]
        
        # Update node metadata with final centrality scores
        self._calculate_centrality_scores(graph)
    
    def _calculate_centrality_scores(self, graph: InteractionGraph):
        """Calculate centrality scores for nodes."""
        # Simple degree centrality calculation
        degree_count = defaultdict(int)
        weighted_degree = defaultdict(float)
        
        for edge in graph.edges:
            degree_count[edge.source] += 1
            degree_count[edge.target] += 1
            weighted_degree[edge.source] += edge.weight
            weighted_degree[edge.target] += edge.weight
        
        max_degree = max(degree_count.values()) if degree_count else 1
        max_weighted = max(weighted_degree.values()) if weighted_degree else 1
        
        for node in graph.nodes:
            node.metadata['degree_centrality'] = degree_count[node.id] / max_degree
            node.metadata['weighted_centrality'] = weighted_degree[node.id] / max_weighted
    
    def _generate_graph_metadata(self, graph: InteractionGraph, session_json: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive graph metadata."""
        # Count nodes by type
        node_types = Counter(node.type for node in graph.nodes)
        
        # Count edges by type
        edge_types = Counter(edge.type for edge in graph.edges)
        
        # Calculate graph metrics
        total_weight = sum(edge.weight for edge in graph.edges)
        avg_weight = total_weight / len(graph.edges) if graph.edges else 0
        
        return {
            'session_id': session_json.get('session_id'),
            'target_address': session_json.get('target'),
            'generated_at': datetime.now().isoformat(),
            'node_count': len(graph.nodes),
            'edge_count': len(graph.edges),
            'node_types': dict(node_types),
            'edge_types': dict(edge_types),
            'total_edge_weight': total_weight,
            'average_edge_weight': avg_weight,
            'graph_density': len(graph.edges) / max(1, len(graph.nodes) * (len(graph.nodes) - 1) / 2),
            'most_connected_nodes': self._get_most_connected_nodes(graph, 5),
            'strongest_edges': self._get_strongest_edges(graph, 5)
        }
    
    def _get_most_connected_nodes(self, graph: InteractionGraph, limit: int) -> List[Dict[str, Any]]:
        """Get most connected nodes by degree."""
        node_degrees = []
        
        for node in graph.nodes:
            degree = len([e for e in graph.edges if e.source == node.id or e.target == node.id])
            node_degrees.append({
                'address': node.id,
                'type': node.type,
                'degree': degree,
                'importance': node.metadata.get('importance_score', 0)
            })
        
        return sorted(node_degrees, key=lambda x: x['degree'], reverse=True)[:limit]
    
    def _get_strongest_edges(self, graph: InteractionGraph, limit: int) -> List[Dict[str, Any]]:
        """Get strongest edges by weight."""
        edge_info = []
        
        for edge in graph.edges:
            edge_info.append({
                'source': edge.source,
                'target': edge.target,
                'type': edge.type,
                'weight': edge.weight
            })
        
        return sorted(edge_info, key=lambda x: x['weight'], reverse=True)[:limit]
