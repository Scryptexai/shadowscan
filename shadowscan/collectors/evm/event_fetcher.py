# shadowscan/collectors/evm/event_fetcher.py
"""Comprehensive event and log fetcher with intelligent parsing."""

import requests
from web3 import Web3
from typing import List, Dict, Any, Optional, Set
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from eth_abi import decode
from eth_utils import keccak

from shadowscan.utils.schema import Event
from shadowscan.utils.helpers import parse_token_transfer

logger = logging.getLogger(__name__)

class EventFetcher:
    """Comprehensive event fetcher with intelligent log parsing and analysis."""
    
    def __init__(self, web3: Web3, etherscan_api_key: Optional[str] = None):
        self.web3 = web3
        self.etherscan_api_key = etherscan_api_key
        
        # Standard event signatures with their ABI definitions
        self.event_signatures = {
            # ERC20/Token Events
            keccak(text="Transfer(address,address,uint256)")[:4].hex(): {
                'name': 'Transfer',
                'inputs': ['address', 'address', 'uint256'],
                'indexed': [True, True, False],
                'labels': ['from', 'to', 'value']
            },
            keccak(text="Approval(address,address,uint256)")[:4].hex(): {
                'name': 'Approval', 
                'inputs': ['address', 'address', 'uint256'],
                'indexed': [True, True, False],
                'labels': ['owner', 'spender', 'value']
            },
            
            # DEX Events
            keccak(text="Swap(address,uint256,uint256,uint256,uint256,address)")[:4].hex(): {
                'name': 'Swap',
                'inputs': ['address', 'uint256', 'uint256', 'uint256', 'uint256', 'address'],
                'indexed': [True, False, False, False, False, True],
                'labels': ['sender', 'amount0In', 'amount1In', 'amount0Out', 'amount1Out', 'to']
            },
            keccak(text="Sync(uint112,uint112)")[:4].hex(): {
                'name': 'Sync',
                'inputs': ['uint112', 'uint112'],
                'indexed': [False, False],
                'labels': ['reserve0', 'reserve1']
            },
            keccak(text="Mint(address,uint256,uint256)")[:4].hex(): {
                'name': 'Mint',
                'inputs': ['address', 'uint256', 'uint256'],
                'indexed': [True, False, False],
                'labels': ['sender', 'amount0', 'amount1']
            },
            keccak(text="Burn(address,uint256,uint256,address)")[:4].hex(): {
                'name': 'Burn',
                'inputs': ['address', 'uint256', 'uint256', 'address'],
                'indexed': [True, False, False, True],
                'labels': ['sender', 'amount0', 'amount1', 'to']
            },
            
            # Governance Events
            keccak(text="OwnershipTransferred(address,address)")[:4].hex(): {
                'name': 'OwnershipTransferred',
                'inputs': ['address', 'address'],
                'indexed': [True, True],
                'labels': ['previousOwner', 'newOwner']
            },
            keccak(text="ProposalCreated(uint256,address,address[],uint256[],string[],bytes[],uint256,uint256,string)")[:4].hex(): {
                'name': 'ProposalCreated',
                'inputs': ['uint256', 'address', 'address[]', 'uint256[]', 'string[]', 'bytes[]', 'uint256', 'uint256', 'string'],
                'indexed': [False, True, False, False, False, False, False, False, False],
                'labels': ['id', 'proposer', 'targets', 'values', 'signatures', 'calldatas', 'startBlock', 'endBlock', 'description']
            },
            
            # Oracle Events
            keccak(text="AnswerUpdated(int256,uint256,uint256)")[:4].hex(): {
                'name': 'AnswerUpdated',
                'inputs': ['int256', 'uint256', 'uint256'],
                'indexed': [True, True, False],
                'labels': ['current', 'roundId', 'updatedAt']
            },
            
            # Proxy Events
            keccak(text="Upgraded(address)")[:4].hex(): {
                'name': 'Upgraded',
                'inputs': ['address'],
                'indexed': [True],
                'labels': ['implementation']
            },
            keccak(text="AdminChanged(address,address)")[:4].hex(): {
                'name': 'AdminChanged',
                'inputs': ['address', 'address'],
                'indexed': [False, False],
                'labels': ['previousAdmin', 'newAdmin']
            }
        }
    
    def fetch_events(self, address: str, provider, topics: Optional[List[str]] = None, 
                    from_block: Optional[int] = None, to_block: Optional[int] = None,
                    limit: int = 10000) -> List[Event]:
        """
        Fetch and parse contract events comprehensively.
        
        Args:
            address: Contract address
            provider: Web3 provider (for compatibility)
            topics: Optional topic filters
            from_block: Starting block number
            to_block: Ending block number  
            limit: Maximum events to return
            
        Returns:
            List of parsed Event objects
        """
        try:
            checksum_addr = Web3.to_checksum_address(address)
            
            # Set default block range if not provided
            if from_block is None:
                current_block = self.web3.eth.block_number
                from_block = max(0, current_block - 10000)  # Last ~2-3 days
            
            if to_block is None:
                to_block = 'latest'
            
            logger.info(f"Fetching events for {address} from block {from_block} to {to_block}")
            
            # Fetch raw logs
            logs = self._fetch_logs_chunked(checksum_addr, from_block, to_block, topics, limit)
            
            # Parse logs into Event objects
            events = self._parse_logs_to_events(logs)
            
            # Sort by block number and log index
            events.sort(key=lambda e: (e.block, e.log_index))
            
            logger.info(f"Successfully parsed {len(events)} events")
            return events[:limit]
            
        except Exception as e:
            logger.error(f"Error fetching events for {address}: {e}")
            return []
    
    def _fetch_logs_chunked(self, address: str, from_block: int, to_block, 
                          topics: Optional[List[str]], limit: int) -> List[Dict[str, Any]]:
        """Fetch logs in chunks to handle large block ranges."""
        all_logs = []
        current_block = from_block
        end_block = self.web3.eth.block_number if to_block == 'latest' else to_block
        
        chunk_size = 2000  # Process 2000 blocks at a time
        
        while current_block <= end_block and len(all_logs) < limit:
            chunk_end = min(current_block + chunk_size - 1, end_block)
            
            try:
                filter_params = {
                    'address': address,
                    'fromBlock': current_block,
                    'toBlock': chunk_end
                }
                
                if topics:
                    filter_params['topics'] = topics
                
                chunk_logs = self.web3.eth.get_logs(filter_params)
                all_logs.extend(chunk_logs)
                
                logger.debug(f"Fetched {len(chunk_logs)} logs from blocks {current_block}-{chunk_end}")
                
                # Rate limiting
                time.sleep(0.1)
                
            except Exception as e:
                logger.warning(f"Error fetching logs for blocks {current_block}-{chunk_end}: {e}")
                
            current_block = chunk_end + 1
        
        return all_logs[:limit]
    
    def _parse_logs_to_events(self, logs: List[Dict[str, Any]]) -> List[Event]:
        """Parse raw logs into structured Event objects."""
        events = []
        
        for log in logs:
            try:
                event = self._parse_single_log(log)
                if event:
                    events.append(event)
            except Exception as e:
                logger.debug(f"Error parsing log: {e}")
                continue
        
        return events
    
    def _parse_single_log(self, log) -> Optional[Event]:
        """Parse a single log entry into an Event object."""
        if not log.topics:
            return None
        
        # Get event signature (topic0)
        topic0 = log.topics[0].hex()
        event_def = self.event_signatures.get(topic0)
        
        if not event_def:
            # Unknown event - create basic event object
            return Event(
                name=f"Unknown_{topic0[:10]}",
                tx_hash=log.transactionHash.hex(),
                args={'raw_data': log.data.hex(), 'topics': [t.hex() for t in log.topics]},
                block=log.blockNumber,
                log_index=log.logIndex,
                address=log.address
            )
        
        # Parse known event
        try:
            parsed_args = self._decode_event_data(log, event_def)
            
            return Event(
                name=event_def['name'],
                tx_hash=log.transactionHash.hex(),
                args=parsed_args,
                block=log.blockNumber,
                log_index=log.logIndex,
                address=log.address
            )
            
        except Exception as e:
            logger.debug(f"Error decoding event {event_def['name']}: {e}")
            return None
    
    def _decode_event_data(self, log, event_def: Dict[str, Any]) -> Dict[str, Any]:
        """Decode event data based on ABI definition."""
        args = {}
        
        # Decode indexed parameters from topics
        topic_index = 1  # Skip topic0 (event signature)
        indexed_types = []
        indexed_labels = []
        non_indexed_types = []
        non_indexed_labels = []
        
        for i, (input_type, is_indexed, label) in enumerate(zip(
            event_def['inputs'], event_def['indexed'], event_def['labels']
        )):
            if is_indexed:
                indexed_types.append(input_type)
                indexed_labels.append(label)
            else:
                non_indexed_types.append(input_type)
                non_indexed_labels.append(label)
        
        # Decode indexed parameters from topics
        for i, (param_type, label) in enumerate(zip(indexed_types, indexed_labels)):
            if topic_index < len(log.topics):
                topic_data = log.topics[topic_index]
                
                if param_type == 'address':
                    # Address is in the last 20 bytes of the topic
                    args[label] = Web3.to_checksum_address(topic_data[-20:])
                elif param_type.startswith('uint') or param_type.startswith('int'):
                    # Integer types
                    args[label] = int.from_bytes(topic_data, byteorder='big', signed=param_type.startswith('int'))
                elif param_type == 'bool':
                    args[label] = bool(int.from_bytes(topic_data, byteorder='big'))
                else:
                    # For complex types, store as hex
                    args[label] = topic_data.hex()
                
                topic_index += 1
        
        # Decode non-indexed parameters from data
        if non_indexed_types and log.data and log.data != '0x':
            try:
                decoded_data = decode(non_indexed_types, log.data)
                
                for label, value in zip(non_indexed_labels, decoded_data):
                    if isinstance(value, bytes):
                        # Convert bytes to appropriate format
                        if len(value) == 20:  # Likely an address
                            args[label] = Web3.to_checksum_address(value)
                        else:
                            args[label] = value.hex()
                    else:
                        args[label] = value
                        
            except Exception as e:
                logger.debug(f"Error decoding non-indexed data: {e}")
                # Store raw data as fallback
                args['raw_data'] = log.data.hex()
        
        return args
    
    def get_event_summary(self, events: List[Event]) -> Dict[str, Any]:
        """Generate summary statistics for events."""
        if not events:
            return {}
        
        summary = {
            'total_events': len(events),
            'event_types': {},
            'unique_addresses': set(),
            'block_range': {
                'start': min(e.block for e in events),
                'end': max(e.block for e in events)
            },
            'transactions': set()
        }
        
        # Analyze event patterns
        for event in events:
            # Count event types
            summary['event_types'][event.name] = summary['event_types'].get(event.name, 0) + 1
            
            # Track unique addresses
            summary['unique_addresses'].add(event.address)
            
            # Track transactions
            summary['transactions'].add(event.tx_hash)
            
            # Analyze Transfer events for token flow
            if event.name == 'Transfer' and 'from' in event.args and 'to' in event.args:
                from_addr = event.args['from']
                to_addr = event.args['to']
                
                if 'transfer_flow' not in summary:
                    summary['transfer_flow'] = {'senders': {}, 'receivers': {}}
                
                summary['transfer_flow']['senders'][from_addr] = summary['transfer_flow']['senders'].get(from_addr, 0) + 1
                summary['transfer_flow']['receivers'][to_addr] = summary['transfer_flow']['receivers'].get(to_addr, 0) + 1
        
        # Convert sets to counts
        summary['unique_addresses'] = len(summary['unique_addresses'])
        summary['unique_transactions'] = len(summary['transactions'])
        del summary['transactions']  # Remove the set itself
        
        return summary
    
    def filter_events_by_type(self, events: List[Event], event_types: List[str]) -> List[Event]:
        """Filter events by specific event types."""
        return [event for event in events if event.name in event_types]
    
    def get_transfer_events(self, events: List[Event]) -> List[Event]:
        """Extract and analyze Transfer events specifically."""
        transfer_events = self.filter_events_by_type(events, ['Transfer'])
        
        # Add additional analysis for transfers
        for event in transfer_events:
            if 'value' in event.args:
                try:
                    # Convert value to float for easier analysis
                    event.args['value_float'] = float(event.args['value'])
                except (ValueError, TypeError):
                    event.args['value_float'] = 0.0
        
        return transfer_events
    
    def detect_suspicious_patterns(self, events: List[Event]) -> List[Dict[str, Any]]:
        """Detect suspicious patterns in events."""
        patterns = []
        
        if not events:
            return patterns
        
        # Pattern 1: Rapid successive transfers
        transfer_events = self.get_transfer_events(events)
        if len(transfer_events) > 10:
            # Check for transfers in same block (potential flashloan/MEV)
            block_transfers = {}
            for event in transfer_events:
                block_transfers[event.block] = block_transfers.get(event.block, 0) + 1
            
            for block, count in block_transfers.items():
                if count > 5:  # More than 5 transfers in same block
                    patterns.append({
                        'type': 'rapid_transfers',
                        'description': f'High transfer activity in block {block} ({count} transfers)',
                        'severity': 'medium',
                        'block': block,
                        'count': count
                    })
        
        # Pattern 2: Large value transfers
        for event in transfer_events:
            if 'value_float' in event.args and event.args['value_float'] > 1e24:  # > 1M tokens (assuming 18 decimals)
                patterns.append({
                    'type': 'large_transfer',
                    'description': f'Large value transfer: {event.args["value_float"]:.2e}',
                    'severity': 'high',
                    'tx_hash': event.tx_hash,
                    'value': event.args['value_float']
                })
        
        # Pattern 3: Ownership changes
        ownership_events = self.filter_events_by_type(events, ['OwnershipTransferred'])
        if ownership_events:
            patterns.append({
                'type': 'ownership_change',
                'description': f'Contract ownership changed {len(ownership_events)} time(s)',
                'severity': 'high',
                'count': len(ownership_events),
                'events': [e.tx_hash for e in ownership_events]
            })
        
        # Pattern 4: Proxy upgrades
        upgrade_events = self.filter_events_by_type(events, ['Upgraded'])
        if upgrade_events:
            patterns.append({
                'type': 'proxy_upgrade',
                'description': f'Proxy implementation upgraded {len(upgrade_events)} time(s)',
                'severity': 'critical',
                'count': len(upgrade_events),
                'events': [e.tx_hash for e in upgrade_events]
            })
        
        # Pattern 5: Unusual approval patterns
        approval_events = self.filter_events_by_type(events, ['Approval'])
        if len(approval_events) > 50:  # High number of approvals
            # Check for max approvals (potential honey pot indicator)
            max_approvals = 0
            for event in approval_events:
                if 'value' in event.args:
                    try:
                        value = int(event.args['value'])
                        # Check for max uint256 approval
                        if value >= 2**256 - 1000:  # Close to max uint256
                            max_approvals += 1
                    except (ValueError, TypeError):
                        pass
            
            if max_approvals > 10:
                patterns.append({
                    'type': 'excessive_max_approvals',
                    'description': f'Excessive max approvals detected: {max_approvals}',
                    'severity': 'medium',
                    'count': max_approvals
                })
        
        return patterns

    def analyze_token_flow(self, events: List[Event], target_address: str) -> Dict[str, Any]:
        """Analyze token flow patterns for the target address."""
        transfer_events = self.get_transfer_events(events)
        target_lower = target_address.lower()
        
        flow_analysis = {
            'inbound_transfers': 0,
            'outbound_transfers': 0,
            'total_inbound_value': 0,
            'total_outbound_value': 0,
            'unique_senders': set(),
            'unique_receivers': set(),
            'top_senders': {},
            'top_receivers': {}
        }
        
        for event in transfer_events:
            from_addr = event.args.get('from', '').lower()
            to_addr = event.args.get('to', '').lower()
            value = event.args.get('value_float', 0)
            
            if to_addr == target_lower:
                # Inbound transfer
                flow_analysis['inbound_transfers'] += 1
                flow_analysis['total_inbound_value'] += value
                flow_analysis['unique_senders'].add(from_addr)
                flow_analysis['top_senders'][from_addr] = flow_analysis['top_senders'].get(from_addr, 0) + value
                
            elif from_addr == target_lower:
                # Outbound transfer
                flow_analysis['outbound_transfers'] += 1
                flow_analysis['total_outbound_value'] += value
                flow_analysis['unique_receivers'].add(to_addr)
                flow_analysis['top_receivers'][to_addr] = flow_analysis['top_receivers'].get(to_addr, 0) + value
        
        # Convert sets to counts
        flow_analysis['unique_senders'] = len(flow_analysis['unique_senders'])
        flow_analysis['unique_receivers'] = len(flow_analysis['unique_receivers'])
        
        # Get top 5 senders/receivers by value
        flow_analysis['top_senders'] = dict(sorted(
            flow_analysis['top_senders'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:5])
        
        flow_analysis['top_receivers'] = dict(sorted(
            flow_analysis['top_receivers'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5])
        
        return flow_analysis
