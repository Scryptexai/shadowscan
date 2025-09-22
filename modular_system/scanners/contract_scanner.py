#!/usr/bin/env python3
"""
Contract Scanner Module - Phase 3 Implementation
Gathers detailed contract and backend intelligence for discovered protocols
"""

import json
import requests
import time
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import logging
from pathlib import Path
import sqlite3
from urllib.parse import urljoin, urlparse
from web3 import Web3
from dataclasses import dataclass, field

from ..core import BaseManager, DiagnosticTools, handle_error, ErrorSeverity, ErrorCategory
from ..core.config_manager import get_config

@dataclass
class ContractIntelligence:
    """Contract intelligence data structure"""
    protocol_name: str
    contract_address: str
    contract_type: str
    chain_id: int
    chain_name: str

    # Contract details
    abi: List[Dict[str, Any]] = field(default_factory=list)
    source_code: str = ""
    bytecode: str = ""
    function_signatures: List[str] = field(default_factory=list)
    event_signatures: List[str] = field(default_factory=list)

    # Backend info
    backend_technology: Dict[str, Any] = field(default_factory=dict)
    api_endpoints: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    related_contracts: List[str] = field(default_factory=list)

    # Security info
    audit_status: str = "UNKNOWN"
    security_score: int = 0
    known_vulnerabilities: List[str] = field(default_factory=list)

    # Metadata
    discovered_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    confidence_level: float = 0.0

class ContractScanner(BaseManager):
    """Advanced contract scanner with comprehensive intelligence gathering"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Initialize config first
        self.config = config or {}
        self.debug_mode = self.config.get('debug_mode', False)

        # Now call parent with proper config
        super().__init__("ContractScanner", self.config)
        self.diagnostic = DiagnosticTools()

        # Configuration
        self.max_retries = get_config('network.max_retries', 3)
        self.timeout = get_config('network.timeout', 30)
        self.user_agent = get_config('network.user_agent', 'ShadowScan-Scanner/1.0')

        # API endpoints
        self.explorer_apis = self._load_explorer_apis()

        # Contract database
        self.contract_database = {}

        # Web3 instances
        self.web3_instances = {}

        # Setup logging
        self.logger.info("ContractScanner initialized")

    def _load_explorer_apis(self) -> Dict[str, Dict[str, Any]]:
        """Load blockchain explorer APIs"""
        return {
            "etherscan": {
                "base_url": "https://api.etherscan.io/api",
                "api_key": get_config('network.etherscan_api_key', ''),
                "rate_limit": 5  # calls per second
            },
            "blockscout": {
                "base_url": "",
                "rate_limit": 10
            },
            "berascan": {
                "base_url": "https://api.bera.io",
                "rate_limit": 10
            }
        }

    def scan_protocol_contracts(self, protocol_data: Dict[str, Any]) -> List[ContractIntelligence]:
        """Scan all contracts for a specific protocol"""
        protocol_name = protocol_data.get('protocol_name', 'Unknown')
        self.logger.info(f"Scanning contracts for protocol: {protocol_name}")

        with self.diagnostic.trace_operation("ContractScanner", f"scan_protocol_{protocol_name}"):
            try:
                # Get potential contract addresses
                contract_addresses = self._discover_contract_addresses(protocol_data)

                # Scan each contract
                contract_intelligence = []
                for address in contract_addresses:
                    try:
                        intelligence = self._scan_contract(address, protocol_data)
                        if intelligence:
                            contract_intelligence.append(intelligence)
                    except Exception as e:
                        self.logger.error(f"Error scanning contract {address}: {e}")
                        continue

                return contract_intelligence

            except Exception as e:
                error_data = handle_error(e, "ContractScanner", {"protocol": protocol_name})
                self.logger.error(f"Protocol scanning failed: {e}")
                return []

    def _discover_contract_addresses(self, protocol_data: Dict[str, Any]) -> List[str]:
        """Discover contract addresses for a protocol"""
        addresses = []

        try:
            # Start with website
            website = protocol_data.get('website')
            if website:
                website_addresses = self._extract_addresses_from_website(website)
                addresses.extend(website_addresses)

            # Check for block explorer links
            blockchain = protocol_data.get('blockchain', '').lower()
            if blockchain in self.explorer_apis:
                explorer_addresses = self._scan_explorer_for_contracts(protocol_data)
                addresses.extend(explorer_addresses)

            # Remove duplicates
            return list(set(addresses))

        except Exception as e:
            self.logger.error(f"Error discovering contract addresses: {e}")
            return []

    def _extract_addresses_from_website(self, website: str) -> List[str]:
        """Extract contract addresses from protocol website"""
        addresses = []

        try:
            # Simple implementation - in production, use proper web scraping
            if 'etherscan.io' in website or 'berascan.io' in website:
                # Extract address from URL
                parsed = urlparse(website)
                path_parts = parsed.path.strip('/').split('/')

                if len(path_parts) > 1:
                    address = path_parts[-1]
                    if self._is_valid_address(address):
                        addresses.append(address)

        except Exception as e:
            self.logger.error(f"Error extracting addresses from website: {e}")

        return addresses

    def _scan_explorer_for_contracts(self, protocol_data: Dict[str, Any]) -> List[str]:
        """Scan blockchain explorer for contract addresses"""
        addresses = []

        try:
            blockchain = protocol_data.get('blockchain', '').lower()
            explorer_config = self.explorer_apis.get(blockchain)

            if not explorer_config:
                return addresses

            # Implementation would search explorer API for protocol name
            # This is a simplified version
            self.logger.info(f"Scanning {blockchain} explorer for contracts")

            # In a real implementation, you would:
            # 1. Search the explorer API for the protocol name
            # 2. Extract contract addresses from search results
            # 3. Validate addresses

        except Exception as e:
            self.logger.error(f"Error scanning explorer: {e}")

        return addresses

    def _is_valid_address(self, address: str) -> bool:
        """Check if address is a valid contract address"""
        try:
            return Web3.is_address(address) and len(address) == 42
        except:
            return False

    def _scan_contract(self, address: str, protocol_data: Dict[str, Any]) -> Optional[ContractIntelligence]:
        """Scan individual contract for intelligence"""
        try:
            self.logger.debug(f"Scanning contract: {address}")

            # Get blockchain info
            chain_id = protocol_data.get('chain_id', 1)
            chain_name = protocol_data.get('blockchain', 'Unknown')

            # Initialize Web3 for the chain
            web3 = self._get_web3_instance(chain_id)
            if not web3:
                return None

            # Get contract ABI
            abi = self._get_contract_abi(address, chain_name)

            # Get contract bytecode
            try:
                contract = web3.eth.contract(address=address, abi=abi)
                bytecode = contract.bytecode.hex() if contract.bytecode else ""
            except Exception as e:
                self.logger.error(f"Error getting bytecode for {address}: {e}")
                bytecode = ""

            # Analyze contract
            analysis = self._analyze_contract_functions(contract, protocol_data)

            # Create intelligence object
            intelligence = ContractIntelligence(
                protocol_name=protocol_data.get('protocol_name', 'Unknown'),
                contract_address=address,
                contract_type=analysis.get('contract_type', 'UNKNOWN'),
                chain_id=chain_id,
                chain_name=chain_name,
                abi=abi,
                source_code=analysis.get('source_code', ''),
                bytecode=bytecode,
                function_signatures=analysis.get('functions', []),
                event_signatures=analysis.get('events', []),
                audit_status=self._get_audit_status(address, chain_name),
                security_score=self._calculate_security_score(analysis)
            )

            # Confidence based on available data
            intelligence.confidence_level = self._calculate_confidence_level(intelligence)

            return intelligence

        except Exception as e:
            self.logger.error(f"Error scanning contract {address}: {e}")
            return None

    def _get_web3_instance(self, chain_id: int) -> Optional[Any]:
        """Get Web3 instance for specific chain"""
        try:
            if chain_id not in self.web3_instances:
                # Load chain configuration
                chains_config = self._load_chain_configurations()
                chain_config = chains_config.get(chain_id)

                if not chain_config:
                    self.logger.error(f"No configuration found for chain ID: {chain_id}")
                    return None

                # Initialize Web3
                web3 = Web3(Web3.HTTPProvider(chain_config['rpc_url']))
                if web3.is_connected():
                    self.web3_instances[chain_id] = web3
                    self.logger.info(f"Connected to {chain_config['name']} RPC")
                else:
                    self.logger.error(f"Failed to connect to {chain_config['name']} RPC")
                    return None

            return self.web3_instances[chain_id]

        except Exception as e:
            self.logger.error(f"Error creating Web3 instance for chain {chain_id}: {e}")
            return None

    def _load_chain_configurations(self) -> Dict[int, Dict[str, Any]]:
        """Load blockchain chain configurations"""
        return {
            1: {'name': 'Ethereum', 'rpc_url': 'https://eth.public-rpc.com'},
            56: {'name': 'BSC', 'rpc_url': 'https://bsc-dataseed.binance.org'},
            137: {'name': 'Polygon', 'rpc_url': 'https://polygon-rpc.com'},
            80085: {'name': 'Berachain', 'rpc_url': 'https://bera.rpc.publicnode.com'},
            1514: {'name': 'Story Protocol', 'rpc_url': 'https://story-rpc.publicnode.com'}
        }

    def _get_contract_abi(self, address: str, chain_name: str) -> List[Dict[str, Any]]:
        """Get contract ABI from explorer API"""
        try:
            # Implementation would call explorer APIs like Etherscan, Blockscout, etc.
            # This is a simplified version

            # Try Etherscan-style API
            if chain_name.lower() in ['ethereum', 'eth']:
                api_url = f"https://api.etherscan.io/api?module=contract&action=getabi&address={address}&apikey={self.explorer_apis['etherscan']['api_key']}"

                for attempt in range(self.max_retries):
                    try:
                        response = requests.get(api_url, timeout=self.timeout)
                        if response.status_code == 200:
                            data = response.json()
                            if data.get('status') == '1':
                                abi = json.loads(data.get('result', '[]'))
                                return abi
                    except Exception as e:
                        if attempt < self.max_retries - 1:
                            time.sleep(1)
                        continue

            # Fallback: Empty ABI
            return []

        except Exception as e:
            self.logger.error(f"Error getting ABI for {address}: {e}")
            return []

    def _analyze_contract_functions(self, contract: Any, protocol_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze contract functions and events"""
        analysis = {
            'contract_type': 'UNKNOWN',
            'functions': [],
            'events': [],
            'source_code': ''
        }

        try:
            # Extract function signatures
            for function in contract.all_functions():
                sig = function.signature
                analysis['functions'].append(sig)

            # Extract event signatures
            for event in contract.events:
                sig = event.signature
                analysis['events'].append(sig)

            # Determine contract type based on function patterns
            function_str = ' '.join(analysis['functions']).lower()

            if 'swap' in function_str and 'liquidity' in function_str:
                analysis['contract_type'] = 'DEX_ROUTER'
            elif 'deposit' in function_str and 'withdraw' in function_str:
                analysis['contract_type'] = 'LENDING'
            elif 'stake' in function_str and 'unstake' in function_str:
                analysis['contract_type'] = 'STAKING'
            elif 'bridge' in function_str:
                analysis['contract_type'] = 'BRIDGE'

        except Exception as e:
            self.logger.error(f"Error analyzing contract functions: {e}")

        return analysis

    def _get_audit_status(self, address: str, chain_name: str) -> str:
        """Get contract audit status"""
        # Implementation would check known audit databases
        # For now, return basic status
        return "UNKNOWN"

    def _calculate_security_score(self, analysis: Dict[str, Any]) -> int:
        """Calculate security score based on analysis"""
        score = 50  # Base score

        # Bonus for complete ABI
        if len(analysis.get('functions', [])) > 10:
            score += 10

        # Bonus for multiple event types
        if len(analysis.get('events', [])) > 5:
            score += 10

        # Penalty for unknown contract type
        if analysis.get('contract_type') == 'UNKNOWN':
            score -= 20

        return max(0, min(100, score))

    def _calculate_confidence_level(self, intelligence: ContractIntelligence) -> float:
        """Calculate confidence level for contract intelligence"""
        confidence = 0.0

        # ABI presence
        if intelligence.abi:
            confidence += 0.3

        # Bytecode presence
        if intelligence.bytecode:
            confidence += 0.2

        # Function signatures
        if intelligence.function_signatures:
            confidence += 0.2

        # Event signatures
        if intelligence.event_signatures:
            confidence += 0.15

        # Security score
        if intelligence.security_score > 70:
            confidence += 0.15

        return min(1.0, confidence)

    def scan_database_contracts(self, database_file: str = "defi_protocol_database.json") -> Dict[str, Any]:
        """Scan all contracts in the protocol database"""
        try:
            with open(database_file, 'r', encoding='utf-8') as f:
                protocols = json.load(f)

            all_intelligence = {}
            scanned_count = 0
            error_count = 0

            for protocol in protocols.get('protocols', []):
                protocol_name = protocol.get('protocol_name', 'Unknown')

                try:
                    self.logger.info(f"Scanning contracts for {protocol_name}")
                    intelligence = self.scan_protocol_contracts(protocol)

                    if intelligence:
                        all_intelligence[protocol_name] = intelligence
                        scanned_count += len(intelligence)
                        self.logger.info(f"Found {len(intelligence)} contracts for {protocol_name}")
                    else:
                        self.logger.warning(f"No contracts found for {protocol_name}")

                except Exception as e:
                    error_count += 1
                    self.logger.error(f"Error scanning {protocol_name}: {e}")

            # Save results
            result = {
                'scan_metadata': {
                    'scan_date': datetime.now().isoformat(),
                    'total_protocols': len(protocols.get('protocols', [])),
                    'scanned_protocols': len(all_intelligence),
                    'total_contracts': scanned_count,
                    'errors': error_count
                },
                'contract_intelligence': all_intelligence
            }

            # Save to database
            output_file = f"contract_intelligence_database_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)

            self.logger.info(f"Contract scanning completed. Results saved to {output_file}")
            return result

        except Exception as e:
            self.logger.error(f"Error scanning database contracts: {e}")
            return {}

    def run(self) -> bool:
        """Run contract scanner"""
        try:
            self.logger.info("Starting contract scanner")

            # Scan database contracts
            result = self.scan_database_contracts()

            if result and result.get('scan_metadata', {}).get('total_contracts', 0) > 0:
                self.logger.info(f"Contract scanning completed successfully. Found {result['scan_metadata']['total_contracts']} contracts.")
                return True
            else:
                self.logger.warning("Contract scanning completed but no contracts found")
                return False

        except Exception as e:
            error_data = handle_error(e, "ContractScanner")
            self.logger.error(f"Contract scanner failed: {e}")
            return False


def main():
    """Main function to run contract scanner"""
    scanner = ContractScanner()
    success = scanner.run()
    scanner.cleanup()
    exit(0 if success else 1)


if __name__ == "__main__":
    main()