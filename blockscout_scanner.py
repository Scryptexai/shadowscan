#!/usr/bin/env python3
"""
Blockscout Scanner for DEFI/DEX Contract Discovery
Scans Blockscout API to discover DEFI/DEX contracts with TVL and active transactions
"""

import json
import requests
import time
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from core.database import database

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BlockscoutScanner:
    """Scanner for discovering DEFI/DEX contracts using Blockscout API"""

    def __init__(self, user_agent: str = "ShadowScan/1.0"):
        self.user_agent = user_agent
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'application/json'
        })

        # Contract categories to search for
        self.defi_categories = [
            "DEX", "LENDING", "STABLECOIN", "YIELD_OPTIMIZER",
            "STAKING", "BRIDGE", "SWAP", "AGGREGATOR"
        ]

        # Contract keywords for filtering
        self.defi_keywords = [
            "uniswap", "sushi", "curve", "aave", "compound", "balancer",
            "pancake", "quick", "trader", "benqi", "maker", "convex",
            "yearn", "lynpo", "venus", "arbitrum", "optimism"
        ]

    def get_chain_config(self, chain_name: str) -> Optional[Dict[str, Any]]:
        """Get chain configuration from target list"""
        try:
            with open('defi_target_list.json', 'r') as f:
                data = json.load(f)
                return data.get('defi_targets', {}).get(chain_name)
        except Exception as e:
            logger.error(f"Error loading chain config for {chain_name}: {e}")
            return None

    def scan_contracts_by_keyword(self, blockscout_url: str, keyword: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Scan contracts by keyword using Blockscout API"""
        try:
            # Search contracts by name
            search_url = f"{blockscout_url}/api/v2/search?q={keyword}&type=contract"

            response = self.session.get(search_url, timeout=30)
            response.raise_for_status()

            data = response.json()
            contracts = data.get('contracts', [])

            filtered_contracts = []
            for contract in contracts[:limit]:
                if self._is_defi_contract(contract):
                    contract_info = self._extract_contract_info(contract, keyword)
                    if contract_info:
                        filtered_contracts.append(contract_info)

            return filtered_contracts

        except Exception as e:
            logger.error(f"Error scanning contracts with keyword '{keyword}': {e}")
            return []

    def _is_defi_contract(self, contract: Dict[str, Any]) -> bool:
        """Check if contract is related to DEFI/DEX"""
        try:
            # Check contract name
            name = contract.get('name', '').lower()

            # Check contract tags
            tags = [tag.lower() for tag in contract.get('tags', [])]

            # Check if it has DEFI-related keywords
            defi_indicators = [
                'defi', 'dex', 'swap', 'lend', 'borrow', 'pool',
                'yield', 'farm', 'stake', 'bridge', 'token'
            ]

            # Check name contains defi keywords
            for keyword in self.defi_keywords:
                if keyword in name:
                    return True

            # Check tags contain defi indicators
            for indicator in defi_indicators:
                if any(indicator in tag for tag in tags):
                    return True

            return False

        except Exception as e:
            logger.error(f"Error checking if contract is DEFI: {e}")
            return False

    def _extract_contract_info(self, contract: Dict[str, Any], source_keyword: str) -> Optional[Dict[str, Any]]:
        """Extract relevant contract information"""
        try:
            contract_info = {
                'address': contract.get('address'),
                'name': contract.get('name'),
                'description': contract.get('description', ''),
                'category': self._classify_contract(contract),
                'tags': contract.get('tags', []),
                'is_verified': contract.get('is_verified', False),
                'implementation': contract.get('implementation', {}),
                'functions_count': len(contract.get('function_sigs', [])),
                'creation_tx_hash': contract.get('creation_tx_hash'),
                'creator_address': contract.get('creator_address'),
                'bytecode_hash': contract.get('bytecode_hash'),
                'abi_hash': contract.get('abi_hash'),
                'source_code_verified': contract.get('source_code_verified', False),
                'source_code': contract.get('source_code_url', ''),
                'audit_count': contract.get('audit_count', 0),
                'security_reviews': contract.get('security_reviews', []),
                'last_updated': contract.get('updated_at'),
                'source_keyword': source_keyword
            }

            return contract_info

        except Exception as e:
            logger.error(f"Error extracting contract info: {e}")
            return None

    def _classify_contract(self, contract: Dict[str, Any]) -> str:
        """Classify contract by DEFI category"""
        try:
            name = contract.get('name', '').lower()
            tags = [tag.lower() for tag in contract.get('tags', [])]

            # Classification logic
            if any(exchange in name for exchange in ['uniswap', 'sushi', 'quick', 'pancake', 'trader']):
                return 'DEX'
            elif any(lending in name for lending in ['aave', 'compound', 'venus']):
                return 'LENDING'
            elif any(stable in name for stable in ['maker', 'dai', 'stable']):
                return 'STABLECOIN'
            elif any(yield_opt in name for yield_opt in ['convex', 'yearn', 'lynpo']):
                return 'YIELD_OPTIMIZER'
            elif any(staking in name for staking in ['benqi', 'stake']):
                return 'STAKING'
            elif any(bridge in name for bridge in ['bridge', 'multichain']):
                return 'BRIDGE'
            elif any(swap in name for swap in ['swap', 'exchange']):
                return 'SWAP'
            elif any(agg in name for agg in ['aggregator', 'flash']):
                return 'AGGREGATOR'
            else:
                return 'UNKNOWN'

        except Exception as e:
            logger.error(f"Error classifying contract: {e}")
            return 'UNKNOWN'

    def get_contract_transfers(self, blockscout_url: str, contract_address: str, days: int = 30) -> Dict[str, Any]:
        """Get contract transfer activity for TVL estimation"""
        try:
            # Get recent transfers
            transfers_url = f"{blockscout_url}/api/v2/addresses/{contract_address}/transfers"

            params = {
                'type': 'token',
                'limit': 1000,
                'block_number_gt': 0
            }

            response = self.session.get(transfers_url, params=params, timeout=30)
            response.raise_for_status()

            data = response.json()
            transfers = data.get('transfers', [])

            # Analyze transfer patterns
            total_transfers = len(transfers)
            unique_addresses = len(set(t.get('to_address') for t in transfers))
            unique_from_addresses = len(set(t.get('from_address') for t in transfers))

            return {
                'total_transfers': total_transfers,
                'unique_addresses': unique_addresses,
                'unique_from_addresses': unique_from_addresses,
                'activity_score': min(total_transfers / 1000, 10),  # Normalize score 0-10
                'days_analyzed': days
            }

        except Exception as e:
            logger.error(f"Error getting transfers for {contract_address}: {e}")
            return {
                'total_transfers': 0,
                'unique_addresses': 0,
                'unique_from_addresses': 0,
                'activity_score': 0,
                'days_analyzed': days
            }

    def scan_chain(self, chain_name: str, min_activity_score: float = 1.0) -> List[Dict[str, Any]]:
        """Scan a specific chain for DEFI/DEX contracts"""
        logger.info(f"Starting scan for chain: {chain_name}")

        chain_config = self.get_chain_config(chain_name)
        if not chain_config:
            logger.error(f"No configuration found for chain: {chain_name}")
            return []

        blockscout_url = chain_config.get('blockscout_api')
        if not blockscout_url:
            logger.error(f"No Blockscout API URL found for chain: {chain_name}")
            return []

        discovered_contracts = []

        # Scan with each keyword
        for keyword in self.defi_keywords:
            logger.info(f"Scanning with keyword: {keyword}")
            contracts = self.scan_contracts_by_keyword(blockscout_url, keyword, limit=50)

            for contract in contracts:
                # Check activity score
                activity_info = self.get_contract_transfers(blockscout_url, contract['address'])

                if activity_info['activity_score'] >= min_activity_score:
                    # Add activity info to contract
                    contract['activity_info'] = activity_info
                    contract['discovered_at'] = datetime.now().isoformat()
                    contract['chain_name'] = chain_name
                    contract['chain_id'] = chain_config.get('chain_id')

                    discovered_contracts.append(contract)

            # Rate limiting
            time.sleep(1)

        # Remove duplicates
        unique_contracts = self._remove_duplicates(discovered_contracts)

        logger.info(f"Discovered {len(unique_contracts)} contracts for {chain_name}")
        return unique_contracts

    def _remove_duplicates(self, contracts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate contracts based on address"""
        seen_addresses = set()
        unique_contracts = []

        for contract in contracts:
            address = contract.get('address')
            if address and address not in seen_addresses:
                seen_addresses.add(address)
                unique_contracts.append(contract)

        return unique_contracts

    def save_to_database(self, contracts: List[Dict[str, Any]], scan_type: str = "BLOCKSCOUT_DISCOVERY") -> bool:
        """Save discovered contracts to database"""
        try:
            for contract in contracts:
                # Prepare contract data for database
                contract_data = {
                    'address': contract.get('address'),
                    'name': contract.get('name'),
                    'description': contract.get('description', ''),
                    'category': contract.get('category', 'UNKNOWN'),
                    'chain_id': contract.get('chain_id'),
                    'chain_name': contract.get('chain_name'),
                    'is_verified': contract.get('is_verified', False),
                    'functions_count': contract.get('functions_count', 0),
                    'activity_score': contract.get('activity_info', {}).get('activity_score', 0),
                    'total_transfers': contract.get('activity_info', {}).get('total_transfers', 0),
                    'unique_addresses': contract.get('activity_info', {}).get('unique_addresses', 0),
                    'discovered_at': contract.get('discovered_at'),
                    'source_keyword': contract.get('source_keyword'),
                    'scan_type': scan_type,
                    'tags': contract.get('tags', []),
                    'source_code': contract.get('source_code', ''),
                    'last_updated': datetime.now().isoformat()
                }

                # Add to database
                database.add_contract(contract_data)

            logger.info(f"Saved {len(contracts)} contracts to database")
            return True

        except Exception as e:
            logger.error(f"Error saving contracts to database: {e}")
            return False

    def scan_all_chains(self, min_activity_score: float = 1.0) -> Dict[str, Any]:
        """Scan all configured chains"""
        results = {}

        try:
            with open('defi_target_list.json', 'r') as f:
                data = json.load(f)
                chains = list(data.get('defi_targets', {}).keys())

            for chain_name in chains:
                logger.info(f"Scanning chain: {chain_name}")
                contracts = self.scan_chain(chain_name, min_activity_score)

                if contracts:
                    results[chain_name] = {
                        'contracts_count': len(contracts),
                        'contracts': contracts,
                        'scan_completed': True,
                        'scan_time': datetime.now().isoformat()
                    }

                    # Save to database
                    self.save_to_database(contracts, f"BLOCKSCOUT_{chain_name.upper()}")
                else:
                    results[chain_name] = {
                        'contracts_count': 0,
                        'contracts': [],
                        'scan_completed': True,
                        'scan_time': datetime.now().isoformat()
                    }

            return results

        except Exception as e:
            logger.error(f"Error scanning all chains: {e}")
            return {}

def main():
    """Main execution function"""
    scanner = BlockscoutScanner()

    # Scan all chains
    results = scanner.scan_all_chains(min_activity_score=0.5)

    # Print results
    print("\n📊 Blockscout Scan Results:")
    print("=" * 50)

    for chain_name, result in results.items():
        print(f"\n🔗 Chain: {chain_name}")
        print(f"   Discovered Contracts: {result['contracts_count']}")
        print(f"   Scan Time: {result['scan_time']}")

        if result['contracts']:
            print("   Top Contracts:")
            for i, contract in enumerate(result['contracts'][:5]):
                print(f"     {i+1}. {contract.get('name', 'Unknown')} ({contract.get('category', 'UNKNOWN')})")
                print(f"        Address: {contract.get('address')}")
                print(f"        Activity Score: {contract.get('activity_info', {}).get('activity_score', 0):.2f}")
                print(f"        Transfers: {contract.get('activity_info', {}).get('total_transfers', 0)}")

if __name__ == "__main__":
    main()