#!/usr/bin/env python3
"""
Advanced DEFI/DEX Discovery Scanner
Focus on Router and LP contracts with vulnerability targeting
"""

import json
import requests
import time
import logging
import re
from typing import Dict, List, Any, Optional
from datetime import datetime
from core.database import database

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DEFIDiscoveryScanner:
    """Advanced scanner focused on Router and LP contracts"""

    def __init__(self, user_agent: str = "ShadowScan/1.0"):
        self.user_agent = user_agent
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'application/json'
        })

        # Enhanced router keywords
        self.router_keywords = [
            "router", "router_v2", "router_v3", "factory", "routerV2", "routerV3",
            "swap_router", "swapRouter", "exchange_router", "exchangeRouter",
            "pathfinder", "exchange", "swap", "multihop", "multiswap"
        ]

        # Enhanced LP/Pool keywords
        self.lp_keywords = [
            "liquidity", "pool", "v2", "v3", "factory", "pair", "pair_v2", "pair_v3",
            "liquidity_pool", "pool_v2", "pool_v3", "stable_swap", "curve_pool",
            "uniswap_v2", "uniswap_v3", "pancake_v2", "pancake_v3", "curve",
            "balancer", "balancer_v2", "sushi_v2", "sushi_v3"
        ]

        # Transaction controlling contract keywords
        self.control_keywords = [
            "controller", "manager", "governance", "admin", "owner", "timelock",
            "guardian", "circuit_breaker", "emergency", "pause", "unpause",
            "access_control", "role", "permission"
        ]

        # Vulnerability-indicating patterns
        self.vuln_patterns = [
            "reentrancy", "unchecked_call", "delegatecall", "onlyowner",
            "require(!emergency", "block.timestamp", "transfer.value",
            "flashloan", "flash_loan", "arbitrage", "manipulation"
        ]

    def get_chain_config(self, chain_name: str) -> Optional[Dict[str, Any]]:
        """Get chain configuration"""
        try:
            with open('defi_target_list.json', 'r') as f:
                data = json.load(f)
                return data.get('defi_targets', {}).get(chain_name)
        except Exception as e:
            logger.error(f"Error loading chain config for {chain_name}: {e}")
            return None

    def scan_contract_details(self, blockscout_url: str, contract_address: str) -> Dict[str, Any]:
        """Get detailed contract information"""
        try:
            # Get contract details
            details_url = f"{blockscout_url}/api/v2/contracts/{contract_address}"
            response = self.session.get(details_url, timeout=30)
            response.raise_for_status()

            return response.json()

        except Exception as e:
            logger.error(f"Error getting details for {contract_address}: {e}")
            return {}

    def analyze_contract_vulnerability_risk(self, contract: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze vulnerability risk of a contract"""
        risk_score = 0
        risk_factors = []

        name = contract.get('name', '').lower()
        description = (contract.get('description', '') or '').lower()
        source_code = contract.get('source_code', '').lower()

        # Check for router/risk patterns
        for keyword in self.router_keywords:
            if keyword in name or keyword in description:
                risk_score += 2
                risk_factors.append(f"Router pattern detected: {keyword}")
                break

        # Check for LP/pool patterns
        for keyword in self.lp_keywords:
            if keyword in name or keyword in description:
                risk_score += 2
                risk_factors.append(f"Liquidity pool detected: {keyword}")
                break

        # Check for transaction control
        for keyword in self.control_keywords:
            if keyword in name or keyword in description:
                risk_score += 1
                risk_factors.append(f"Control function detected: {keyword}")
                break

        # Check vulnerability indicators
        for pattern in self.vuln_patterns:
            if pattern in source_code:
                risk_score += 3
                risk_factors.append(f"Vulnerability pattern: {pattern}")

        # Risk assessment
        if risk_score >= 10:
            risk_level = "CRITICAL"
        elif risk_score >= 7:
            risk_level = "HIGH"
        elif risk_score >= 4:
            risk_level = "MEDIUM"
        elif risk_score >= 1:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'analysis_completed': True
        }

    def scan_contracts_by_category(self, blockscout_url: str, category: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Scan contracts by specific category"""
        try:
            category_keywords = {
                'router': self.router_keywords,
                'lp_pool': self.lp_keywords,
                'control': self.control_keywords
            }

            if category not in category_keywords:
                logger.error(f"Unknown category: {category}")
                return []

            keywords = category_keywords[category]
            discovered_contracts = []

            for keyword in keywords:
                logger.info(f"🔍 Scanning {category} with keyword: {keyword}")
                contracts = self.scan_contracts_by_keyword(blockscout_url, keyword, limit)

                for contract in contracts:
                    # Analyze vulnerability risk
                    risk_analysis = self.analyze_contract_vulnerability_risk(contract)
                    contract['risk_analysis'] = risk_analysis
                    contract['discovery_category'] = category
                    contract['discovery_keyword'] = keyword

                    discovered_contracts.append(contract)

                # Rate limiting
                time.sleep(1)

            return discovered_contracts

        except Exception as e:
            logger.error(f"Error scanning {category} contracts: {e}")
            return []

    def scan_contracts_by_keyword(self, blockscout_url: str, keyword: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Scan contracts by keyword"""
        try:
            search_url = f"{blockscout_url}/api/v2/search?q={keyword}&type=contract"

            response = self.session.get(search_url, timeout=30)
            response.raise_for_status()

            data = response.json()
            contracts = data.get('contracts', [])

            filtered_contracts = []
            for contract in contracts[:limit]:
                if self._is_target_contract(contract):
                    contract_info = self._extract_contract_info(contract, keyword)
                    if contract_info:
                        filtered_contracts.append(contract_info)

            return filtered_contracts

        except Exception as e:
            logger.error(f"Error scanning contracts with keyword '{keyword}': {e}")
            return []

    def _is_target_contract(self, contract: Dict[str, Any]) -> bool:
        """Check if contract is a target for vulnerability scanning"""
        try:
            name = contract.get('name', '').lower()
            description = (contract.get('description', '') or '').lower()

            # Target patterns
            target_indicators = [
                'router', 'swap', 'pool', 'pair', 'exchange', 'liquidity',
                'factory', 'controller', 'manager', 'admin', 'v2', 'v3'
            ]

            # Check if contract matches target patterns
            for indicator in target_indicators:
                if indicator in name or indicator in description:
                    return True

            return False

        except Exception as e:
            logger.error(f"Error checking target contract: {e}")
            return False

    def _extract_contract_info(self, contract: Dict[str, Any], source_keyword: str) -> Optional[Dict[str, Any]]:
        """Extract detailed contract information"""
        try:
            contract_info = {
                'address': contract.get('address'),
                'name': contract.get('name'),
                'description': contract.get('description', ''),
                'is_verified': contract.get('is_verified', False),
                'source_code': contract.get('source_code', ''),
                'abi': contract.get('abi', {}),
                'bytecode_hash': contract.get('bytecode_hash'),
                'creation_tx_hash': contract.get('creation_tx_hash'),
                'creator_address': contract.get('creator_address'),
                'implementation': contract.get('implementation', {}),
                'tags': contract.get('tags', []),
                'functions_count': len(contract.get('function_sigs', [])),
                'last_updated': contract.get('updated_at'),
                'discovery_keyword': source_keyword,
                'discovered_at': datetime.now().isoformat()
            }

            return contract_info

        except Exception as e:
            logger.error(f"Error extracting contract info: {e}")
            return None

    def get_contract_transactions(self, blockscout_url: str, contract_address: str, days: int = 30) -> Dict[str, Any]:
        """Get transaction activity data"""
        try:
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

            # Analyze transaction patterns
            total_transfers = len(transfers)
            unique_addresses = len(set(t.get('to_address') for t in transfers))
            unique_from_addresses = len(set(t.get('from_address') for t in transfers))

            # Calculate activity score
            activity_score = min(total_transfers / 1000, 10)  # Normalize to 0-10

            return {
                'total_transfers': total_transfers,
                'unique_addresses': unique_addresses,
                'unique_from_addresses': unique_from_addresses,
                'activity_score': activity_score,
                'days_analyzed': days,
                'transaction_volume': total_transfers
            }

        except Exception as e:
            logger.error(f"Error getting transactions for {contract_address}: {e}")
            return {
                'total_transfers': 0,
                'unique_addresses': 0,
                'unique_from_addresses': 0,
                'activity_score': 0,
                'days_analyzed': days,
                'transaction_volume': 0
            }

    def scan_chain_new_defi(self, chain_name: str, min_activity_score: float = 0.5) -> Dict[str, List[Dict[str, Any]]]:
        """Scan a chain for new DEFI/DEX contracts with focus on router and LP"""
        logger.info(f"🚀 Starting DEFI/DEX discovery scan for chain: {chain_name}")

        chain_config = self.get_chain_config(chain_name)
        if not chain_config:
            logger.error(f"No configuration found for chain: {chain_name}")
            return {}

        blockscout_url = chain_config.get('blockscout_api')
        if not blockscout_url:
            logger.error(f"No Blockscout API URL found for chain: {chain_name}")
            return {}

        discovered_contracts = {
            'router_contracts': [],
            'lp_pool_contracts': [],
            'control_contracts': [],
            'other_defi': []
        }

        # Scan router contracts
        logger.info("🔍 Scanning Router Contracts")
        router_contracts = self.scan_contracts_by_category(blockscout_url, 'router', limit=30)
        for contract in router_contracts:
            # Get transaction data
            tx_data = self.get_contract_transactions(blockscout_url, contract['address'])
            contract['transaction_data'] = tx_data

            if tx_data['activity_score'] >= min_activity_score:
                discovered_contracts['router_contracts'].append(contract)
                logger.info(f"✅ Found router contract: {contract['name']}")

        # Scan LP/pool contracts
        logger.info("🔍 Scanning LP/Pool Contracts")
        lp_contracts = self.scan_contracts_by_category(blockscout_url, 'lp_pool', limit=50)
        for contract in lp_contracts:
            # Get transaction data
            tx_data = self.get_contract_transactions(blockscout_url, contract['address'])
            contract['transaction_data'] = tx_data

            if tx_data['activity_score'] >= min_activity_score:
                discovered_contracts['lp_pool_contracts'].append(contract)
                logger.info(f"✅ Found LP contract: {contract['name']}")

        # Scan control contracts
        logger.info("🔍 Scanning Control Contracts")
        control_contracts = self.scan_contracts_by_category(blockscout_url, 'control', limit=30)
        for contract in control_contracts:
            # Get transaction data
            tx_data = self.get_contract_transactions(blockscout_url, contract['address'])
            contract['transaction_data'] = tx_data

            if tx_data['activity_score'] >= min_activity_score:
                discovered_contracts['control_contracts'].append(contract)
                logger.info(f"✅ Found control contract: {contract['name']}")

        # Scan other DEFI contracts
        logger.info("🔍 Scanning Other DEFI Contracts")
        other_defi = self.scan_contracts_by_keyword(blockscout_url, 'defi', limit=20)
        for contract in other_defi:
            if self._is_target_contract(contract):
                tx_data = self.get_contract_transactions(blockscout_url, contract['address'])
                contract['transaction_data'] = tx_data

                if tx_data['activity_score'] >= min_activity_score:
                    discovered_contracts['other_defi'].append(contract)
                    logger.info(f"✅ Found DEFI contract: {contract['name']}")

        return discovered_contracts

    def save_discovered_contracts(self, discovered_contracts: Dict[str, List[Dict[str, Any]]], chain_name: str) -> bool:
        """Save discovered contracts to database"""
        try:
            total_saved = 0

            for category, contracts in discovered_contracts.items():
                for contract in contracts:
                    # Prepare contract data for database
                    contract_data = {
                        'address': contract.get('address'),
                        'name': contract.get('name'),
                        'description': contract.get('description', ''),
                        'category': category.replace('_contracts', ''),
                        'chain_id': self.get_chain_config(chain_name).get('chain_id'),
                        'chain_name': chain_name,
                        'is_verified': contract.get('is_verified', False),
                        'functions_count': contract.get('functions_count', 0),
                        'discovery_keyword': contract.get('discovery_keyword'),
                        'discovery_category': contract.get('discovery_category'),
                        'activity_score': contract.get('transaction_data', {}).get('activity_score', 0),
                        'total_transfers': contract.get('transaction_data', {}).get('total_transfers', 0),
                        'unique_addresses': contract.get('transaction_data', {}).get('unique_addresses', 0),
                        'risk_score': contract.get('risk_analysis', {}).get('risk_score', 0),
                        'risk_level': contract.get('risk_analysis', {}).get('risk_level', 'UNKNOWN'),
                        'risk_factors': contract.get('risk_analysis', {}).get('risk_factors', []),
                        'discovered_at': contract.get('discovered_at'),
                        'scan_type': 'DEFI_DISCOVERY',
                        'last_updated': datetime.now().isoformat()
                    }

                    # Add to database
                    database.add_contract(contract_data)
                    total_saved += 1

                    logger.info(f"💾 Saved contract: {contract.get('name')} ({total_saved} total)")

            logger.info(f"✅ Saved {total_saved} contracts to database")
            return True

        except Exception as e:
            logger.error(f"Error saving contracts to database: {e}")
            return False

    def scan_all_chains_new_defi(self, min_activity_score: float = 0.5) -> Dict[str, Any]:
        """Scan all configured chains for new DEFI/DEX contracts"""
        results = {}

        try:
            with open('defi_target_list.json', 'r') as f:
                data = json.load(f)
                chains = list(data.get('defi_targets', {}).keys())

            for chain_name in chains:
                logger.info(f"🚀 Scanning chain: {chain_name}")
                discovered_contracts = self.scan_chain_new_defi(chain_name, min_activity_score)

                if any(discovered_contracts.values()):
                    results[chain_name] = {
                        'discovery_completed': True,
                        'scan_time': datetime.now().isoformat(),
                        'router_contracts': len(discovered_contracts['router_contracts']),
                        'lp_pool_contracts': len(discovered_contracts['lp_pool_contracts']),
                        'control_contracts': len(discovered_contracts['control_contracts']),
                        'other_defi': len(discovered_contracts['other_defi']),
                        'total_contracts': sum(len(contracts) for contracts in discovered_contracts.values()),
                        'contracts': discovered_contracts
                    }

                    # Save to database
                    self.save_discovered_contracts(discovered_contracts, chain_name)
                else:
                    results[chain_name] = {
                        'discovery_completed': True,
                        'scan_time': datetime.now().isoformat(),
                        'router_contracts': 0,
                        'lp_pool_contracts': 0,
                        'control_contracts': 0,
                        'other_defi': 0,
                        'total_contracts': 0,
                        'contracts': {}
                    }

                # Rate limiting between chains
                time.sleep(3)

            return results

        except Exception as e:
            logger.error(f"Error scanning all chains: {e}")
            return {}

def main():
    """Main execution function"""
    print("🚀 Starting Advanced DEFI/DEX Discovery Scanner")
    print("="*60)
    print("🎯 Focus: Router and LP contracts with vulnerability targeting")

    # Initialize scanner
    scanner = DEFIDiscoveryScanner()

    # Start discovery process
    results = scanner.scan_all_chains_new_defi(min_activity_score=0.3)

    # Print results
    print("\n📊 Discovery Results:")
    print("="*60)

    total_discovered = 0
    for chain_name, result in results.items():
        print(f"\n🔗 Chain: {chain_name}")
        print(f"   Discovery Completed: {result['discovery_completed']}")
        print(f"   Total Contracts: {result['total_contracts']}")
        print(f"   Router Contracts: {result['router_contracts']}")
        print(f"   LP Pool Contracts: {result['lp_pool_contracts']}")
        print(f"   Control Contracts: {result['control_contracts']}")
        print(f"   Other DEFI: {result['other_defi']}")

        total_discovered += result['total_contracts']

    print(f"\n🎯 Total Contracts Discovered: {total_discovered}")
    print("✅ Discovery completed successfully")

if __name__ == "__main__":
    main()