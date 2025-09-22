#!/usr/bin/env python3
"""
Phase 1: DEFI/DEX Discovery and Collection
Scan and collect new DEFI/DEX websites on emerging blockchains
Check protocol age, maturity, and categorization
"""

import json
import time
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from bs4 import BeautifulSoup
import re
import logging
from urllib.parse import urljoin, urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Phase1DiscoveryScanner:
    """Phase 1: DEFI/DEX Discovery Scanner"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

        # Load configuration
        self.load_config()

        # Discovery sources
        self.discovery_sources = {
            'blockchain_explorers': [
                'https://storyscan.co',
                'https://berascan.com',
                'https://shiden.blockscout.com',
                'https://karura.subscan.io',
                'https://moonbeam.subscan.io',
                'https://scope.klaytn.com',
                'https://evmexplorer.velas.com',
                'https://bifrostscan.io',
                'https://subscan.io/account',
                'https://scan.tomochain.com'
            ],
            'defi_aggregators': [
                'https://defillama.com',
                'https://defipulse.com',
                'https://dappradar.com'
            ],
            'social_media_sources': [
                'https://twitter.com/hashtag/defi',
                'https://twitter.com/hashtag/dex',
                'https://discord.com/channels',
                'https://t.me'
            ],
            'news_sources': [
                'https://cryptopanic.com',
                'https://coindesk.com',
                'https://theblock.co',
                'https://defiprime.com'
            ]
        }

        # Protocol keywords for categorization
        self.protocol_keywords = {
            'DEX': ['swap', 'exchange', 'trading', 'marketplace', 'dex', 'uniswap', 'pancakeswap', 'sushiswap'],
            'LENDING': ['lend', 'borrow', 'credit', 'debt', 'interest', 'aave', 'compound', 'maker'],
            'YIELD': ['farm', 'yield', 'staking', 'reward', 'ap', 'apr', 'vault', 'gauge'],
            'BRIDGE': ['bridge', 'crosschain', 'multichain', 'tokenbridge', 'warp', 'hop'],
            'NFT': ['nft', 'nft marketplace', 'nft lending', 'nft fractional', 'nft rental'],
            'STABLECOIN': ['stable', 'peg', 'usd', 'dai', 'usdc', 'tusd', 'frax'],
            'DERIVATIVES': ['option', 'future', 'perpetual', 'swap', 'synthetic'],
            'INSURANCE': ['insurance', 'protection', 'coverage', 'nexus', 'mutual'],
            'WALLET': ['wallet', 'custody', 'non-custodial', 'multisig', 'smart wallet'],
            'ORACLE': ['oracle', 'data', 'feed', 'price', 'chainlink', 'band']
        }

    def load_config(self):
        """Load scanning configuration"""
        try:
            with open('structured_scanning_config.json', 'r') as f:
                config = json.load(f)
                self.emerging_blockchains = config['emerging_blockchains']
                self.phase_config = config['phase_definitions']['phase_1']
        except FileNotFoundError:
            logger.error("❌ Configuration file not found")
            self.emerging_blockchains = []
            self.phase_config = {}

    def run_discovery_scan(self) -> Dict[str, Any]:
        """Run complete Phase 1 discovery scan"""
        print("🚀 PHASE 1: DEFI/DEX Discovery and Collection")
        print("="*70)
        print("🎯 Objective: Scan and collect new DEFI/DEX websites")
        print("📊 Target: Emerging blockchains with new protocols")
        print("="*70)

        discovery_results = {
            'scan_metadata': {
                'scan_date': datetime.now().isoformat(),
                'scan_phase': 'phase_1',
                'scan_tool': 'Phase1DiscoveryScanner',
                'total_sources': len(self.discovery_sources),
                'total_chains': len(self.emerging_blockchains)
            },
            'protocols': [],
            'discovered_websites': [],
            'chain_coverage': {},
            'categories_found': []
        }

        # Step 1: Scan blockchain explorers
        print("\n🔍 Step 1: Scanning blockchain explorers...")
        explorer_results = self.scan_blockchain_explorers()
        discovery_results['discovered_websites'].extend(explorer_results)

        # Step 2: Scan DEFI aggregators
        print("\n🔍 Step 2: Scanning DEFI aggregators...")
        aggregator_results = self.scan_defi_aggregators()
        discovery_results['discovered_websites'].extend(aggregator_results)

        # Step 3: Social media monitoring
        print("\n🔍 Step 3: Social media monitoring...")
        social_results = self.scan_social_media()
        discovery_results['discovered_websites'].extend(social_results)

        # Step 4: News sources
        print("\n🔍 Step 4: News source monitoring...")
        news_results = self.scan_news_sources()
        discovery_results['discovered_websites'].extend(news_results)

        # Step 5: Process and categorize discovered protocols
        print("\n🔍 Step 5: Processing and categorizing protocols...")
        processed_protocols = self.process_discovered_protocols(discovery_results['discovered_websites'])
        discovery_results['protocols'] = processed_protocols

        # Step 6: Analyze chain coverage
        discovery_results['chain_coverage'] = self.analyze_chain_coverage(processed_protocols)

        # Step 7: Generate final report
        self.generate_phase1_report(discovery_results)

        return discovery_results

    def scan_blockchain_explorers(self) -> List[Dict[str, Any]]:
        """Scan blockchain explorers for new DEFI/DEX protocols"""
        results = []

        for explorer_url in self.discovery_sources['blockchain_explorers']:
            try:
                print(f"   🌐 Scanning: {explorer_url}")

                # Try different search patterns
                search_patterns = [
                    '/api/v2/search?q=defi&type=contract',
                    '/api/v2/search?q=dex&type=contract',
                    '/api/v2/search?q=swap&type=contract',
                    '/api/v2/search?q=lend&type=contract',
                    '/api/v2/search?q=farm&type=contract'
                ]

                for pattern in search_patterns:
                    try:
                        search_url = urljoin(explorer_url, pattern)
                        response = self.session.get(search_url, timeout=30)

                        if response.status_code == 200:
                            data = response.json()
                            contracts = data.get('contracts', [])

                            for contract in contracts:
                                protocol_info = self.extract_protocol_info(contract, explorer_url)
                                if protocol_info:
                                    results.append(protocol_info)
                                    logger.info(f"   ✅ Found: {protocol_info['protocol_name']}")

                        time.sleep(1)  # Rate limiting
                        break

                    except Exception as e:
                        logger.warning(f"⚠️ Failed {pattern}: {e}")
                        continue

            except Exception as e:
                logger.error(f"❌ Error scanning {explorer_url}: {e}")

        return results

    def scan_defi_aggregators(self) -> List[Dict[str, Any]]:
        """Scan DEFI aggregators for new protocols"""
        results = []

        for aggregator_url in self.discovery_sources['defi_aggregators']:
            try:
                print(f"   📊 Scanning: {aggregator_url}")

                # Try to get protocol lists
                response = self.session.get(aggregator_url, timeout=30)

                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')

                    # Extract protocol links and information
                    protocol_links = soup.find_all('a', href=True)

                    for link in protocol_links:
                        href = link.get('href', '')
                        if any(keyword in href.lower() for keyword in ['defi', 'dex', 'protocol', 'project']):
                            protocol_info = self.extract_aggregator_protocol(href, aggregator_url)
                            if protocol_info:
                                results.append(protocol_info)
                                logger.info(f"   ✅ Found: {protocol_info['protocol_name']}")

                time.sleep(2)

            except Exception as e:
                logger.error(f"❌ Error scanning {aggregator_url}: {e}")

        return results

    def scan_social_media(self) -> List[Dict[str, Any]]:
        """Scan social media for new protocol announcements"""
        results = []

        # Simulated social media scanning (would normally use API)
        social_keywords = [
            'new defi protocol', 'launch', 'announcement', 'beta', 'testnet',
            'partnership', 'integration', 'defi project', 'dex launch'
        ]

        for keyword in social_keywords:
            try:
                print(f"   💬 Searching: {keyword}")

                # Simulated search results
                # In real implementation, would use Twitter API, Discord API, etc.
                time.sleep(1)

            except Exception as e:
                logger.error(f"❌ Error searching {keyword}: {e}")

        return results

    def scan_news_sources(self) -> List[Dict[str, Any]]:
        """Scan news sources for new protocol announcements"""
        results = []

        for news_url in self.discovery_sources['news_sources']:
            try:
                print(f"   📰 Scanning: {news_url}")

                response = self.session.get(news_url, timeout=30)

                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')

                    # Extract article content and look for protocol mentions
                    articles = soup.find_all('article') or soup.find_all('div', class_='article')

                    for article in articles[:5]:  # Limit to avoid overload
                        text = article.get_text().lower()
                        if any(keyword in text for keyword in ['defi', 'protocol', 'launch', 'new']):
                            protocol_info = self.extract_news_protocol(article, news_url)
                            if protocol_info:
                                results.append(protocol_info)
                                logger.info(f"   ✅ Found: {protocol_info['protocol_name']}")

                time.sleep(2)

            except Exception as e:
                logger.error(f"❌ Error scanning {news_url}: {e}")

        return results

    def extract_protocol_info(self, contract: Dict[str, Any], source_url: str) -> Optional[Dict[str, Any]]:
        """Extract protocol information from contract data"""
        try:
            # Extract basic contract information
            protocol_name = contract.get('name', f"Protocol_{contract.get('address', 'unknown')[:8]}")

            # Determine blockchain from source URL
            blockchain = self.determine_blockchain_from_url(source_url)
            chain_id = self.get_chain_id(blockchain)

            # Categorize protocol
            category = self.categorize_protocol(protocol_name, contract.get('abi', []))
            maturity_level = self.assess_maturity(protocol_name, blockchain)

            protocol_info = {
                'protocol_name': protocol_name,
                'website': '',
                'blockchain': blockchain,
                'chain_id': chain_id,
                'category': category,
                'subcategory': '',
                'maturity_level': maturity_level,
                'age_months': self.calculate_protocol_age(protocol_name),
                'risk_level': self.assess_risk_level(maturity_level, category),
                'keywords': self.extract_keywords(protocol_name, contract),
                'social_media': {},
                'discovery_source': source_url,
                'discovery_date': datetime.now().isoformat(),
                'last_updated': datetime.now().isoformat()
            }

            return protocol_info

        except Exception as e:
            logger.error(f"❌ Error extracting protocol info: {e}")
            return None

    def determine_blockchain_from_url(self, url: str) -> str:
        """Determine blockchain from URL"""
        url_lower = url.lower()

        blockchain_mapping = {
            'story': 'story_protocol',
            'bera': 'berachain',
            'shiden': 'shiden',
            'karura': 'karura',
            'moonbeam': 'moonbeam',
            'klaytn': 'klaytn',
            'velas': 'velas',
            'bifrost': 'bifrost',
            'astar': 'astar',
            'tomochain': 'tomochain'
        }

        for key, blockchain in blockchain_mapping.items():
            if key in url_lower:
                return blockchain

        return 'unknown'

    def get_chain_id(self, blockchain: str) -> int:
        """Get chain ID for blockchain"""
        chain_mapping = {
            'story_protocol': 1514,
            'berachain': 80085,
            'shiden': 336,
            'karura': 686,
            'moonbeam': 1284,
            'klaytn': 8217,
            'velas': 106,
            'bifrost': 2047,
            'astar': 60805,
            'tomochain': 88
        }

        return chain_mapping.get(blockchain, 0)

    def categorize_protocol(self, protocol_name: str, abi: List[str]) -> str:
        """Categorize protocol based on name and ABI"""
        name_lower = protocol_name.lower()
        abi_str = str(abi).lower()

        # Check for specific patterns
        category_patterns = {
            'DEX': ['swap', 'exchange', 'trading', 'market'],
            'LENDING': ['lend', 'borrow', 'credit', 'debt'],
            'YIELD': ['farm', 'yield', 'staking', 'vault', 'gauge'],
            'BRIDGE': ['bridge', 'crosschain', 'multichain'],
            'NFT': ['nft', 'nft marketplace', 'nft lending'],
            'STABLECOIN': ['stable', 'peg', 'usd'],
            'DERIVATIVES': ['option', 'future', 'perpetual'],
            'INSURANCE': ['insurance', 'protection', 'coverage'],
            'WALLET': ['wallet', 'custody'],
            'ORACLE': ['oracle', 'data', 'feed']
        }

        # Check name first
        for category, patterns in category_patterns.items():
            if any(pattern in name_lower for pattern in patterns):
                return category

        # Check ABI if name doesn't match
        for category, patterns in category_patterns.items():
            if any(pattern in abi_str for pattern in patterns):
                return category

        return 'UNKNOWN'

    def assess_maturity(self, protocol_name: str, blockchain: str) -> str:
        """Assess protocol maturity level"""
        # New protocols often have version numbers, beta, testnet in name
        name_lower = protocol_name.lower()

        if any(term in name_lower for term in ['beta', 'testnet', 'v1', 'version', 'new']):
            return 'NEW'
        elif any(term in name_lower for term in ['alpha', 'prototype', 'demo']):
            return 'EMERGING'
        elif any(term in name_lower for term in ['mature', 'stable', 'production']):
            return 'GROWING'
        else:
            return 'EMERGING'

    def calculate_protocol_age(self, protocol_name: str) -> int:
        """Calculate protocol age in months (simulated)"""
        # In real implementation, would check launch dates, GitHub creation, etc.
        # For now, use naming patterns
        name_lower = protocol_name.lower()

        if any(term in name_lower for term in ['new', 'beta', 'testnet', 'v1']):
            return 1  # Very new
        elif any(term in name_lower for term in ['v2', 'version 2', 'mature']):
            return 6  # 6 months
        else:
            return 3  # Default 3 months

    def assess_risk_level(self, maturity: str, category: str) -> str:
        """Assess risk level based on maturity and category"""
        risk_matrix = {
            'DEX': {'NEW': 'CRITICAL', 'EMERGING': 'HIGH', 'GROWING': 'MEDIUM'},
            'LENDING': {'NEW': 'CRITICAL', 'EMERGING': 'CRITICAL', 'GROWING': 'HIGH'},
            'YIELD': {'NEW': 'HIGH', 'EMERGING': 'MEDIUM', 'GROWING': 'MEDIUM'},
            'BRIDGE': {'NEW': 'CRITICAL', 'EMERGING': 'HIGH', 'GROWING': 'HIGH'},
            'NFT': {'NEW': 'HIGH', 'EMERGING': 'MEDIUM', 'GROWING': 'LOW'},
            'STABLECOIN': {'NEW': 'HIGH', 'EMERGING': 'HIGH', 'GROWING': 'MEDIUM'},
            'DERIVATIVES': {'NEW': 'CRITICAL', 'EMERGING': 'CRITICAL', 'GROWING': 'HIGH'},
            'INSURANCE': {'NEW': 'HIGH', 'EMERGING': 'HIGH', 'GROWING': 'MEDIUM'},
            'WALLET': {'NEW': 'CRITICAL', 'EMERGING': 'HIGH', 'GROWING': 'HIGH'},
            'ORACLE': {'NEW': 'CRITICAL', 'EMERGING': 'CRITICAL', 'GROWING': 'HIGH'}
        }

        return risk_matrix.get(category, {'NEW': 'HIGH', 'EMERGING': 'MEDIUM', 'GROWING': 'LOW'})[maturity]

    def extract_keywords(self, protocol_name: str, contract: Dict[str, Any]) -> List[str]:
        """Extract keywords from protocol name and contract data"""
        keywords = []
        name_lower = protocol_name.lower()
        contract_str = str(contract).lower()

        # Extract keywords from name
        for category, patterns in self.protocol_keywords.items():
            for pattern in patterns:
                if pattern in name_lower:
                    keywords.append(pattern)

        # Extract keywords from contract data
        function_names = contract.get('abi', [])
        for func in function_names:
            if isinstance(func, dict) and func.get('type') == 'function':
                func_name = func.get('name', '').lower()
                if any(pattern in func_name for pattern in self.protocol_keywords['DEX']):
                    keywords.append(func_name)

        return list(set(keywords))

    def extract_aggregator_protocol(self, href: str, source_url: str) -> Optional[Dict[str, Any]]:
        """Extract protocol information from aggregator links"""
        try:
            # Extract protocol name from URL
            url_parts = href.split('/')
            protocol_name = url_parts[-1] if url_parts else 'Unknown'

            # Basic protocol info
            protocol_info = {
                'protocol_name': protocol_name,
                'website': href,
                'blockchain': self.determine_blockchain_from_url(href),
                'chain_id': 0,  # Would need to be determined
                'category': 'DEFI',
                'subcategory': 'AGGREGATOR',
                'maturity_level': 'EMERGING',
                'age_months': 2,
                'risk_level': 'MEDIUM',
                'keywords': self.extract_keywords(protocol_name, {}),
                'social_media': {},
                'discovery_source': source_url,
                'discovery_date': datetime.now().isoformat(),
                'last_updated': datetime.now().isoformat()
            }

            return protocol_info

        except Exception as e:
            logger.error(f"❌ Error extracting aggregator protocol: {e}")
            return None

    def extract_news_protocol(self, article: Any, source_url: str) -> Optional[Dict[str, Any]]:
        """Extract protocol information from news articles"""
        try:
            # Extract text from article
            text = article.get_text().strip()

            # Simple keyword-based protocol extraction
            if 'defi' in text.lower() or 'protocol' in text.lower():
                protocol_name = f"NewsProtocol_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

                protocol_info = {
                    'protocol_name': protocol_name,
                    'website': source_url,
                    'blockchain': 'unknown',
                    'chain_id': 0,
                    'category': 'NEWS_MENTIONED',
                    'subcategory': '',
                    'maturity_level': 'UNKNOWN',
                    'age_months': 0,
                    'risk_level': 'LOW',
                    'keywords': ['news', 'announcement', 'defi'],
                    'social_media': {},
                    'discovery_source': source_url,
                    'discovery_date': datetime.now().isoformat(),
                    'last_updated': datetime.now().isoformat()
                }

                return protocol_info

        except Exception as e:
            logger.error(f"❌ Error extracting news protocol: {e}")
            return None

    def process_discovered_protocols(self, websites: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process and deduplicate discovered protocols"""
        protocols = []
        seen_names = set()

        for website in websites:
            protocol_name = website.get('protocol_name', '')

            # Skip duplicates
            if protocol_name in seen_names:
                continue

            seen_names.add(protocol_name)
            protocols.append(website)

        # Remove protocols with unknown blockchain
        protocols = [p for p in protocols if p.get('blockchain') != 'unknown']

        return protocols

    def analyze_chain_coverage(self, protocols: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze blockchain coverage of discovered protocols"""
        coverage = {}

        for protocol in protocols:
            blockchain = protocol.get('blockchain', 'unknown')

            if blockchain not in coverage:
                coverage[blockchain] = {
                    'protocol_count': 0,
                    'categories': set(),
                    'risk_levels': {}
                }

            coverage[blockchain]['protocol_count'] += 1
            coverage[blockchain]['categories'].add(protocol.get('category', 'UNKNOWN'))

            risk_level = protocol.get('risk_level', 'UNKNOWN')
            coverage[blockchain]['risk_levels'][risk_level] = coverage[blockchain]['risk_levels'].get(risk_level, 0) + 1

        # Convert sets to lists for JSON serialization
        for blockchain in coverage:
            coverage[blockchain]['categories'] = list(coverage[blockchain]['categories'])

        return coverage

    def generate_phase1_report(self, discovery_results: Dict[str, Any]):
        """Generate Phase 1 discovery report"""
        print(f"\n📊 PHASE 1 DISCOVERY RESULTS")
        print("="*50)

        protocols = discovery_results['protocols']
        metadata = discovery_results['scan_metadata']
        coverage = discovery_results['chain_coverage']

        print(f"🎯 Total Protocols Discovered: {len(protocols)}")
        print(f"🌐 Sources Scanned: {metadata['total_sources']}")
        print(f"⛓️  Chains Covered: {len(coverage)}")

        # Chain coverage breakdown
        print(f"\n🔗 Chain Coverage:")
        for blockchain, data in coverage.items():
            print(f"   {blockchain}: {data['protocol_count']} protocols")

        # Category breakdown
        categories = {}
        for protocol in protocols:
            category = protocol.get('category', 'UNKNOWN')
            categories[category] = categories.get(category, 0) + 1

        print(f"\n📋 Protocol Categories:")
        for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            print(f"   {category}: {count}")

        # Risk level breakdown
        risk_levels = {}
        for protocol in protocols:
            risk_level = protocol.get('risk_level', 'UNKNOWN')
            risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1

        print(f"\n⚠️  Risk Levels:")
        for risk_level, count in sorted(risk_levels.items(), key=lambda x: x[1], reverse=True):
            print(f"   {risk_level}: {count}")

        # Save results
        output_file = 'defi_discovery_database.json'
        with open(output_file, 'w') as f:
            json.dump(discovery_results, f, indent=2)

        print(f"\n✅ Results saved to: {output_file}")
        print(f"🎉 PHASE 1 COMPLETED SUCCESSFULLY!")

def main():
    """Main execution function"""
    scanner = Phase1DiscoveryScanner()
    results = scanner.run_discovery_scan()

    print(f"\n🚀 Phase 1 scanning completed with {len(results['protocols'])} protocols discovered")

if __name__ == "__main__":
    main()