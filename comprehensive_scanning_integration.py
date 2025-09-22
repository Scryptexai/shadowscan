#!/usr/bin/env python3
"""
Comprehensive Scanning Integration
Integrates DEFI/DEX scanning and Token Contract scanning with the new methodology:
1. Get comprehensive DEFI/DEX lists first
2. Save all contracts to database
3. Scan vulnerabilities per contract specifically
4. Include token contract scanning
"""

import json
import time
from datetime import datetime
from typing import Dict, List, Any
from real_blockchain_scanner import RealBlockchainScanner
from token_contract_scanner import TokenContractScanner
from core.database import database
from vulnerability_scanner import VulnerabilityScanner

class ComprehensiveScanner:
    """Comprehensive scanner integrating all scanning methodologies"""

    def __init__(self):
        self.defi_scanner = RealBlockchainScanner()
        self.token_scanner = TokenContractScanner()
        self.vulnerability_scanner = VulnerabilityScanner()

    def run_comprehensive_scan(self) -> Dict[str, Any]:
        """Run comprehensive scan with new methodology"""
        print("🚀 COMPREHENSIVE SCANNING INTEGRATION")
        print("="*60)
        print("🎯 Methodology: Get DEFI lists → Save to database → Scan per contract → Token scanning")
        print("="*60)

        scan_results = {
            'start_time': datetime.now().isoformat(),
            'total_contracts': 0,
            'total_vulnerabilities': 0,
            'chains_scanned': [],
            'results': {}
        }

        # Step 1: Get comprehensive DEFI/DEX lists first
        print("\n📋 STEP 1: Get comprehensive DEFI/DEX lists")
        print("-" * 50)
        defi_contracts = self.get_comprehensive_defi_list()
        print(f"✅ Found {len(defi_contracts)} DEFI/DEX contracts")

        # Step 2: Save all contracts to database
        print("\n💾 STEP 2: Save all contracts to database")
        print("-" * 50)
        saved_contracts = self.save_contracts_to_database(defi_contracts)
        print(f"✅ Saved {saved_contracts} contracts to database")

        # Step 3: Scan vulnerabilities per contract specifically
        print("\n🔍 STEP 3: Scan vulnerabilities per contract specifically")
        print("-" * 50)
        vuln_results = self.scan_vulnerabilities_per_contract(saved_contracts)

        # Step 4: Token contract scanning
        print("\n🪙 STEP 4: Token contract scanning")
        print("-" * 50)
        token_results = self.scan_token_contracts()

        # Compile results
        scan_results['total_contracts'] = saved_contracts + len(token_results['tokens'])
        scan_results['total_vulnerabilities'] = vuln_results['total_vulns'] + token_results['total_vulns']
        scan_results['chains_scanned'] = ['ethereum_mainnet', 'polygon_mainnet', 'arbitrum_one', 'optimism', 'avalanche', 'bsc_mainnet']
        scan_results['results'] = {
            'defi_contracts': saved_contracts,
            'defi_vulnerabilities': vuln_results,
            'token_contracts': len(token_results['tokens']),
            'token_vulnerabilities': token_results
        }

        # Show final summary
        self.show_comprehensive_summary(scan_results)

        return scan_results

    def get_comprehensive_defi_list(self) -> List[Dict[str, Any]]:
        """Get comprehensive DEFI/DEX contract lists using new methodology"""
        all_contracts = []
        chains = ['ethereum_mainnet', 'polygon_mainnet', 'arbitrum_one', 'optimism', 'avalanche', 'bsc_mainnet']

        for chain in chains:
            try:
                print(f"🔍 Getting DEFI contracts on {chain}...")

                # Get DEFI/DEX specific contracts
                defi_contracts = self.defi_scanner.get_etherscan_contracts(chain, 'defi')
                all_contracts.extend(defi_contracts)

                # Get Blockscout contracts with DEFI keywords
                blockscout_contracts = self.defi_scanner.get_blockscout_contracts(
                    chain,
                    ['uniswap', 'pancakeswap', 'curve', 'balancer', 'aave', 'compound', 'sushiswap', 'maker'],
                    limit=15
                )
                all_contracts.extend(blockscout_contracts)

                print(f"   ✅ Found {len(defi_contracts) + len(blockscout_contracts)} contracts on {chain}")

                # Rate limiting
                time.sleep(2)

            except Exception as e:
                print(f"❌ Error getting contracts on {chain}: {e}")

        return all_contracts

    def save_contracts_to_database(self, contracts: List[Dict[str, Any]]) -> int:
        """Save all contracts to database"""
        total_saved = 0

        for contract in contracts:
            try:
                # Prepare contract data
                contract_data = {
                    'address': contract.get('address', ''),
                    'name': contract.get('name', 'Unknown Contract'),
                    'description': contract.get('description', 'DEFI contract'),
                    'category': contract.get('category', 'defi'),
                    'chain_name': contract.get('chain_name', 'unknown'),
                    'chain_id': contract.get('chain_id', 1),
                    'is_verified': contract.get('is_verified', False),
                    'functions_count': contract.get('functions_count', 0),
                    'risk_score': contract.get('risk_score', 1),
                    'risk_level': contract.get('risk_level', 'MINIMAL'),
                    'discovery_keyword': contract.get('discovery_keyword', ''),
                    'discovery_category': contract.get('discovery_category', ''),
                    'activity_score': contract.get('activity_score', 0),
                    'total_transfers': contract.get('total_transfers', 0),
                    'unique_addresses': contract.get('unique_addresses', 0),
                    'discovered_at': contract.get('discovered_at', datetime.now().isoformat()),
                    'scan_type': 'COMPREHENSIVE_SCAN',
                    'last_updated': datetime.now().isoformat()
                }

                # Add to database
                if database.add_contract(contract_data):
                    total_saved += 1
                    print(f"   💾 Saved: {contract_data['name']} ({contract_data['chain_name']})")

            except Exception as e:
                print(f"   ❌ Error saving contract: {e}")

        return total_saved

    def scan_vulnerabilities_per_contract(self, contracts) -> Dict[str, Any]:
        """Scan vulnerabilities per contract specifically"""
        total_vulns = 0
        vuln_by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        contract_results = {}

        for contract in contracts:
            try:
                print(f"🔎 Scanning vulnerabilities for: {contract['name']}")

                # Get enhanced contract data
                enhanced_contract = self.defi_scanner.enhance_contract_with_real_data(contract)

                # Scan specifically for this contract
                vulnerabilities = self.vulnerability_scanner.scan_contract_vulnerabilities(enhanced_contract)

                # Save vulnerabilities to database
                if vulnerabilities:
                    for vuln in vulnerabilities:
                        # Add contract reference
                        vuln['contract_address'] = contract['address']
                        vuln['contract_name'] = contract['name']
                        vuln['discovered_at'] = datetime.now().isoformat()
                        vuln['scan_type'] = 'COMPREHENSIVE_VULNERABILITY_SCAN'

                        database.add_vulnerability(vuln)

                        # Count by severity
                        severity = vuln.get('impact', 'LOW')
                        vuln_by_severity[severity] = vuln_by_severity.get(severity, 0) + 1
                        total_vulns += 1

                    print(f"   ✅ Found {len(vulnerabilities)} vulnerabilities")

                    contract_results[contract['address']] = {
                        'contract_name': contract['name'],
                        'vulnerability_count': len(vulnerabilities),
                        'vulnerabilities': vulnerabilities
                    }
                else:
                    print(f"   ✅ No vulnerabilities found")

                # Rate limiting
                time.sleep(1)

            except Exception as e:
                print(f"❌ Error scanning {contract.get('name', 'unknown')}: {e}")

        return {
            'total_vulns': total_vulns,
            'by_severity': vuln_by_severity,
            'contract_results': contract_results
        }

    def scan_token_contracts(self) -> Dict[str, Any]:
        """Execute token contract scanning"""
        try:
            # Get token addresses from database
            token_addresses = []
            contracts = database.get_contracts()
            for contract in contracts:
                if contract.get('category') == 'token':
                    token_addresses.append(contract['address'])

            # Add some well-known token addresses if database is empty
            if not token_addresses:
                token_addresses = [
                    '0xA0b86a33E6417aAb7b6DbCBbe9FD4E89c0778a4B',  # USDC
                    '0x6B175474E89094C44Da98b954EedeAC495271d0F',  # DAI
                    '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599',  # LINK
                    '0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9',  # AAVE
                ]

            print(f"🪙 Found {len(token_addresses)} token contracts to scan")

            # Scan tokens
            scanned_tokens = []
            total_vulns = 0

            for token_address in token_addresses:
                try:
                    token_data = self.token_scanner.scan_single_token(token_address, 'ethereum_mainnet')
                    if token_data:
                        scanned_tokens.append(token_data)
                        total_vulns += len(token_data.get('vulnerabilities', []))

                        # Save to database
                        database.add_contract(token_data)
                        if token_data.get('vulnerabilities'):
                            database.add_vulnerabilities(token_data['vulnerabilities'])

                    time.sleep(1)

                except Exception as e:
                    print(f"❌ Error scanning token {token_address}: {e}")

            return {
                'tokens': scanned_tokens,
                'total_vulns': total_vulns,
                'token_count': len(scanned_tokens)
            }

        except Exception as e:
            print(f"❌ Error in token scanning: {e}")
            return {'tokens': [], 'total_vulns': 0, 'token_count': 0}

    def show_comprehensive_summary(self, scan_results: Dict[str, Any]):
        """Show comprehensive scanning summary"""
        print("\n📊 COMPREHENSIVE SCANNING SUMMARY")
        print("="*60)

        print(f"🎯 Methodology Applied:")
        print(f"   ✅ Step 1: Get comprehensive DEFI/DEX lists")
        print(f"   ✅ Step 2: Save all contracts to database")
        print(f"   ✅ Step 3: Scan vulnerabilities per contract specifically")
        print(f"   ✅ Step 4: Token contract scanning")

        print(f"\n📈 Overall Results:")
        print(f"   🕐 Start Time: {scan_results['start_time']}")
        print(f"   📋 Total Contracts: {scan_results['total_contracts']}")
        print(f"   🔥 Total Vulnerabilities: {scan_results['total_vulnerabilities']}")
        print(f"   🌐 Chains Scanned: {len(scan_results['chains_scanned'])}")

        print(f"\n🏗️ DEFI/DEX Results:")
        print(f"   📊 DEFI Contracts: {scan_results['results']['defi_contracts']}")

        defi_vulns = scan_results['results']['defi_vulnerabilities']
        print(f"   🔥 DEFI Vulnerabilities: {defi_vulns['total_vulns']}")
        for severity, count in defi_vulns['by_severity'].items():
            print(f"      {severity}: {count}")

        print(f"\n🪙 Token Contract Results:")
        print(f"   📊 Token Contracts: {scan_results['results']['token_contracts']}")
        print(f"   🔥 Token Vulnerabilities: {scan_results['results']['token_vulnerabilities']['total_vulns']}")

        # Get high-risk contracts
        try:
            contracts = database.get_contracts()
            high_risk = [c for c in contracts if c.get('risk_level') in ['CRITICAL', 'HIGH']]

            print(f"\n🚨 High-Risk Contracts Summary:")
            print(f"   Total High-Risk: {len(high_risk)}")

            # Show top 5 high-risk contracts
            for contract in high_risk[:5]:
                print(f"   • {contract['name']} ({contract['risk_level']}) - Score: {contract['risk_score']}")
        except Exception as e:
            print(f"❌ Error getting high-risk summary: {e}")

        print(f"\n✅ COMPREHENSIVE SCANNING COMPLETED")
        print("="*60)

def main():
    """Main execution function"""
    scanner = ComprehensiveScanner()

    print("🚀 Starting Comprehensive Scanning Integration")
    print("="*60)
    print("🎯 Following new methodology: Get lists → Save database → Scan per contract → Token scanning")

    results = scanner.run_comprehensive_scan()

    print(f"\n🎉 Scanning completed successfully!")
    print(f"📊 Total Results: {results['total_contracts']} contracts, {results['total_vulnerabilities']} vulnerabilities")

if __name__ == "__main__":
    main()