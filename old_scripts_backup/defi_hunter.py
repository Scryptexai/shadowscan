#!/usr/bin/env python3
"""
DEFI Vulnerability Hunting System
Main orchestrator for scanning DEFI/DEX contracts with Blockscout API and vulnerability detection
"""

import json
import logging
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
from blockscout_scanner import BlockscoutScanner
from vulnerability_scanner import VulnerabilityScanner
from core.database import database

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DEFIHunter:
    """Main DEFI vulnerability hunting system"""

    def __init__(self):
        self.blockscout_scanner = BlockscoutScanner()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.target_chains = self._load_target_chains()

    def _load_target_chains(self) -> List[str]:
        """Load target chains from configuration"""
        try:
            with open('defi_target_list.json', 'r') as f:
                data = json.load(f)
                return list(data.get('defi_targets', {}).keys())
        except Exception as e:
            logger.error(f"Error loading target chains: {e}")
            return ['ethereum_mainnet', 'polygon_mainnet']

    def hunt_defi_vulnerabilities(self, min_activity_score: float = 1.0,
                                 min_severity: str = 'MEDIUM') -> Dict[str, Any]:
        """Main hunting function"""
        logger.info("🔥 Starting DEFI Vulnerability Hunt")
        logger.info(f"Target Chains: {', '.join(self.target_chains)}")
        logger.info(f"Minimum Activity Score: {min_activity_score}")
        logger.info(f"Minimum Severity: {min_severity}")

        hunting_results = {
            'scan_start_time': datetime.now().isoformat(),
            'chains_scanned': [],
            'total_contracts_discovered': 0,
            'total_vulnerabilities_found': 0,
            'chains': {}
        }

        try:
            # Step 1: Discover DEFI contracts using Blockscout API
            logger.info("📡 Step 1: Discovering DEFI contracts using Blockscout API")
            discovered_contracts = self._discover_contracts(min_activity_score)

            # Step 2: Scan discovered contracts for vulnerabilities
            logger.info("🔍 Step 2: Scanning contracts for vulnerabilities")
            vulnerabilities = self._scan_contracts_vulnerabilities(discovered_contracts, min_severity)

            # Compile results
            for chain_name, chain_data in discovered_contracts.items():
                chain_vulnerabilities = [v for v in vulnerabilities if v.get('chain_name') == chain_name]

                hunting_results['chains'][chain_name] = {
                    'contracts_discovered': len(chain_data),
                    'vulnerabilities_found': len(chain_vulnerabilities),
                    'contracts': chain_data,
                    'vulnerabilities': chain_vulnerabilities
                }

                hunting_results['chains_scanned'].append(chain_name)
                hunting_results['total_contracts_discovered'] += len(chain_data)
                hunting_results['total_vulnerabilities_found'] += len(chain_vulnerabilities)

            # Step 3: Generate comprehensive report
            logger.info("📊 Step 3: Generating hunting report")
            report = self._generate_hunting_report(hunting_results)

            # Save results to database
            self._save_hunting_results(hunting_results)

            return hunting_results

        except Exception as e:
            logger.error(f"Error in hunting process: {e}")
            return hunting_results

    def _discover_contracts(self, min_activity_score: float) -> Dict[str, List[Dict[str, Any]]]:
        """Discover DEFI contracts using Blockscout API"""
        discovered_contracts = {}

        for chain_name in self.target_chains:
            logger.info(f"🔍 Discovering contracts in {chain_name}")

            try:
                # Scan chain for DEFI contracts
                contracts = self.blockscout_scanner.scan_chain(chain_name, min_activity_score)

                if contracts:
                    discovered_contracts[chain_name] = contracts
                    logger.info(f"✅ Found {len(contracts)} contracts in {chain_name}")

                    # Save to database
                    self.blockscout_scanner.save_to_database(contracts, f"HUNTING_{chain_name.upper()}")
                else:
                    logger.info(f"⚠️ No contracts found in {chain_name}")
                    discovered_contracts[chain_name] = []

            except Exception as e:
                logger.error(f"Error discovering contracts in {chain_name}: {e}")
                discovered_contracts[chain_name] = []

            # Rate limiting between chains
            time.sleep(2)

        return discovered_contracts

    def _scan_contracts_vulnerabilities(self, discovered_contracts: Dict[str, List[Dict[str, Any]]],
                                      min_severity: str) -> List[Dict[str, Any]]:
        """Scan contracts for vulnerabilities"""
        all_vulnerabilities = []

        for chain_name, contracts in discovered_contracts.items():
            logger.info(f"🔍 Scanning {len(contracts)} contracts in {chain_name} for vulnerabilities")

            for contract in contracts:
                try:
                    # Scan for vulnerabilities
                    vulnerabilities = self.vulnerability_scanner.scan_contract_vulnerabilities(contract)

                    # Filter by severity
                    filtered_vulnerabilities = [
                        vuln for vuln in vulnerabilities
                        if self._get_severity_value(vuln.get('severity', 'UNKNOWN')) >= self._get_severity_value(min_severity)
                    ]

                    all_vulnerabilities.extend(filtered_vulnerabilities)

                    # Rate limiting
                    time.sleep(0.1)

                except Exception as e:
                    logger.error(f"Error scanning contract {contract.get('address')}: {e}")

        return all_vulnerabilities

    def _get_severity_value(self, severity: str) -> int:
        """Convert severity string to numeric value"""
        severity_mapping = {
            'CRITICAL': 5,
            'HIGH': 4,
            'MEDIUM': 3,
            'LOW': 2,
            'UNKNOWN': 1
        }
        return severity_mapping.get(severity.upper(), 1)

    def _generate_hunting_report(self, hunting_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive hunting report"""
        report = {
            'report_id': f"DEFI_HUNT_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'scan_time': datetime.now().isoformat(),
            'summary': {
                'total_chains_scanned': len(hunting_results['chains_scanned']),
                'total_contracts_discovered': hunting_results['total_contracts_discovered'],
                'total_vulnerabilities_found': hunting_results['total_vulnerabilities_found'],
                'average_vulnerabilities_per_contract':
                    hunting_results['total_vulnerabilities_found'] / max(hunting_results['total_contracts_discovered'], 1),
                'severity_breakdown': self._get_severity_breakdown(),
                'category_breakdown': self._get_category_breakdown(),
                'chain_breakdown': self._get_chain_breakdown()
            },
            'top_vulnerable_contracts': self._get_top_vulnerable_contracts(),
            'critical_findings': self._get_critical_findings(),
            'recommendations': self._generate_recommendations()
        }

        return report

    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Get breakdown of vulnerabilities by severity"""
        summary = database.get_vulnerability_summary()
        return summary.get('by_severity', {})

    def _get_category_breakdown(self) -> Dict[str, int]:
        """Get breakdown of vulnerabilities by category"""
        # This would need to be implemented in the database
        return {}

    def _get_chain_breakdown(self) -> Dict[str, int]:
        """Get breakdown of vulnerabilities by chain"""
        summary = database.get_vulnerability_summary()
        return summary.get('by_chain', {})

    def _get_top_vulnerable_contracts(self) -> List[Dict[str, Any]]:
        """Get top 10 most vulnerable contracts"""
        # This would need to be implemented to count vulnerabilities per contract
        return []

    def _get_critical_findings(self) -> List[Dict[str, Any]]:
        """Get critical vulnerability findings"""
        try:
            critical_vulns = database.get_vulnerabilities(severity='CRITICAL')
            return critical_vulns[:10]  # Top 10 critical findings
        except Exception as e:
            logger.error(f"Error getting critical findings: {e}")
            return []

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = [
            "Immediately patch critical vulnerabilities in production contracts",
            "Implement proper access controls on sensitive functions",
            "Use reentrancy guards for all external calls",
            "Implement slippage limits on trading functions",
            "Regular security audits and testing"
        ]

        # Add specific recommendations based on findings
        summary = database.get_vulnerability_summary()

        if summary.get('by_severity', {}).get('CRITICAL', 0) > 0:
            recommendations.insert(0, "⚠️ CRITICAL vulnerabilities found - immediate action required")

        return recommendations

    def _save_hunting_results(self, hunting_results: Dict[str, Any]) -> bool:
        """Save hunting results to database"""
        try:
            # Save report
            report_data = {
                'scan_type': 'DEFI_HUNTING',
                'scan_start_time': hunting_results['scan_start_time'],
                'total_contracts': hunting_results['total_contracts_discovered'],
                'total_vulnerabilities': hunting_results['total_vulnerabilities_found'],
                'chains_scanned': hunting_results['chains_scanned'],
                'results': hunting_results,
                'timestamp': datetime.now().isoformat()
            }

            database.add_report(report_data)
            logger.info("✅ Hunting results saved to database")
            return True

        except Exception as e:
            logger.error(f"Error saving hunting results: {e}")
            return False

    def print_hunting_summary(self, hunting_results: Dict[str, Any]):
        """Print human-readable hunting summary"""
        print("\n" + "="*80)
        print("🎯 DEFI VULNERABILITY HUNTING RESULTS")
        print("="*80)

        print(f"\n📊 Scan Summary:")
        print(f"   Chains Scanned: {hunting_results['total_contracts_discovered']}")
        print(f"   Contracts Discovered: {hunting_results['total_contracts_discovered']}")
        print(f"   Vulnerabilities Found: {hunting_results['total_vulnerabilities_found']}")
        print(f"   Average Vulns/Contract: {hunting_results['total_vulnerabilities_found'] / max(hunting_results['total_contracts_discovered'], 1):.2f}")

        print(f"\n🔗 Chain Breakdown:")
        for chain_name, chain_data in hunting_results['chains'].items():
            print(f"   {chain_name}: {chain_data['contracts_discovered']} contracts, {chain_data['vulnerabilities_found']} vulnerabilities")

        print(f"\n⚠️ Critical Findings:")
        critical_findings = self._get_critical_findings()
        if critical_findings:
            for finding in critical_findings[:5]:
                print(f"   {finding.get('vulnerability_type', 'Unknown')} - {finding.get('contract_address', 'Unknown')}")
        else:
            print("   No critical findings")

        print(f"\n💡 Recommendations:")
        for rec in self._generate_recommendations()[:5]:
            print(f"   • {rec}")

        print("\n" + "="*80)

def main():
    """Main execution function"""
    print("🚀 Starting DEFI Vulnerability Hunter")

    # Initialize hunter
    hunter = DEFIHunter()

    # Start hunting process
    results = hunter.hunt_defi_vulnerabilities(
        min_activity_score=0.5,
        min_severity='MEDIUM'
    )

    # Print results
    hunter.print_hunting_summary(results)

    print("✅ Hunting completed")

if __name__ == "__main__":
    main()