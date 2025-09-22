#!/usr/bin/env python3
"""
CLI Target Manager
Command-line interface for managing DEFI/DEX targets and viewing scan results
"""

import json
import click
import sys
from typing import Dict, List, Any
from datetime import datetime
from core.database import database
from defi_discovery_scanner import DEFIDiscoveryScanner

class TargetManagerCLI:
    """CLI interface for managing DEFI/DEX targets"""

    def __init__(self):
        self.discovery_scanner = DEFIDiscoveryScanner()

    def get_targets_from_json(self) -> Dict[str, Any]:
        """Load targets from JSON file"""
        try:
            with open('defi_target_list.json', 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Error loading targets: {e}")
            return {}

    def get_targets_from_database(self, chain_name: str = None) -> List[Dict[str, Any]]:
        """Get targets from database"""
        try:
            if chain_name:
                return database.get_contracts(chain_name)
            else:
                return database.get_contracts()
        except Exception as e:
            print(f"❌ Error getting targets from database: {e}")
            return []

    def get_vulnerabilities_from_database(self, chain_name: str = None, severity: str = None) -> List[Dict[str, Any]]:
        """Get vulnerabilities from database"""
        try:
            return database.get_vulnerabilities(severity=severity)
        except Exception as e:
            print(f"❌ Error getting vulnerabilities: {e}")
            return []

@click.group()
@click.version_option(version="1.0.0")
def cli():
    """ShadowScan Target Manager CLI"""
    pass

@cli.command()
@click.option('--chain', '-c', help='Specific chain to scan')
@click.option('--activity', '-a', type=float, default=0.3, help='Minimum activity score')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(chain, activity, verbose):
    """Scan for new DEFI/DEX contracts with vulnerability targeting"""
    print("🚀 Starting DEFI/DEX Discovery Scan")
    print("="*50)

    scanner = DEFIDiscoveryScanner()

    if chain:
        print(f"🎯 Scanning specific chain: {chain}")
        results = scanner.scan_chain_new_defi(chain, activity)
    else:
        print(f"🎯 Scanning all chains with min activity: {activity}")
        results = scanner.scan_all_chains_new_defi(activity)

    print_results(results)

@cli.command()
@click.option('--chain', '-c', help='Filter by chain')
@click.option('--category', help='Filter by category (router, lp_pool, control)')
@click.option('--risk', help='Filter by risk level (CRITICAL, HIGH, MEDIUM, LOW)')
@click.option('--limit', '-l', type=int, default=10, help='Limit results')
def targets(chain, category, risk, limit):
    """List DEFI/DEX targets from database"""
    print("📋 DEFI/DEX Targets")
    print("="*50)

    try:
        targets = database.get_contracts()

        if chain:
            targets = [t for t in targets if t.get('chain_name') == chain]

        if category:
            targets = [t for t in targets if t.get('category') == category]

        if risk:
            targets = [t for t in targets if t.get('risk_level') == risk]

        targets = targets[:limit]

        print(f"Found {len(targets)} targets:")

        for target in targets:
            print(f"\n🎯 {target.get('name', 'Unknown')}")
            print(f"   Address: {target.get('address', 'Unknown')}")
            print(f"   Chain: {target.get('chain_name', 'Unknown')}")
            print(f"   Category: {target.get('category', 'Unknown')}")
            print(f"   Risk Level: {target.get('risk_level', 'Unknown')}")
            print(f"   Activity Score: {target.get('activity_score', 0):.2f}")
            print(f"   Transfers: {target.get('total_transfers', 0)}")
            print(f"   Discovered: {target.get('discovered_at', 'Unknown')}")

    except Exception as e:
        print(f"❌ Error: {e}")

@cli.command()
@click.option('--chain', '-c', help='Filter by chain')
@click.option('--severity', '-s', help='Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)')
@click.option('--limit', '-l', type=int, default=10, help='Limit results')
def vulnerabilities(chain, severity, limit):
    """List vulnerabilities from database"""
    print("🔍 Vulnerabilities")
    print("="*50)

    try:
        vulns = database.get_vulnerabilities(severity=severity)

        if chain:
            vulns = [v for v in vulns if v.get('chain_name') == chain]

        vulns = vulns[:limit]

        print(f"Found {len(vulns)} vulnerabilities:")

        for vuln in vulns:
            print(f"\n⚠️  {vuln.get('vulnerability_type', 'Unknown')}")
            print(f"   Contract: {vuln.get('contract_address', 'Unknown')}")
            print(f"   Chain: {vuln.get('chain_name', 'Unknown')}")
            print(f"   Severity: {vuln.get('severity', 'UNKNOWN')}")
            print(f"   Confidence: {vuln.get('confidence', 0):.2f}")
            print(f"   Exploitable: {vuln.get('exploitable', False)}")
            print(f"   Evidence: {', '.join(vuln.get('evidence', []))}")
            print(f"   Discovered: {vuln.get('discovered_at', 'Unknown')}")

    except Exception as e:
        print(f"❌ Error: {e}")

@cli.command()
@click.option('--chain', '-c', help='Specific chain')
@click.option('--category', help='Specific category')
def stats(chain, category):
    """Show statistics for targets and vulnerabilities"""
    print("📊 Statistics")
    print("="*50)

    try:
        # Get database statistics
        db_stats = database.get_statistics()

        print("🏗️  Database Statistics:")
        print(f"   Total Chains: {db_stats['chains']['total']}")
        print(f"   Total Contracts: {db_stats['contracts']['total']}")
        print(f"   Total Vulnerabilities: {db_stats['vulnerabilities']['total']}")
        print(f"   Total Reports: {db_stats['reports']['total']}")

        print(f"\n🔗 Chains:")
        for chain, count in db_stats['contracts']['by_chain'].items():
            print(f"   {chain}: {count} contracts")

        print(f"\n⚠️  Vulnerabilities by Severity:")
        for severity, count in db_stats['vulnerabilities']['by_severity'].items():
            print(f"   {severity}: {count}")

        print(f"\n🎯 Exploitability:")
        for key, count in db_stats['vulnerabilities']['by_exploitability'].items():
            print(f"   {key}: {count}")

    except Exception as e:
        print(f"❌ Error: {e}")

@cli.command()
@click.option('--file', '-f', required=True, help='Output file path')
@click.option('--format', '-t', type=click.Choice(['json', 'csv']), default='json', help='Output format')
def export(file, format):
    """Export targets and vulnerabilities to file"""
    print(f"📤 Exporting to {file}")
    print("="*50)

    try:
        data = {
            'export_timestamp': datetime.now().isoformat(),
            'statistics': database.get_statistics(),
            'contracts': database.get_contracts(),
            'vulnerabilities': database.get_vulnerabilities(),
            'reports': database.get_reports()
        }

        if format == 'json':
            with open(file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        elif format == 'csv':
            # Simple CSV export
            with open(file, 'w') as f:
                f.write("address,name,chain,category,risk_level,activity_score\n")
                for contract in data['contracts']:
                    f.write(f"{contract.get('address', '')},{contract.get('name', '')},")
                    f.write(f"{contract.get('chain_name', '')},{contract.get('category', '')},")
                    f.write(f"{contract.get('risk_level', '')},{contract.get('activity_score', 0)}\n")

        print(f"✅ Export completed successfully")

    except Exception as e:
        print(f"❌ Error: {e}")

@cli.command()
@click.option('--chain', '-c', help='Filter by chain')
@click.option('--risk', '-r', help='Filter by risk level')
def high_risk(chain, risk):
    """Show high-risk contracts and vulnerabilities"""
    print("🚨 High-Risk Analysis")
    print("="*50)

    try:
        # Get high-risk contracts
        contracts = database.get_contracts()
        if chain:
            contracts = [c for c in contracts if c.get('chain_name') == chain]

        # Filter by risk level
        risk_levels = ['CRITICAL', 'HIGH']
        if risk:
            risk_levels = [risk]

        high_risk_contracts = [c for c in contracts if c.get('risk_level') in risk_levels]

        print(f"High-Risk Contracts: {len(high_risk_contracts)}")

        for contract in high_risk_contracts:
            print(f"\n🎯 {contract.get('name', 'Unknown')}")
            print(f"   Address: {contract.get('address', 'Unknown')}")
            print(f"   Chain: {contract.get('chain_name', 'Unknown')}")
            print(f"   Category: {contract.get('category', 'Unknown')}")
            print(f"   Risk Level: {contract.get('risk_level', 'Unknown')}")
            print(f"   Activity Score: {contract.get('activity_score', 0):.2f}")
            print(f"   Risk Factors: {', '.join(contract.get('risk_factors', []))}")

        # Get related vulnerabilities
        vulns = database.get_vulnerabilities()
        high_risk_vulns = [v for v in vulns if v.get('severity') in ['CRITICAL', 'HIGH']]

        print(f"\n⚠️  High-Risk Vulnerabilities: {len(high_risk_vulns)}")

        for vuln in high_risk_vulns[:5]:  # Show top 5
            print(f"\n🔍 {vuln.get('vulnerability_type', 'Unknown')}")
            print(f"   Contract: {vuln.get('contract_address', 'Unknown')}")
            print(f"   Severity: {vuln.get('severity', 'UNKNOWN')}")
            print(f"   Confidence: {vuln.get('confidence', 0):.2f}")
            print(f"   Evidence: {', '.join(vuln.get('evidence', []))}")

    except Exception as e:
        print(f"❌ Error: {e}")

def print_results(results):
    """Print scan results"""
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

if __name__ == '__main__':
    cli()