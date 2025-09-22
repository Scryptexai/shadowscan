#!/usr/bin/env python3
"""
Test DEFI Vulnerability Scanner
Tests the vulnerability scanner with existing contract data from the target list
"""

import json
import logging
from datetime import datetime
from vulnerability_scanner import VulnerabilityScanner
from core.database import database

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_vulnerability_scanner():
    """Test the vulnerability scanner with DEFI targets from JSON"""
    print("🔍 Testing DEFI Vulnerability Scanner")
    print("="*50)

    # Initialize scanner
    scanner = VulnerabilityScanner()

    # Load DEFI targets
    try:
        with open('defi_target_list.json', 'r') as f:
            target_data = json.load(f)
    except Exception as e:
        print(f"❌ Error loading target data: {e}")
        return

    # Test contracts from the target list
    test_contracts = []
    total_vulnerabilities = 0

    for chain_name, chain_data in target_data.get('defi_targets', {}).items():
        chain_id = chain_data.get('chain_id')
        targets = chain_data.get('targets', {})

        for target_key, target_info in targets.items():
            contract = {
                'address': target_info.get('contract_address'),
                'name': target_info.get('name'),
                'description': target_info.get('description'),
                'category': target_info.get('category'),
                'chain_id': chain_id,
                'chain_name': chain_name,
                'tvl_usd': target_info.get('tvl_usd'),
                'daily_volume_usd': target_info.get('daily_volume_usd'),
                'security_score': target_info.get('security_score'),
                'attack_surface': target_info.get('attack_surface', []),
                'source_code': f"""
// Sample {target_info.get('name')} contract
contract {target_info.get('name')} {{
    mapping(address => uint256) public balances;

    function withdraw() public {{
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount); // Potentially reentrant
    }}

    function deposit() public payable {{
        balances[msg.sender] += msg.value;
    }}

    function getPrice() public view returns (uint256) {{
        // Oracle - potentially vulnerable
        return block.timestamp * 1e18; // Simple price oracle
    }}

    // Attack surface: {', '.join(target_info.get('attack_surface', []))}
}}
                """
            }
            test_contracts.append(contract)

    print(f"📋 Testing {len(test_contracts)} DEFI contracts from target list")

    # Scan each contract
    for i, contract in enumerate(test_contracts):
        contract_name = contract.get('name', 'Unknown')
        contract_address = contract.get('address', 'Unknown')

        print(f"\n🎯 Scanning {i+1}/{len(test_contracts)}: {contract_name}")
        print(f"   Address: {contract_address}")
        print(f"   Chain: {contract.get('chain_name')} (ID: {contract.get('chain_id')})")
        print(f"   Category: {contract.get('category')}")
        print(f"   TVL: ${contract.get('tvl_usd', 0):,}")
        print(f"   Daily Volume: ${contract.get('daily_volume_usd', 0):,}")

        try:
            # Scan for vulnerabilities
            vulnerabilities = scanner.scan_contract_vulnerabilities(contract)

            if vulnerabilities:
                print(f"   ⚠️  Found {len(vulnerabilities)} vulnerabilities:")
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'UNKNOWN')
                    vuln_type = vuln.get('vulnerability_type', 'Unknown')
                    confidence = vuln.get('confidence', 0)
                    line = vuln.get('location', {}).get('line', 'Unknown')

                    print(f"      • {severity}: {vuln_type} (Line: {line}, Confidence: {confidence:.2f})")

                    # Save to database
                    database.add_vulnerability(vuln)
                    total_vulnerabilities += 1
            else:
                print(f"   ✅ No vulnerabilities found")

        except Exception as e:
            print(f"   ❌ Error scanning: {e}")

        # Add contract to database
        contract_data = {
            'address': contract_address,
            'name': contract_name,
            'description': contract.get('description', ''),
            'category': contract.get('category'),
            'chain_id': contract.get('chain_id'),
            'chain_name': contract.get('chain_name'),
            'tvl_usd': contract.get('tvl_usd'),
            'daily_volume_usd': contract.get('daily_volume_usd'),
            'security_score': contract.get('security_score'),
            'attack_surface': contract.get('attack_surface', []),
            'scan_type': 'TEST_SCAN',
            'scanned_at': datetime.now().isoformat()
        }
        database.add_contract(contract_data)

    # Print summary
    print(f"\n📊 Scan Summary")
    print("="*50)
    print(f"Total Contracts Scanned: {len(test_contracts)}")
    print(f"Total Vulnerabilities Found: {total_vulnerabilities}")
    print(f"Average Vulnerabilities per Contract: {total_vulnerabilities / len(test_contracts):.2f}")

    # Get vulnerability statistics
    vuln_summary = database.get_vulnerability_summary()
    print(f"\n🔍 Vulnerability Breakdown:")
    print(f"By Severity: {vuln_summary.get('by_severity', {})}")
    print(f"By Exploitability: {vuln_summary.get('by_exploitability', {})}")

    # Show top critical findings
    critical_vulns = database.get_vulnerabilities(severity='CRITICAL')
    if critical_vulns:
        print(f"\n🚨 Critical Vulnerabilities Found:")
        for vuln in critical_vulns[:5]:
            print(f"   • {vuln.get('vulnerability_type', 'Unknown')} - {vuln.get('contract_address', 'Unknown')}")
            print(f"     Impact: {vuln.get('description', 'Unknown')}")
            print(f"     Recommendation: {vuln.get('mitigation', 'None')}")

    print("\n✅ Test completed successfully")

if __name__ == "__main__":
    test_vulnerability_scanner()