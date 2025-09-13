#!/usr/bin/env python3
"""
ShadowScan Example Scripts

This file contains practical examples of using ShadowScan for various security analysis tasks.
"""

import asyncio
import json
import logging
from typing import Dict, List, Any

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def example_1_basic_contract_scan():
    """
    Example 1: Basic Contract Security Scan
    
    Demonstrates how to perform a basic security scan of a smart contract.
    """
    print("🔍 Example 1: Basic Contract Security Scan")
    print("=" * 50)
    
    try:
        from shadowscan.core.pipeline.screening_engine import ScreeningEngine
        
        # Initialize screening engine
        engine = ScreeningEngine()
        
        # Target contract (Uniswap V2 Router)
        target_address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
        
        print(f"Scanning contract: {target_address}")
        
        # Perform shallow scan (500 blocks)
        results = await engine.screen_contract(
            target_address=target_address,
            chain="ethereum",
            depth="shallow"
        )
        
        # Display results
        print(f"\n📊 Scan Results:")
        print(f"   Target: {results['target_address']}")
        print(f"   Chain: {results['chain']}")
        print(f"   Depth: {results['screening_depth']}")
        print(f"   Total Findings: {len(results['findings'])}")
        
        print(f"\n🚨 Security Findings:")
        for i, finding in enumerate(results['findings'][:5], 1):  # Show first 5 findings
            print(f"   {i}. {finding['title']}")
            print(f"      Severity: {finding['severity']}")
            print(f"      Description: {finding['description'][:100]}...")
            print()
        
        print("✅ Basic scan completed successfully!")
        
    except Exception as e:
        print(f"❌ Error in basic scan: {e}")
        import traceback
        traceback.print_exc()


async def example_2_comprehensive_vulnerability_scan():
    """
    Example 2: Comprehensive Vulnerability Scan
    
    Demonstrates using all 20 vulnerability detectors for thorough analysis.
    """
    print("\n🔍 Example 2: Comprehensive Vulnerability Scan")
    print("=" * 50)
    
    try:
        from shadowscan.detectors.evm.defi_detectors import ComprehensiveVulnerabilityScanner
        from shadowscan.adapters.evm.provider import EVMProvider
        
        # Initialize provider and scanner
        provider = EVMProvider()
        scanner = ComprehensiveVulnerabilityScanner(provider)
        
        # Target contract (Aave Lending Pool)
        target_contract = "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9"
        
        print(f"Running comprehensive scan on: {target_contract}")
        print(f"Using {len(scanner.detectors)} vulnerability detectors...")
        
        # Perform comprehensive scan
        results = await scanner.comprehensive_scan(target_contract)
        
        # Display summary
        print(f"\n📊 Comprehensive Scan Summary:")
        print(f"   Total Findings: {results['total_findings']}")
        print(f"   Detectors Used: {results['scan_metadata']['detectors_used']}")
        print(f"   Successful Detectors: {results['scan_metadata']['successful_detectors']}")
        
        print(f"\n📈 Severity Distribution:")
        for severity, count in results['severity_distribution'].items():
            print(f"   {severity}: {count}")
        
        # Display detector-specific results
        print(f"\n🔍 Detector Results:")
        for detector_name, detector_result in results['detector_results'].items():
            if 'findings_count' in detector_result and detector_result['findings_count'] > 0:
                print(f"   {detector_name}: {detector_result['findings_count']} findings")
        
        print("✅ Comprehensive scan completed successfully!")
        
    except Exception as e:
        print(f"❌ Error in comprehensive scan: {e}")
        import traceback
        traceback.print_exc()


async def example_3_dex_relationship_analysis():
    """
    Example 3: DEX Relationship Analysis
    
    Demonstrates how to analyze DEX relationships and liquidity.
    """
    print("\n🔍 Example 3: DEX Relationship Analysis")
    print("=" * 50)
    
    try:
        from shadowscan.collectors.evm.dex_discovery import DexDiscovery
        from web3 import Web3
        
        # Initialize Web3 and DEX discovery
        web3 = Web3(Web3.HTTPProvider('https://virtual.mainnet.eu.rpc.tenderly.co/eeffdb55-4da5-4241-a9eb-bb6ac3ef16e8'))
        dex_discovery = DexDiscovery(web3, max_workers=4)
        
        # Target token (DAI)
        target_token = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
        
        print(f"Analyzing DEX relationships for token: {target_token}")
        
        # Discover DEX relationships
        dex_relationships = await dex_discovery.discover_dex_relations(
            target_token, web3, chain="ethereum"
        )
        
        print(f"\n💱 DEX Relationships Found: {len(dex_relationships)}")
        
        # Display top relationships by liquidity
        print("\n📊 Top DEX Relationships by Liquidity:")
        for i, relationship in enumerate(dex_relationships[:10], 1):
            print(f"   {i}. {relationship.dex_name}")
            print(f"      Pair: {relationship.pair}")
            print(f"      Liquidity: ${relationship.liquidity_usd:,.2f}")
            print(f"      Depth Score: {relationship.depth_score:.2f}")
            print(f"      Fee Tier: {relationship.fee_tier or 'N/A'}")
            print()
        
        print("✅ DEX analysis completed successfully!")
        
    except Exception as e:
        print(f"❌ Error in DEX analysis: {e}")
        import traceback
        traceback.print_exc()


async def example_4_contract_registry_management():
    """
    Example 4: Contract Registry Management
    
    Demonstrates how to use the contract registry for session management.
    """
    print("\n🔍 Example 4: Contract Registry Management")
    print("=" * 50)
    
    try:
        from shadowscan.data.contracts import ContractRegistry
        
        # Initialize contract registry
        registry = ContractRegistry()
        
        # Create a screening session
        target_address = "0x1234567890123456789012345678901234567890"
        session_id = "example-session-001"
        
        print(f"Creating screening session for: {target_address}")
        session = registry.create_session(
            target=target_address,
            chain="ethereum",
            session_id=session_id
        )
        
        print(f"✅ Session created: {session.session_id}")
        print(f"   Status: {session.status}")
        print(f"   Start Time: {session.session_start}")
        
        # Add some discovered contracts
        contracts_to_add = [
            {
                "address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                "role": "token",
                "metadata": {"symbol": "TOKEN1", "decimals": 18}
            },
            {
                "address": "0x1111111111111111111111111111111111111111",
                "role": "dex",
                "metadata": {"type": "uniswap_v2"}
            }
        ]
        
        for contract_data in contracts_to_add:
            contract = registry.add_contract(
                target=target_address,
                chain="ethereum",
                address=contract_data["address"],
                role=contract_data["role"],
                metadata=contract_data["metadata"]
            )
            print(f"   Added contract: {contract.address} ({contract.role})")
        
        # Get registry statistics
        stats = registry.get_statistics()
        print(f"\n📊 Registry Statistics:")
        print(f"   Total Contracts: {stats['total_contracts']}")
        print(f"   Total Sessions: {stats['total_sessions']}")
        print(f"   Active Sessions: {stats['active_sessions']}")
        
        # Get contracts for target
        target_contracts = registry.get_contracts_for_target(target_address, "ethereum")
        print(f"\n📋 Contracts for Target:")
        for contract in target_contracts:
            print(f"   • {contract.address} ({contract.role})")
        
        # Update session status
        updated_session = registry.update_session(
            session_id, "completed", set(contract.address for contract in target_contracts)
        )
        print(f"\n✅ Session updated: {updated_session.status}")
        
        print("✅ Contract registry management completed successfully!")
        
    except Exception as e:
        print(f"❌ Error in registry management: {e}")
        import traceback
        traceback.print_exc()


async def example_5_custom_detection_rules():
    """
    Example 5: Custom Detection Rules
    
    Demonstrates how to implement custom vulnerability detection logic.
    """
    print("\n🔍 Example 5: Custom Detection Rules")
    print("=" * 50)
    
    try:
        from shadowscan.detectors.evm.vulnerability_detectors import BaseVulnerabilityDetector
        from shadowscan.adapters.evm.provider import EVMProvider
        
        class CustomHoneypotDetector(BaseVulnerabilityDetector):
            """Custom detector for potential honeypot patterns."""
            
            async def screen(self, target_contract: str) -> List[Any]:
                findings = []
                
                try:
                    contract_info = await self.provider.get_contract_info(target_contract)
                    
                    if not contract_info or not contract_info.source_code:
                        return findings
                    
                    source_code = contract_info.source_code.lower()
                    
                    # Detect honeypot patterns
                    honeypot_patterns = self._detect_honeypot_patterns(source_code)
                    
                    for pattern in honeypot_patterns:
                        finding = type('Finding', (), {
                            'vulnerability_type': 'POTENTIAL_HONEYPOT',
                            'severity': 'HIGH',
                            'title': 'Potential Honeypot Detected',
                            'description': f'Contract contains pattern commonly associated with honeypots: {pattern}',
                            'affected_functions': ['all_functions'],
                            'confidence': 0.7,
                            'exploitability_score': 0.8,
                            'impact_score': 0.9,
                            'evidence': {'pattern': pattern},
                            'remediation': 'Exercise extreme caution; thorough manual review required',
                            'references': []
                        })()
                        findings.append(finding)
                        
                except Exception as e:
                    logger.error(f"Error in custom honeypot detector: {e}")
                
                return findings
            
            def _detect_honeypot_patterns(self, source_code: str) -> List[str]:
                """Detect potential honeypot patterns."""
                patterns = []
                
                # Pattern 1: Functions that claim to send ETH but have complex conditions
                if re.search(r'function.*send.*eth.*require.*balance', source_code):
                    patterns.append("Complex ETH sending conditions")
                
                # Pattern 2: Multiple ownership transfers
                ownership_transfers = re.findall(r'transferownership', source_code)
                if len(ownership_transfers) > 2:
                    patterns.append("Multiple ownership transfer functions")
                
                # Pattern 3: Unusual fee structures
                if re.search(r'fee.*>\s*50', source_code):
                    patterns.append("Unusually high fees")
                
                return patterns
        
        # Use custom detector
        provider = EVMProvider()
        custom_detector = CustomHoneypotDetector(provider)
        
        # Test on a contract
        target_contract = "0x1234567890123456789012345678901234567890"
        print(f"Running custom honeypot detection on: {target_contract}")
        
        findings = await custom_detector.screen(target_contract)
        
        print(f"\n🔍 Custom Detection Results:")
        if findings:
            for finding in findings:
                print(f"   • {finding.title}")
                print(f"     Pattern: {finding.evidence.get('pattern', 'Unknown')}")
                print(f"     Confidence: {finding.confidence:.1%}")
        else:
            print("   No honeypot patterns detected")
        
        print("✅ Custom detection completed successfully!")
        
    except Exception as e:
        print(f"❌ Error in custom detection: {e}")
        import traceback
        traceback.print_exc()


async def example_6_batch_analysis():
    """
    Example 6: Batch Contract Analysis
    
    Demonstrates how to analyze multiple contracts efficiently.
    """
    print("\n🔍 Example 6: Batch Contract Analysis")
    print("=" * 50)
    
    try:
        from shadowscan.core.pipeline.screening_engine import ScreeningEngine
        
        # List of well-known DeFi contracts to analyze
        contracts = [
            "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",  # Uniswap V2 Router
            "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9",  # Aave Lending Pool
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  # WETH
            "0x6B175474E89094C44Da98b954EedeAC495271d0F",  # DAI
            "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT
        ]
        
        print(f"📊 Starting batch analysis of {len(contracts)} contracts")
        
        engine = ScreeningEngine()
        results = {}
        
        # Analyze each contract
        for i, contract in enumerate(contracts, 1):
            print(f"\n   [{i}/{len(contracts)}] Analyzing: {contract}")
            
            try:
                # Use shallow scan for faster processing
                result = await engine.screen_contract(
                    target_address=contract,
                    chain="ethereum",
                    depth="shallow"
                )
                
                findings_count = len(result['findings'])
                high_severity = len([f for f in result['findings'] if f.get('severity') in ['HIGH', 'CRITICAL']])
                
                results[contract] = {
                    'findings_count': findings_count,
                    'high_severity': high_severity,
                    'risk_score': high_severity * 3 + (findings_count - high_severity)
                }
                
                print(f"      ✓ {findings_count} findings ({high_severity} high severity)")
                
            except Exception as e:
                print(f"      ✗ Error: {e}")
                results[contract] = {'error': str(e)}
        
        # Generate batch summary
        print(f"\n📋 Batch Analysis Summary:")
        total_contracts = len(contracts)
        successful_scans = len([r for r in results.values() if 'error' not in r])
        total_findings = sum(r.get('findings_count', 0) for r in results.values())
        
        print(f"   Contracts Analyzed: {successful_scans}/{total_contracts}")
        print(f"   Total Findings: {total_findings}")
        print(f"   Average Findings per Contract: {total_findings / successful_scans:.1f}" if successful_scans > 0 else "N/A")
        
        # Rank contracts by risk
        contract_risks = []
        for contract, result in results.items():
            if 'risk_score' in result:
                contract_risks.append((contract, result['risk_score'], result['findings_count']))
        
        contract_risks.sort(key=lambda x: x[1], reverse=True)
        
        print(f"\n🚨 Highest Risk Contracts:")
        for contract, risk_score, findings_count in contract_risks[:3]:
            print(f"   {contract[:10]}...{contract[-8:]} - Risk Score: {risk_score} ({findings_count} findings)")
        
        print("✅ Batch analysis completed successfully!")
        
    except Exception as e:
        print(f"❌ Error in batch analysis: {e}")
        import traceback
        traceback.print_exc()


async def main():
    """
    Run all examples sequentially.
    """
    print("🌑 ShadowScan Example Scripts")
    print("=" * 60)
    print("This script demonstrates various ShadowScan capabilities.")
    print("Note: Some examples may require valid RPC endpoints.")
    print()
    
    examples = [
        ("Basic Contract Security Scan", example_1_basic_contract_scan),
        ("Comprehensive Vulnerability Scan", example_2_comprehensive_vulnerability_scan),
        ("DEX Relationship Analysis", example_3_dex_relationship_analysis),
        ("Contract Registry Management", example_4_contract_registry_management),
        ("Custom Detection Rules", example_5_custom_detection_rules),
        ("Batch Contract Analysis", example_6_batch_analysis),
    ]
    
    for name, example_func in examples:
        try:
            await example_func()
            print(f"\n✅ Completed: {name}")
            print("\n" + "=" * 60 + "\n")
        except Exception as e:
            print(f"\n❌ Failed: {name}")
            print(f"   Error: {e}")
            print("\n" + "=" * 60 + "\n")
        
        # Small delay between examples
        await asyncio.sleep(1)
    
    print("🎉 All examples completed!")
    print("\n💡 Tips:")
    print("   • RPC endpoint sudah dikonfigurasi dari .env")
    print("   • Adjust target addresses as needed")
    print("   • Modify screening depth based on requirements")
    print("   • Add error handling for production use")


if __name__ == "__main__":
    asyncio.run(main())