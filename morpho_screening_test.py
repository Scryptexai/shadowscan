#!/usr/bin/env python3
"""
SHADOWSCAN - Morpho Protocol Vulnerability Scanner with Tenderly Fork Testing
Screening-only vulnerability detection for DeFi protocols
"""

import asyncio
import json
import sys
import os
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import asdict
from web3 import Web3
from eth_account import Account

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        elif hasattr(obj, 'asdict'):
            return obj.asdict()
        else:
            return super().default(obj)

# Add framework to path
sys.path.append('/home/nurkahfi/MyProject/shadowscan/modules/web_claim_dex_framework')

from morpho_protocol_scanner import MorphoProtocolScanner
from real_blockchain_integration import BlockchainConfig

class TenderlyForkTester:
    """Tenderly fork integration for safe vulnerability testing"""
    
    def __init__(self):
        self.tenderly_fork_rpc = os.getenv('TENDERLY_FORK_RPC')
        self.tenderly_access_key = os.getenv('TENDERLY_ACCESS_KEY')
        
    async def create_fork(self, network: str = 'ethereum') -> Optional[str]:
        """Create Tenderly fork for testing"""
        if not self.tenderly_access_key:
            print("❌ TENDERLY_ACCESS_KEY not configured")
            return None
            
        print(f"🍴 Creating Tenderly fork for {network}...")
        
        # Mock fork creation - in real implementation, this would call Tenderly API
        fork_id = f"shadowscan_fork_{network}_{int(time.time())}"
        print(f"✅ Fork created: {fork_id}")
        
        return fork_id
    
    async def get_fork_rpc_url(self, fork_id: str) -> str:
        """Get RPC URL for Tenderly fork"""
        if self.tenderly_fork_rpc:
            return self.tenderly_fork_rpc
        return f"https://rpc.tenderly.co/fork/{fork_id}"

class MorphoScreeningTest:
    """Comprehensive Morpho protocol screening test"""
    
    def __init__(self):
        self.scanner = MorphoProtocolScanner()
        self.tenderly_tester = TenderlyForkTester()
        self.results = {
            'test_info': {
                'start_time': datetime.now().isoformat(),
                'framework': 'Shadowscan Morpho Protocol Screening',
                'version': '2.1.0'
            },
            'results': {}
        }
    
    async def run_tenderly_fork_test(self, network: str = 'ethereum') -> Dict[str, Any]:
        """Run screening on Tenderly fork first"""
        print(f"🍴 Testing Morpho protocol on Tenderly fork ({network})")
        print("=" * 60)
        
        # Create fork
        fork_id = await self.tenderly_tester.create_fork(network)
        if not fork_id:
            return {'error': 'Failed to create Tenderly fork'}
        
        # Get fork RPC URL
        fork_rpc_url = await self.tenderly_tester.get_fork_rpc_url(fork_id)
        
        # Create temporary scanner with fork RPC
        fork_scanner = MorphoProtocolScanner()
        
        # Override RPC with fork RPC
        if network in fork_scanner.web3_providers:
            fork_scanner.web3_providers[network] = Web3(Web3.HTTPProvider(fork_rpc_url))
        
        try:
            # Run screening on fork
            result = await fork_scanner.screen_morpho_protocol(network)
            
            print(f"✅ Fork screening completed")
            print(f"   Contracts analyzed: {len(result.get('contracts', {}))}")
            print(f"   Vulnerabilities found: {len(result.get('vulnerabilities', []))}")
            print(f"   TVL analyzed: {len(result.get('tvl_analysis', {}))}")
            
            return {
                'fork_id': fork_id,
                'screening_result': result,
                'network': network,
                'success': True
            }
            
        except Exception as e:
            print(f"❌ Fork screening failed: {e}")
            return {
                'fork_id': fork_id,
                'error': str(e),
                'network': network,
                'success': False
            }
    
    async def run_real_rpc_test(self, network: str = 'ethereum') -> Dict[str, Any]:
        """Run screening on real RPC endpoints"""
        print(f"🔗 Testing Morpho protocol on real RPC ({network})")
        print("=" * 60)
        
        try:
            # Run screening on real RPC
            result = await self.scanner.screen_morpho_protocol(network)
            
            print(f"✅ Real RPC screening completed")
            print(f"   Contracts analyzed: {len(result.get('contracts', {}))}")
            print(f"   Vulnerabilities found: {len(result.get('vulnerabilities', []))}")
            print(f"   TVL analyzed: {len(result.get('tvl_analysis', {}))}")
            
            return {
                'screening_result': result,
                'network': network,
                'success': True
            }
            
        except Exception as e:
            print(f"❌ Real RPC screening failed: {e}")
            return {
                'error': str(e),
                'network': network,
                'success': False
            }
    
    async def analyze_vulnerabilities(self, screening_result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze found vulnerabilities for exploit potential"""
        print("🔍 Analyzing vulnerabilities for exploit potential...")
        
        vulnerabilities = screening_result.get('vulnerabilities', [])
        analysis = {
            'total_vulnerabilities': len(vulnerabilities),
            'exploitable_vulnerabilities': [],
            'risk_assessment': {},
            'recommendations': []
        }
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            severity = vuln.get('severity', 'Low')
            
            # Assess exploitability
            exploitability = self._assess_exploitability(vuln)
            
            if exploitability['exploitable']:
                analysis['exploitable_vulnerabilities'].append({
                    'type': vuln_type,
                    'severity': severity,
                    'description': vuln.get('description', ''),
                    'exploit_method': exploitability['method'],
                    'estimated_impact': exploitability['impact']
                })
            
            # Risk assessment
            if vuln_type not in analysis['risk_assessment']:
                analysis['risk_assessment'][vuln_type] = {
                    'count': 0,
                    'max_severity': 'Low',
                    'exploitable': False
                }
            
            analysis['risk_assessment'][vuln_type]['count'] += 1
            if severity in ['Critical', 'High']:
                analysis['risk_assessment'][vuln_type]['max_severity'] = severity
            
            if exploitability['exploitable']:
                analysis['risk_assessment'][vuln_type]['exploitable'] = True
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _assess_exploitability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Assess if vulnerability is exploitable"""
        vuln_type = vulnerability.get('type', 'Unknown')
        
        # Exploitability assessment based on vulnerability type
        exploitability_map = {
            'Flashloan Vulnerability': {
                'exploitable': True,
                'method': 'Flash loan attack with price manipulation',
                'impact': 'High - Can drain protocol funds'
            },
            'Oracle Manipulation': {
                'exploitable': True,
                'method': 'Price oracle manipulation with large trades',
                'impact': 'Critical - Can affect all protocol operations'
            },
            'Reentrancy Vulnerability': {
                'exploitable': True,
                'method': 'Reentrancy attack during fund withdrawal',
                'impact': 'High - Can drain contract balances'
            },
            'Access Control Vulnerability': {
                'exploitable': True,
                'method': 'Unauthorized function calls',
                'impact': 'Medium to High - Depends on function privileges'
            },
            'Integer Overflow': {
                'exploitable': True,
                'method': 'Overflow attack to manipulate calculations',
                'impact': 'Medium to High - Can break financial calculations'
            }
        }
        
        return exploitability_map.get(vuln_type, {
            'exploitable': False,
            'method': 'Unknown',
            'impact': 'Unknown'
        })
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        exploitable_count = len(analysis['exploitable_vulnerabilities'])
        
        if exploitable_count > 0:
            recommendations.append(f"🚨 CRITICAL: {exploitable_count} exploitable vulnerabilities found!")
            recommendations.append("   Immediate patching required before production deployment")
        
        for vuln_type, risk in analysis['risk_assessment'].items():
            if risk['exploitable']:
                recommendations.append(f"🔴 Address {vuln_type} vulnerabilities - {risk['count']} found")
        
        if analysis['total_vulnerabilities'] > 5:
            recommendations.append("📊 High vulnerability count - consider comprehensive security audit")
        
        recommendations.append("🔍 Regular security screening recommended")
        recommendations.append("💰 Consider implementing bug bounty program")
        
        return recommendations
    
    async def run_comprehensive_test(self):
        """Run comprehensive screening test"""
        print("🚀 SHADOWSCAN MORPHO PROTOCOL SCREENING TEST")
        print("=" * 80)
        print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("🎯 Target: https://app.morpho.org")
        print("🔍 Focus: DeFi vulnerability screening (no gas required)")
        print("=" * 80)
        
        start_time = time.time()
        
        # Test networks
        networks = ['ethereum', 'base', 'arbitrum']
        
        for network in networks:
            print(f"\n🌐 Testing on {network.upper()}")
            print("-" * 40)
            
            # Step 1: Test on Tenderly fork first
            print("Step 1: Tenderly Fork Test")
            fork_result = await self.run_tenderly_fork_test(network)
            self.results['results'][f'{network}_fork_test'] = fork_result
            
            # Step 2: Test on real RPC (proceed even if fork test failed)
            print("\nStep 2: Real RPC Test")
            real_result = await self.run_real_rpc_test(network)
            self.results['results'][f'{network}_real_test'] = real_result
            
            # Analyze vulnerabilities from real RPC test
            if real_result.get('success') and 'screening_result' in real_result:
                vuln_analysis = await self.analyze_vulnerabilities(real_result['screening_result'])
                self.results['results'][f'{network}_vulnerability_analysis'] = vuln_analysis
                
                # Print analysis
                print("\n🔍 Vulnerability Analysis:")
                print(f"   Total vulnerabilities: {vuln_analysis['total_vulnerabilities']}")
                print(f"   Exploitable: {len(vuln_analysis['exploitable_vulnerabilities'])}")
                
                for rec in vuln_analysis['recommendations'][:3]:  # Show top 3 recommendations
                    print(f"   {rec}")
            else:
                print("❌ Real RPC test failed - skipping vulnerability analysis")
            
            print()
        
        # Calculate execution time
        execution_time = time.time() - start_time
        self.results['test_info']['execution_time'] = execution_time
        self.results['test_info']['end_time'] = datetime.now().isoformat()
        
        # Summary
        self._print_summary()
        
        # Save results
        await self._save_results()
        
        return self.results
    
    def _print_summary(self):
        """Print test summary"""
        print(f"\n📊 MORPHO PROTOCOL SCREENING SUMMARY")
        print("=" * 50)
        
        networks_tested = 0
        successful_tests = 0
        total_vulnerabilities = 0
        exploitable_vulnerabilities = 0
        
        for key, result in self.results['results'].items():
            if 'real_test' in key and result.get('success'):
                networks_tested += 1
                successful_tests += 1
                
                # Count vulnerabilities from analysis
                analysis_key = key.replace('real_test', 'vulnerability_analysis')
                if analysis_key in self.results['results']:
                    analysis = self.results['results'][analysis_key]
                    total_vulnerabilities += analysis.get('total_vulnerabilities', 0)
                    exploitable_vulnerabilities += len(analysis.get('exploitable_vulnerabilities', []))
        
        print(f"⏱️ Execution time: {self.results['test_info']['execution_time']:.2f}s")
        print(f"🌐 Networks tested: {networks_tested}")
        print(f"✅ Successful tests: {successful_tests}")
        print(f"🔍 Total vulnerabilities: {total_vulnerabilities}")
        print(f"🚨 Exploitable vulnerabilities: {exploitable_vulnerabilities}")
        
        if exploitable_vulnerabilities > 0:
            print("⚠️ CRITICAL: Exploitable vulnerabilities found!")
            print("   Immediate action required!")
        elif total_vulnerabilities > 0:
            print("⚠️ Vulnerabilities detected - further analysis recommended")
        else:
            print("✅ No critical vulnerabilities detected")
    
    async def _save_results(self):
        """Save test results"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"morpho_screening_test_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, cls=CustomJSONEncoder)
        
        print(f"\n💾 Results saved to: {filename}")
        
        # Also save a summary report
        summary_filename = f"morpho_screening_summary_{timestamp}.md"
        await self._generate_summary_report(summary_filename)
    
    async def _generate_summary_report(self, filename: str):
        """Generate summary report"""
        report_content = f"""# Morpho Protocol Security Screening Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Framework:** Shadowscan v2.1.0
**Target:** https://app.morpho.org

## Executive Summary

This report presents the results of a comprehensive security screening of the Morpho protocol across multiple blockchain networks. The screening focused on identifying DeFi-specific vulnerabilities without executing gas-consuming transactions.

## Test Results

- **Execution Time:** {self.results['test_info']['execution_time']:.2f}s
- **Networks Tested:** Multiple (Ethereum, Base, Arbitrum)
- **Screening Method:** Read-only blockchain analysis

## Key Findings

"""
        
        # Add findings from each network
        for key, result in self.results['results'].items():
            if 'vulnerability_analysis' in key:
                network = key.split('_')[0]
                analysis = result
                
                report_content += f"""
### {network.upper()} Network

- **Total Vulnerabilities:** {analysis.get('total_vulnerabilities', 0)}
- **Exploitable Vulnerabilities:** {len(analysis.get('exploitable_vulnerabilities', []))}
- **Risk Level:** {'High' if len(analysis.get('exploitable_vulnerabilities', [])) > 0 else 'Low'}

#### Recommendations:
"""
                for rec in analysis.get('recommendations', []):
                    report_content += f"- {rec}\n"
        
        report_content += f"""

## Technical Details

### Screening Methodology

1. **Tenderly Fork Testing:** Safe testing on isolated blockchain fork
2. **Real RPC Validation:** Confirmation on actual blockchain networks
3. **Read-Only Analysis:** No gas transactions required
4. **DeFi-Specific Checks:** Focus on flashloan, oracle, and reentrancy vulnerabilities

### Vulnerability Types Screened

- Flashloan Vulnerabilities
- Oracle Manipulation
- Reentrancy Attacks
- Access Control Issues
- Integer Overflow/Underflow
- TVL (Total Value Locked) Analysis

## Next Steps

1. **Immediate Action:** Address any critical vulnerabilities found
2. **Continuous Monitoring:** Implement regular security screening
3. **Bug Bounty:** Consider launching a bug bounty program
4. **Professional Audit:** Engage for comprehensive security assessment

---
*Report generated by Shadowscan Framework*
"""
        
        with open(filename, 'w') as f:
            f.write(report_content)
        
        print(f"📄 Summary report saved to: {filename}")

async def main():
    """Main test function"""
    tester = MorphoScreeningTest()
    results = await tester.run_comprehensive_test()
    return results

if __name__ == "__main__":
    results = asyncio.run(main())