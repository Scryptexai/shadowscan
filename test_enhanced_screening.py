#!/usr/bin/env python3
"""
Test Enhanced Screening Capabilities
Validate the enhanced vulnerability detection system
"""

import asyncio
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Add enhanced screening to path
sys.path.insert(0, str(project_root / 'shadowscan' / 'enhanced_screening'))

from enhanced_engine import EnhancedScreeningEngine
from deep_scans.deep_scan_engine import DeepScanEngine, DeepScanIntensity
from detectors.enhanced_detector import EnhancedVulnerabilityDetector
from web3 import Web3

async def test_enhanced_screening():
    """Test enhanced screening functionality"""
    print("🧪 Testing Enhanced Screening System")
    print("=" * 50)
    
    # Test configuration
    target_contract = "0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3"
    rpc_url = os.getenv('TENDERLY_RPC')
    
    if not rpc_url:
        print("❌ TENDERLY_RPC not found in environment")
        return False
    
    try:
        # Initialize Web3
        web3 = Web3(Web3.HTTPProvider(rpc_url))
        if not web3.is_connected():
            print("❌ Failed to connect to RPC")
            return False
        
        print("✅ Web3 connection established")
        
        # Test 1: Enhanced Vulnerability Detector
        print("\n🔬 Test 1: Enhanced Vulnerability Detector")
        print("-" * 40)
        
        detector = EnhancedVulnerabilityDetector(web3)
        
        # Test deep scan
        deep_scan_result = await detector.deep_scan_contract(
            contract_address=target_contract,
            scan_depth="deep",
            vulnerability_types=["reentrancy", "flashloan", "access_control"],
            intensity="deep"
        )
        
        print(f"✅ Deep scan completed")
        print(f"   Vulnerabilities found: {len(deep_scan_result.vulnerabilities)}")
        print(f"   Code coverage: {deep_scan_result.code_coverage:.1f}%")
        print(f"   Execution time: {deep_scan_result.execution_time:.2f}s")
        
        # Test 2: Enhanced Screening Engine
        print("\n🚀 Test 2: Enhanced Screening Engine")
        print("-" * 40)
        
        enhanced_engine = EnhancedScreeningEngine(rpc_url)
        
        enhanced_result = await enhanced_engine.run_enhanced_screening(
            target=target_contract,
            chain='ethereum',
            mode='fork',
            scan_depth='deep',
            vulnerability_types=['reentrancy', 'flashloan'],
            intensity='deep',
            opts={'output': 'test_output/enhanced'}
        )
        
        if enhanced_result['success']:
            print("✅ Enhanced screening completed successfully")
            
            enhanced_summary = enhanced_result.get('enhanced_report', {})
            enhanced_metrics = enhanced_summary.get('enhanced_metrics', {})
            
            print(f"   Deep vulnerabilities: {enhanced_metrics.get('deep_vulnerabilities_found', 0)}")
            print(f"   Scan depth: {enhanced_metrics.get('scan_depth', 'unknown')}")
            print(f"   Analysis methods: {', '.join(enhanced_metrics.get('analysis_methods_used', []))}")
            
            ecosystem = enhanced_summary.get('ecosystem_analysis', {})
            print(f"   Ecosystem risk: {ecosystem.get('ecosystem_risk_score', 0):.2f}")
        else:
            print("❌ Enhanced screening failed")
            return False
        
        # Test 3: Deep Scan Engine
        print("\n🔍 Test 3: Deep Scan Engine")
        print("-" * 40)
        
        deep_engine = DeepScanEngine(web3)
        
        # Test deep scan for reentrancy
        deep_finding = await deep_engine.deep_scan_vulnerability(
            contract_address=target_contract,
            vulnerability_type="reentrancy",
            intensity=DeepScanIntensity.DEEP,
            timeout=600
        )
        
        print("✅ Deep scan vulnerability completed")
        print(f"   Vulnerability: {deep_finding.vulnerability_type}")
        print(f"   Severity: {deep_finding.severity.upper()}")
        print(f"   Confidence: {deep_finding.confidence:.1%}")
        print(f"   Exploitability: {deep_finding.exploitability_score:.1%}")
        print(f"   Symbolic paths: {len(deep_finding.symbolic_paths)}")
        print(f"   Taint flows: {len(deep_finding.taint_flows)}")
        print(f"   Attack vectors: {len(deep_finding.attack_vectors)}")
        
        # Test 4: Configuration Loading
        print("\n⚙️  Test 4: Configuration System")
        print("-" * 40)
        
        config = detector.config
        vuln_types = config.get('vulnerability_types', {})
        
        total_vulns = sum(len(category) for category in vuln_types.values())
        print(f"✅ Configuration loaded successfully")
        print(f"   Vulnerability categories: {len(vuln_types)}")
        print(f"   Total vulnerability types: {total_vulns}")
        
        # Show some example vulnerability types
        for category, vulns in list(vuln_types.items())[:3]:  # Show first 3 categories
            print(f"   {category}: {', '.join(list(vulns.keys())[:2])}")  # Show first 2 per category
        
        print("\n🎉 All Enhanced Screening Tests Passed!")
        print("\n📊 Summary:")
        print(f"   ✅ Enhanced Detector: Operational")
        print(f"   ✅ Enhanced Engine: Operational") 
        print(f"   ✅ Deep Scan Engine: Operational")
        print(f"   ✅ Configuration System: Operational")
        print(f"   ✅ Total vuln types supported: {total_vulns}")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    """Main test function"""
    print("🚀 Enhanced Screening System Test")
    print("=" * 60)
    
    success = await test_enhanced_screening()
    
    if success:
        print("\n🎉 Enhanced Screening System is fully operational!")
        print("\n📋 Available Commands:")
        print("   shadowscan enhanced scan -t 0xTarget -d deep")
        print("   shadowscan enhanced vulns")
        print("   shadowscan enhanced deep -v reentrancy")
        print("   shadowscan enhanced ecosystem")
        print("\n🔧 Ready for deep vulnerability analysis!")
        sys.exit(0)
    else:
        print("\n❌ Enhanced Screening System has issues")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())