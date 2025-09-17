#!/usr/bin/env python3
"""
SHADOWSCAN Quick Test - Single Target Validation
"""

import asyncio
import json
import sys
import os
import time
from datetime import datetime

# Add framework ke path
sys.path.append('/home/nurkahfi/MyProject/shadowscan/modules/web_claim_dex_framework')

from real_exploit_framework import RealExploitFramework
from real_time_validator import RealTimeValidator

async def quick_test():
    """Quick test of Shadowscan framework"""
    print("🚀 SHADOWSCAN QUICK TEST")
    print("=" * 50)
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🎯 Target: https://app.free.tech")
    print("=" * 50)
    
    framework = RealExploitFramework()
    validator = RealTimeValidator()
    
    results = {
        'test_info': {
            'start_time': datetime.now().isoformat(),
            'target': 'https://app.free.tech',
            'framework': 'Shadowscan v2.0.0'
        },
        'results': {}
    }
    
    start_time = time.time()
    
    try:
        # Step 1: Quick Analysis
        print("🔍 Step 1: Target Analysis")
        analysis = await framework.analyze_target("https://app.free.tech")
        
        results['results']['analysis'] = {
            'technologies': len(analysis.technology_stack),
            'vulnerabilities': len(analysis.vulnerabilities),
            'risk_level': analysis.risk_level,
            'attack_surface': len(analysis.attack_surface)
        }
        
        print(f"   ✅ {len(analysis.vulnerabilities)} vulnerabilities found")
        print(f"   ✅ Risk level: {analysis.risk_level}")
        
        # Step 2: Quick Exploitation
        print("\n💥 Step 2: Quick Exploitation")
        exploit_results = await framework.execute_exploit_chain("https://app.free.tech", "free_tech_exploit")
        
        successful_exploits = [r for r in exploit_results if r.success]
        results['results']['exploitation'] = {
            'total_exploits': len(exploit_results),
            'successful_exploits': len(successful_exploits),
            'success_rate': len(successful_exploits) / len(exploit_results) if exploit_results else 0
        }
        
        print(f"   ✅ {len(successful_exploits)}/{len(exploit_results)} exploits successful")
        
        # Step 3: Quick Validation
        print("\n🔬 Step 3: Quick Validation")
        
        # Test one vulnerability
        test_vulnerability = {
            'type': 'ssrf',
            'payload': '/api/_nextjs_static_data',
            'description': 'Next.js SSRF vulnerability',
            'target': 'https://app.free.tech'
        }
        
        validation_result = await validator.validate_vulnerability("https://app.free.tech", test_vulnerability)
        
        results['results']['validation'] = {
            'vulnerability_valid': validation_result.is_valid,
            'confidence': validation_result.confidence,
            'exploitation_success': validation_result.exploitation_success,
            'validation_method': validation_result.validation_method
        }
        
        print(f"   ✅ Vulnerability valid: {validation_result.is_valid}")
        print(f"   ✅ Confidence: {validation_result.confidence:.2f}")
        print(f"   ✅ Exploitation success: {validation_result.exploitation_success}")
        
        # Calculate execution time
        execution_time = time.time() - start_time
        results['test_info']['execution_time'] = execution_time
        results['test_info']['end_time'] = datetime.now().isoformat()
        
        # Summary
        print(f"\n📊 QUICK TEST SUMMARY")
        print("=" * 30)
        print(f"⏱️ Execution time: {execution_time:.2f}s")
        print(f"🎯 Target: https://app.free.tech")
        print(f"🔍 Vulnerabilities found: {len(analysis.vulnerabilities)}")
        print(f"💥 Exploits successful: {len(successful_exploits)}/{len(exploit_results)}")
        print(f"🔬 Validation success: {validation_result.is_valid}")
        print(f"🚀 Real exploitation: {validation_result.exploitation_success}")
        
        if validation_result.exploitation_success and validation_result.exploitation_details:
            details = validation_result.exploitation_details
            print(f"💥 EXPLOITATION SUCCESS!")
            print(f"   Type: {details.get('exploit_type', 'unknown')}")
            print(f"   Details: {details.get('details', 'No details')}")
            if details.get('response_size'):
                print(f"   Data accessed: {details.get('response_size')} bytes")
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"shadowscan_quick_test_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n💾 Results saved to: {filename}")
        
        return results
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    asyncio.run(quick_test())