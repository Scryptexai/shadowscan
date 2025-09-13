#!/usr/bin/env python3
"""
Comprehensive Attack Framework Test Script
Tests all core functions of the attack framework
"""

import asyncio
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from shadowscan.core.attack.attack_framework import (
    AttackFramework, AttackMode, Environment, AttackTarget
)

async def test_attack_framework():
    """Test all attack framework functions"""
    print("🧪 Testing ShadowScan Attack Framework")
    print("=" * 50)
    
    # Initialize framework
    framework = AttackFramework()
    
    # Test 1: Create attack target
    print("\n1️⃣ Testing Attack Target Creation...")
    target = AttackTarget(
        address="0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3",
        name="Test_Target",
        chain="ethereum",
        vulnerabilities=["reentrancy"],
        estimated_value=1.0,
        complexity="medium"
    )
    print(f"✅ Target created: {target.address}")
    
    # Test 2: Test network connectivity
    print("\n2️⃣ Testing Network Connectivity...")
    try:
        web3_fork = framework.get_web3_instance("ethereum", Environment.FORK)
        print(f"✅ Fork connected: Block {web3_fork.eth.block_number:,}")
        
        web3_mainnet = framework.get_web3_instance("ethereum", Environment.MAINNET)
        print(f"✅ Mainnet connected: Block {web3_mainnet.eth.block_number:,}")
    except Exception as e:
        print(f"❌ Network connection failed: {e}")
        return False
    
    # Test 3: Plan attack
    print("\n3️⃣ Testing Attack Planning...")
    try:
        attack_id = framework.plan_attack(
            target=target,
            mode=AttackMode.REENTRANCY,
            environment=Environment.FORK
        )
        print(f"✅ Attack planned: {attack_id}")
    except Exception as e:
        print(f"❌ Attack planning failed: {e}")
        return False
    
    # Test 4: Check attack status
    print("\n4️⃣ Testing Attack Status...")
    try:
        status = framework.get_attack_status(attack_id)
        if status:
            print(f"✅ Attack status: {status['status']}")
            print(f"   Target: {status['target']}")
            print(f"   Mode: {status['mode']}")
        else:
            print("❌ Attack status not found")
            return False
    except Exception as e:
        print(f"❌ Status check failed: {e}")
        return False
    
    # Test 5: Prepare attack
    print("\n5️⃣ Testing Attack Preparation...")
    try:
        prepared = await framework.prepare_attack(attack_id)
        if prepared:
            print("✅ Attack preparation successful")
        else:
            print("❌ Attack preparation failed")
            return False
    except Exception as e:
        print(f"❌ Attack preparation failed: {e}")
        return False
    
    # Test 6: Execute attack
    print("\n6️⃣ Testing Attack Execution...")
    try:
        success = await framework.execute_attack(attack_id)
        if success:
            print("✅ Attack execution successful")
        else:
            print("❌ Attack execution failed")
            # Check for error details
            status = framework.get_attack_status(attack_id)
            if status and status.get('error_message'):
                print(f"   Error: {status['error_message']}")
            return False
    except Exception as e:
        print(f"❌ Attack execution failed: {e}")
        return False
    
    # Test 7: Generate report
    print("\n7️⃣ Testing Report Generation...")
    try:
        report = framework.generate_attack_report(attack_id)
        if report:
            print("✅ Attack report generated")
            print(f"   Target: {report.target_info['address']}")
            print(f"   Success: {report.execution_details['transactions']}")
            print(f"   Profit: {report.financial_impact['total_profit']:.6f} ETH")
        else:
            print("❌ Report generation failed")
            return False
    except Exception as e:
        print(f"❌ Report generation failed: {e}")
        return False
    
    # Test 8: Save report
    print("\n8️⃣ Testing Report Saving...")
    try:
        report_path = framework.save_attack_report(attack_id)
        if report_path:
            print(f"✅ Report saved: {report_path}")
        else:
            print("❌ Report saving failed")
            return False
    except Exception as e:
        print(f"❌ Report saving failed: {e}")
        return False
    
    # Test 9: Test multiple attack modes
    print("\n9️⃣ Testing Multiple Attack Modes...")
    modes_to_test = [
        AttackMode.REENTRANCY,
        AttackMode.FLASHLOAN,
        AttackMode.ORACLE_MANIPULATION,
        AttackMode.ACCESS_CONTROL,
        AttackMode.INTEGER_OVERFLOW
    ]
    
    for mode in modes_to_test:
        try:
            attack_id = framework.plan_attack(target, mode, Environment.FORK)
            await framework.prepare_attack(attack_id)
            success = await framework.execute_attack(attack_id)
            
            status_emoji = "✅" if success else "❌"
            print(f"   {status_emoji} {mode.value}: {'Success' if success else 'Failed'}")
            
        except Exception as e:
            print(f"   ❌ {mode.value}: {e}")
    
    # Test 10: Test different environments
    print("\n🔟 Testing Different Environments...")
    environments = [Environment.FORK, Environment.MAINNET]
    
    for env in environments:
        try:
            attack_id = framework.plan_attack(target, AttackMode.REENTRANCY, env)
            await framework.prepare_attack(attack_id)
            success = await framework.execute_attack(attack_id)
            
            status_emoji = "✅" if success else "❌"
            print(f"   {status_emoji} {env.value}: {'Success' if success else 'Failed'}")
            
        except Exception as e:
            print(f"   ❌ {env.value}: {e}")
    
    print("\n🎉 Attack Framework Testing Complete!")
    return True

if __name__ == "__main__":
    success = asyncio.run(test_attack_framework())
    sys.exit(0 if success else 1)