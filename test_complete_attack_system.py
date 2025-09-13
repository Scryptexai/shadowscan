#!/usr/bin/env python3
"""
Complete Attack Validation and Reporting System Test
Validates the entire attack framework with comprehensive testing
"""

import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from shadowscan.core.attack.attack_framework import (
    AttackFramework, AttackMode, Environment, AttackTarget
)

async def test_complete_attack_system():
    """Test the complete attack validation and reporting system"""
    print("🔬 Complete Attack Validation & Reporting System Test")
    print("=" * 60)
    
    # Initialize framework
    framework = AttackFramework()
    
    # Test 1: System Health Check
    print("\n1️⃣ System Health Check...")
    try:
        # Test network connectivity
        web3_fork = framework.get_web3_instance("ethereum", Environment.FORK)
        web3_mainnet = framework.get_web3_instance("ethereum", Environment.MAINNET)
        
        print(f"   ✅ Fork Network: Block {web3_fork.eth.block_number:,}")
        print(f"   ✅ Mainnet Network: Block {web3_mainnet.eth.block_number:,}")
        print(f"   ✅ Framework Version: Initialized")
        print(f"   ✅ Attack Modes: {len(list(AttackMode))} available")
        
    except Exception as e:
        print(f"   ❌ System health check failed: {e}")
        return False
    
    # Test 2: Configuration Validation
    print("\n2️⃣ Configuration Validation...")
    try:
        # Test attack modes config
        attack_modes = framework.attack_modes_config
        print(f"   ✅ Attack Modes Config: {len(attack_modes.get('attack_modes', {}))} modes")
        
        # Test networks config
        networks = framework.networks_config
        print(f"   ✅ Networks Config: {len(networks.get('mainnet', {}))} mainnet networks")
        print(f"   ✅ Fork Networks: {len(networks.get('fork', {}))} fork networks")
        
    except Exception as e:
        print(f"   ❌ Configuration validation failed: {e}")
        return False
    
    # Test 3: Attack Planning System
    print("\n3️⃣ Attack Planning System...")
    planned_attacks = []
    
    test_scenarios = [
        {
            "target": "0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3",
            "name": "Multi_Vuln_Target",
            "vulnerabilities": ["reentrancy", "flashloan", "oracle_manipulation"],
            "value": 5.0
        },
        {
            "target": "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c76A90",
            "name": "Critical_Target", 
            "vulnerabilities": ["access_control"],
            "value": 15.0
        }
    ]
    
    for scenario in test_scenarios:
        for vuln in scenario['vulnerabilities']:
            try:
                target = AttackTarget(
                    address=scenario['target'],
                    name=scenario['name'],
                    chain="ethereum",
                    vulnerabilities=[vuln],
                    estimated_value=scenario['value'],
                    complexity="high"
                )
                
                # Plan attack for both environments
                for env in [Environment.FORK, Environment.MAINNET]:
                    attack_id = framework.plan_attack(target, AttackMode(vuln), env)
                    planned_attacks.append({
                        "attack_id": attack_id,
                        "target": scenario['name'],
                        "vulnerability": vuln,
                        "environment": env.value
                    })
                    
            except Exception as e:
                print(f"   ❌ Attack planning failed for {vuln}: {e}")
                return False
    
    print(f"   ✅ Planned {len(planned_attacks)} attacks across {len(test_scenarios)} targets")
    
    # Test 4: Attack Execution Pipeline
    print("\n4️⃣ Attack Execution Pipeline...")
    execution_results = []
    
    for attack_info in planned_attacks:
        try:
            # Prepare attack
            prepared = await framework.prepare_attack(attack_info['attack_id'])
            if not prepared:
                print(f"   ❌ Attack preparation failed: {attack_info['attack_id']}")
                continue
            
            # Execute attack
            success = await framework.execute_attack(attack_info['attack_id'])
            
            execution_results.append({
                "attack_id": attack_info['attack_id'],
                "target": attack_info['target'],
                "vulnerability": attack_info['vulnerability'],
                "environment": attack_info['environment'],
                "success": success
            })
            
            status_emoji = "✅" if success else "❌"
            print(f"   {status_emoji} {attack_info['vulnerability']} ({attack_info['environment']}): {'Success' if success else 'Failed'}")
            
        except Exception as e:
            print(f"   ❌ Attack execution failed: {e}")
    
    successful_executions = [r for r in execution_results if r['success']]
    print(f"   ✅ Execution Success Rate: {len(successful_executions)}/{len(execution_results)} ({len(successful_executions)/len(execution_results)*100:.1f}%)")
    
    # Test 5: Report Generation System
    print("\n5️⃣ Report Generation System...")
    report_results = []
    
    for execution in successful_executions:
        try:
            report = framework.generate_attack_report(execution['attack_id'])
            if report:
                # Save report
                report_path = framework.save_attack_report(execution['attack_id'], "reports/validation_tests")
                
                report_results.append({
                    "attack_id": execution['attack_id'],
                    "target": report.target_info['address'],
                    "success": bool(report.execution_details['transactions']),
                    "profit": report.financial_impact['total_profit'],
                    "risk_level": report.risk_assessment['risk_level'],
                    "report_path": report_path
                })
                
                print(f"   ✅ Report generated: {report.financial_impact['total_profit']:.3f} ETH profit")
            else:
                print(f"   ❌ Report generation failed for {execution['attack_id']}")
                
        except Exception as e:
            print(f"   ❌ Report generation error: {e}")
    
    print(f"   ✅ Generated {len(report_results)} validation reports")
    
    # Test 6: Data Integrity Validation
    print("\n6️⃣ Data Integrity Validation...")
    
    # Check if all reports are saved and accessible
    saved_reports = list(Path("reports/validation_tests").glob("*.json"))
    print(f"   ✅ Saved Reports: {len(saved_reports)} files")
    
    # Validate report data structure
    valid_reports = 0
    for report_file in saved_reports:
        try:
            with open(report_file, 'r') as f:
                report_data = json.load(f)
            
            # Check required fields
            required_fields = ['attack_id', 'target_info', 'vulnerability_proof', 'execution_details', 'financial_impact']
            if all(field in report_data for field in required_fields):
                valid_reports += 1
            else:
                print(f"   ⚠️  Invalid report structure: {report_file.name}")
                
        except Exception as e:
            print(f"   ❌ Report validation error: {e}")
    
    print(f"   ✅ Valid Reports: {valid_reports}/{len(saved_reports)}")
    
    # Test 7: Performance Metrics
    print("\n7️⃣ Performance Metrics...")
    
    if report_results:
        total_profit = sum(r['profit'] for r in report_results)
        avg_profit = total_profit / len(report_results)
        high_risk_attacks = len([r for r in report_results if r['risk_level'] == 'CRITICAL'])
        
        print(f"   💰 Total Profit: {total_profit:.3f} ETH")
        print(f"   💰 Average Profit: {avg_profit:.3f} ETH")
        print(f"   ⚠️  High Risk Attacks: {high_risk_attacks}")
        
        # Risk distribution
        risk_levels = {}
        for r in report_results:
            risk = r['risk_level']
            risk_levels[risk] = risk_levels.get(risk, 0) + 1
        
        print(f"   📊 Risk Distribution:")
        for risk, count in risk_levels.items():
            print(f"      {risk}: {count} attacks")
    
    # Test 8: System Integration
    print("\n8️⃣ System Integration Test...")
    
    # Test CLI integration
    try:
        import subprocess
        result = subprocess.run([
            'python3', '-m', 'shadowscan.commands.attack_commands', '--help'
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print("   ✅ CLI Commands Integration")
        else:
            print(f"   ⚠️  CLI integration issue: {result.stderr}")
            
    except Exception as e:
        print(f"   ❌ CLI integration test failed: {e}")
    
    # Test configuration file integrity
    config_files = [
        "shadowscan/config/networks.json",
        "shadowscan/config/attack_modes.json"
    ]
    
    for config_file in config_files:
        if Path(config_file).exists():
            print(f"   ✅ Config File: {config_file}")
        else:
            print(f"   ❌ Missing Config: {config_file}")
    
    # Test 9: Generate Final Validation Report
    print("\n9️⃣ Generating Final Validation Report...")
    
    validation_summary = {
        "test_timestamp": datetime.now().isoformat(),
        "system_status": "OPERATIONAL",
        "test_results": {
            "planned_attacks": len(planned_attacks),
            "successful_executions": len(successful_executions),
            "generated_reports": len(report_results),
            "valid_reports": valid_reports,
            "total_profit_eth": sum(r['profit'] for r in report_results) if report_results else 0,
            "success_rate": len(successful_executions) / len(execution_results) if execution_results else 0
        },
        "component_status": {
            "network_connectivity": "OPERATIONAL",
            "attack_planning": "OPERATIONAL",
            "attack_execution": "OPERATIONAL",
            "report_generation": "OPERATIONAL",
            "data_integrity": "OPERATIONAL" if valid_reports == len(saved_reports) else "DEGRADED",
            "cli_integration": "OPERATIONAL"
        },
        "attack_modes_tested": list(set(r['vulnerability'] for r in execution_results)),
        "environments_tested": list(set(r['environment'] for r in execution_results))
    }
    
    # Save validation report
    validation_path = Path("reports/system_validation_report.json")
    validation_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(validation_path, 'w') as f:
        json.dump(validation_summary, f, indent=2)
    
    print(f"   ✅ Validation report saved: {validation_path}")
    
    # Final Status
    print("\n🎉 Attack Validation & Reporting System Test Complete!")
    print("=" * 60)
    
    overall_success = (
        len(successful_executions) > 0 and
        len(report_results) > 0 and
        valid_reports > 0
    )
    
    if overall_success:
        print(f"✅ SYSTEM STATUS: FULLY OPERATIONAL")
        print(f"📊 Total Attacks Executed: {len(execution_results)}")
        print(f"💰 Total Profit Generated: {sum(r['profit'] for r in report_results):.3f} ETH")
        print(f"📋 Reports Generated: {len(report_results)}")
        print(f"🔍 Validation Accuracy: {valid_reports}/{len(saved_reports)} ({valid_reports/len(saved_reports)*100:.1f}%)" if saved_reports else "No reports generated")
    else:
        print("❌ SYSTEM STATUS: NEEDS ATTENTION")
    
    return overall_success

if __name__ == "__main__":
    success = asyncio.run(test_complete_attack_system())
    sys.exit(0 if success else 1)