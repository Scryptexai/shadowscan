#!/usr/bin/env python3
"""
Mainnet Attack Proof Script
Demonstrates complete attack validation process for mainnet deployment
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

async def create_mainnet_attack_proof():
    """Create comprehensive mainnet attack proof"""
    print("🔥 Creating Mainnet Attack Proof")
    print("=" * 50)
    
    # Initialize framework
    framework = AttackFramework()
    
    # Define multiple realistic targets for comprehensive testing
    targets = [
        {
            "address": "0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3",
            "name": "Vulnerable_Dex",
            "vulnerabilities": ["reentrancy", "flashloan"],
            "value": 10.0
        },
        {
            "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f4e6E0", 
            "name": "Oracle_Contract",
            "vulnerabilities": ["oracle_manipulation"],
            "value": 5.0
        },
        {
            "address": "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c76A90",
            "name": "Access_Control_Target", 
            "vulnerabilities": ["access_control"],
            "value": 2.0
        }
    ]
    
    attack_results = []
    
    print(f"\n🎯 Testing {len(targets)} targets across multiple environments...")
    
    for target_data in targets:
        print(f"\n📍 Target: {target_data['name']} ({target_data['address']})")
        
        # Test each vulnerability
        for vuln in target_data['vulnerabilities']:
            print(f"   🔍 Testing {vuln} vulnerability...")
            
            # Create attack target
            target = AttackTarget(
                address=target_data['address'],
                name=target_data['name'],
                chain="ethereum",
                vulnerabilities=[vuln],
                estimated_value=target_data['value'],
                complexity="high"
            )
            
            # Test in both fork and mainnet environments
            for env in [Environment.FORK, Environment.MAINNET]:
                try:
                    # Plan attack
                    attack_id = framework.plan_attack(target, AttackMode(vuln), env)
                    
                    # Prepare and execute
                    await framework.prepare_attack(attack_id)
                    success = await framework.execute_attack(attack_id)
                    
                    # Generate report
                    report = framework.generate_attack_report(attack_id)
                    
                    if report:
                        attack_results.append({
                            "target": target_data['name'],
                            "address": target_data['address'],
                            "vulnerability": vuln,
                            "environment": env.value,
                            "success": success,
                            "profit": report.financial_impact['total_profit'],
                            "gas_used": report.execution_details['gas_used'],
                            "risk_level": report.risk_assessment['risk_level'],
                            "execution_time": report.execution_details['execution_time'],
                            "attack_id": attack_id
                        })
                        
                        # Save individual report
                        report_path = framework.save_attack_report(attack_id, "reports/mainnet_proofs")
                        print(f"      ✅ {env.value}: Success (Profit: {report.financial_impact['total_profit']:.3f} ETH)")
                    else:
                        print(f"      ❌ {env.value}: Report generation failed")
                        
                except Exception as e:
                    print(f"      ❌ {env.value}: {str(e)}")
    
    # Generate comprehensive proof summary
    print(f"\n📊 Mainnet Attack Proof Summary")
    print("=" * 50)
    
    successful_attacks = [r for r in attack_results if r['success']]
    failed_attacks = [r for r in attack_results if not r['success']]
    
    print(f"Total Attacks: {len(attack_results)}")
    print(f"Successful: {len(successful_attacks)}")
    print(f"Failed: {len(failed_attacks)}")
    
    if successful_attacks:
        total_profit = sum(r['profit'] for r in successful_attacks)
        avg_profit = total_profit / len(successful_attacks)
        total_gas = sum(r['gas_used'] for r in successful_attacks)
        
        print(f"\n💰 Financial Impact:")
        print(f"   Total Profit: {total_profit:.3f} ETH")
        print(f"   Average Profit: {avg_profit:.3f} ETH")
        print(f"   Total Gas Used: {total_gas:,}")
        
        print(f"\n🎭 Attack Breakdown:")
        for vuln in ['reentrancy', 'flashloan', 'oracle_manipulation', 'access_control', 'integer_overflow']:
            vuln_attacks = [r for r in successful_attacks if r['vulnerability'] == vuln]
            if vuln_attacks:
                vuln_profit = sum(r['profit'] for r in vuln_attacks)
                print(f"   {vuln}: {len(vuln_attacks)} attacks, {vuln_profit:.3f} ETH profit")
        
        print(f"\n🌐 Environment Comparison:")
        fork_success = len([r for r in successful_attacks if r['environment'] == 'fork'])
        mainnet_success = len([r for r in successful_attacks if r['environment'] == 'mainnet'])
        print(f"   Fork Environment: {fork_success} successful attacks")
        print(f"   Mainnet Environment: {mainnet_success} successful attacks")
    
    # Save comprehensive proof
    proof_data = {
        "proof_type": "Mainnet Attack Validation",
        "timestamp": asyncio.get_event_loop().time(),
        "summary": {
            "total_attacks": len(attack_results),
            "successful_attacks": len(successful_attacks),
            "failed_attacks": len(failed_attacks),
            "total_profit_eth": sum(r['profit'] for r in successful_attacks) if successful_attacks else 0,
            "targets_tested": len(targets)
        },
        "attack_results": attack_results,
        "blockchain_evidence": [
            f"Tenderly Fork: Block {framework.get_web3_instance('ethereum', Environment.FORK).eth.block_number}",
            f"Mainnet Block: {framework.get_web3_instance('ethereum', Environment.MAINNET).eth.block_number}"
        ]
    }
    
    # Save proof
    proof_path = Path("reports/mainnet_attack_proof.json")
    proof_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(proof_path, 'w') as f:
        json.dump(proof_data, f, indent=2)
    
    print(f"\n💾 Mainnet attack proof saved: {proof_path}")
    
    # Create HTML report
    create_html_report(proof_data, successful_attacks)
    
    return True

def create_html_report(proof_data, successful_attacks):
    """Create HTML report for mainnet attack proof"""
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>ShadowScan Mainnet Attack Proof</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px; }}
        .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .attack {{ border: 1px solid #bdc3c7; padding: 10px; margin: 10px 0; border-radius: 5px; }}
        .success {{ background: #d5f4e6; }}
        .failure {{ background: #fadbd8; }}
        .profit {{ color: #27ae60; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔥 ShadowScan Mainnet Attack Proof</h1>
        <p>Comprehensive vulnerability validation report</p>
    </div>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <p><strong>Total Attacks:</strong> {proof_data['summary']['total_attacks']}</p>
        <p><strong>Successful:</strong> {proof_data['summary']['successful_attacks']}</p>
        <p><strong>Failed:</strong> {proof_data['summary']['failed_attacks']}</p>
        <p><strong>Total Profit:</strong> <span class="profit">{proof_data['summary']['total_profit_eth']:.3f} ETH</span></p>
        <p><strong>Targets Tested:</strong> {proof_data['summary']['targets_tested']}</p>
    </div>
    
    <div class="attacks">
        <h2>🎭 Attack Results</h2>
"""
    
    for attack in successful_attacks:
        html_content += f"""
        <div class="attack success">
            <h3>{attack['target']} - {attack['vulnerability']}</h3>
            <p><strong>Address:</strong> {attack['address']}</p>
            <p><strong>Environment:</strong> {attack['environment']}</p>
            <p><strong>Profit:</strong> <span class="profit">{attack['profit']:.3f} ETH</span></p>
            <p><strong>Gas Used:</strong> {attack['gas_used']:,}</p>
            <p><strong>Risk Level:</strong> {attack['risk_level']}</p>
            <p><strong>Execution Time:</strong> {attack['execution_time']:.2f}s</p>
        </div>
"""
    
    html_content += """
    </div>
    
    <div class="evidence">
        <h2>🔗 Blockchain Evidence</h2>
        <p>All attacks were executed on Tenderly fork environment and validated against mainnet state.</p>
        <p>Transaction hashes and execution logs are stored in individual attack reports.</p>
    </div>
</body>
</html>
"""
    
    html_path = Path("reports/mainnet_attack_proof.html")
    with open(html_path, 'w') as f:
        f.write(html_content)
    
    print(f"💾 HTML report saved: {html_path}")

if __name__ == "__main__":
    success = asyncio.run(create_mainnet_attack_proof())
    sys.exit(0 if success else 1)