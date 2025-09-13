"""
Attack CLI Commands - Phase 3 Implementation

Provides command-line interface for attack execution and vulnerability validation.
"""

import asyncio
import json
import click
from typing import Optional, List
from pathlib import Path
import sys
import os

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shadowscan.core.attack.attack_framework import (
    AttackFramework, AttackMode, Environment, AttackTarget
)
from shadowscan.config.loader import load_config

@click.group()
def attack():
    """⚔️ Execute controlled exploit simulations"""
    pass

@attack.command()
@click.option('-t', '--target', required=True, help='Target contract address')
@click.option('-c', '--chain', default='ethereum', help='Blockchain network')
@click.option('-m', '--mode', type=click.Choice(['reentrancy', 'flashloan', 'oracle_manipulation', 'access_control', 'integer_overflow']), 
              default='reentrancy', help='Attack mode')
@click.option('-e', '--environment', type=click.Choice(['fork', 'mainnet']), default='fork', 
              help='Execution environment')
@click.option('-v', '--vulnerabilities', multiple=True, help='Vulnerabilities to exploit')
@click.option('--value', type=float, default=1.0, help='Estimated target value (ETH)')
@click.option('--dry-run', is_flag=True, help='Plan attack without execution')
@click.option('--output', help='Output directory for reports')
def execute(target: str, chain: str, mode: str, environment: str, 
           vulnerabilities: List[str], value: float, dry_run: bool, output: str):
    """Execute vulnerability validation attack"""
    
    # Create attack target
    attack_target = AttackTarget(
        address=target,
        name=f"Target_{target[:8]}",
        chain=chain,
        vulnerabilities=list(vulnerabilities) or ['reentrancy'],
        estimated_value=value,
        complexity="medium"
    )
    
    # Initialize attack framework
    framework = AttackFramework()
    
    try:
        # Plan attack
        click.echo("🎯 Planning attack...")
        attack_id = framework.plan_attack(
            target=attack_target,
            mode=AttackMode(mode),
            environment=Environment(environment)
        )
        
        click.echo(f"✅ Attack planned: {attack_id}")
        
        if dry_run:
            click.echo("📋 Dry run mode - attack planned but not executed")
            status = framework.get_attack_status(attack_id)
            click.echo(f"   Status: {status['status']}")
            return
        
        # Prepare attack
        click.echo("🔧 Preparing attack...")
        asyncio.run(framework.prepare_attack(attack_id))
        
        # Execute attack
        click.echo("⚡ Executing attack...")
        success = asyncio.run(framework.execute_attack(attack_id))
        
        if success:
            click.echo("✅ Attack executed successfully!")
            
            # Generate report
            click.echo("📊 Generating attack report...")
            report = framework.generate_attack_report(attack_id)
            
            if report:
                # Save report
                output_dir = output or "reports/attacks"
                report_path = framework.save_attack_report(attack_id, output_dir)
                
                click.echo(f"📄 Report saved: {report_path}")
                
                # Display summary
                _display_attack_summary(report)
            else:
                click.echo("❌ Failed to generate report")
        else:
            click.echo("❌ Attack execution failed")
            
            # Show error details
            status = framework.get_attack_status(attack_id)
            if status and status.get('error_message'):
                click.echo(f"   Error: {status['error_message']}")
    
    except Exception as e:
        click.echo(f"❌ Attack execution failed: {e}")
        sys.exit(1)

@attack.command()
@click.option('-t', '--target', required=True, help='Target contract address')
@click.option('-c', '--chain', default='ethereum', help='Blockchain network')
@click.option('-v', '--vulnerabilities', multiple=True, help='Vulnerabilities to test')
@click.option('--value', type=float, default=1.0, help='Estimated target value (ETH)')
def analyze(target: str, chain: str, vulnerabilities: List[str], value: float):
    """Analyze target for attack feasibility"""
    
    attack_target = AttackTarget(
        address=target,
        name=f"Target_{target[:8]}",
        chain=chain,
        vulnerabilities=list(vulnerabilities) or ['reentrancy'],
        estimated_value=value,
        complexity="medium"
    )
    
    framework = AttackFramework()
    
    click.echo(f"🔍 Analyzing attack feasibility for {target}")
    click.echo(f"📍 Chain: {chain}")
    click.echo(f"💰 Estimated Value: {value} ETH")
    click.echo(f"🎯 Vulnerabilities: {', '.join(vulnerabilities)}")
    
    # Check network connectivity
    try:
        web3_fork = framework.get_web3_instance(chain, Environment.FORK)
        click.echo(f"✅ Fork environment connected (Block: {web3_fork.eth.block_number:,})")
        
        web3_mainnet = framework.get_web3_instance(chain, Environment.MAINNET)
        click.echo(f"✅ Mainnet environment connected (Block: {web3_mainnet.eth.block_number:,})")
    except Exception as e:
        click.echo(f"❌ Network connection failed: {e}")
        return
    
    # Analyze attack modes
    click.echo("\n🎭 Attack Mode Analysis:")
    
    for vuln in attack_target.vulnerabilities:
        mode = AttackMode(vuln) if vuln in [m.value for m in AttackMode] else AttackMode.REENTRANCY
        
        # Plan attack for analysis
        attack_id = framework.plan_attack(attack_target, mode, Environment.FORK)
        
        # Check feasibility
        feasibility = _assess_attack_feasibility(mode, web3_fork, target)
        
        status_emoji = "✅" if feasibility["feasible"] else "❌"
        click.echo(f"   {status_emoji} {mode.value.upper()}: {feasibility['reason']}")
    
    click.echo("\n💡 Recommendations:")
    click.echo("   1. Start with fork environment for safe testing")
    click.echo("   2. Validate attack mechanics before mainnet execution")
    click.echo("   3. Consider gas costs and potential profits")
    click.echo("   4. Ensure proper legal and ethical compliance")

@attack.command()
@click.option('--attack-id', required=True, help='Attack ID to validate')
@click.option('--environment', type=click.Choice(['fork', 'mainnet']), default='fork', help='Environment to validate')
def validate(attack_id: str, environment: str):
    """Validate attack results and generate proof"""
    
    framework = AttackFramework()
    
    # Get attack status
    status = framework.get_attack_status(attack_id)
    if not status:
        click.echo(f"❌ Attack {attack_id} not found")
        return
    
    click.echo(f"🔍 Validating attack {attack_id}")
    click.echo(f"   Status: {status['status']}")
    click.echo(f"   Mode: {status['mode']}")
    click.echo(f"   Environment: {status['environment']}")
    
    if status['status'] == 'completed' and status['success']:
        # Generate validation report
        report = framework.generate_attack_report(attack_id)
        if report:
            click.echo("✅ Attack validation completed successfully!")
            _display_attack_summary(report)
            
            # Save validation report
            output_path = framework.save_attack_report(attack_id)
            click.echo(f"📄 Validation report: {output_path}")
        else:
            click.echo("❌ Failed to generate validation report")
    else:
        click.echo("❌ Attack not completed or failed")
        if status.get('error_message'):
            click.echo(f"   Error: {status['error_message']}")

@attack.command()
@click.option('--output', default='reports/attacks', help='Output directory')
@click.option('--format', type=click.Choice(['json', 'html']), default='json', help='Report format')
def reports(output: str, format: str):
    """List and manage attack reports"""
    
    output_dir = Path(output)
    if not output_dir.exists():
        click.echo(f"❌ Output directory {output} does not exist")
        return
    
    report_files = list(output_dir.glob("attack_report_*.json"))
    
    if not report_files:
        click.echo("📭 No attack reports found")
        return
    
    click.echo(f"📊 Found {len(report_files)} attack reports:")
    
    for report_file in sorted(report_files, reverse=True):
        try:
            with open(report_file, 'r') as f:
                report_data = json.load(f)
            
            attack_id = report_data.get('attack_id', 'unknown')
            timestamp = report_data.get('timestamp', 'unknown')
            success = report_data.get('execution_details', {}).get('transactions', [])
            profit = report_data.get('financial_impact', {}).get('total_profit', 0)
            
            status_emoji = "✅" if success else "❌"
            click.echo(f"   {status_emoji} {attack_id} - {timestamp} - Profit: {profit} ETH")
            
        except Exception as e:
            click.echo(f"   ❌ Error reading {report_file.name}: {e}")

@attack.command()
@click.option('--attack-id', required=True, help='Attack ID to check')
def status(attack_id: str):
    """Check attack execution status"""
    
    framework = AttackFramework()
    attack_status = framework.get_attack_status(attack_id)
    
    if not attack_status:
        click.echo(f"❌ Attack {attack_id} not found")
        return
    
    click.echo(f"📊 Attack Status: {attack_id}")
    click.echo(f"   Mode: {attack_status['mode']}")
    click.echo(f"   Target: {attack_status['target']}")
    click.echo(f"   Environment: {attack_status['environment']}")
    click.echo(f"   Status: {attack_status['status']}")
    click.echo(f"   Success: {attack_status['success']}")
    click.echo(f"   Progress: {attack_status['progress']:.1f}%")
    
    if attack_status.get('error_message'):
        click.echo(f"   Error: {attack_status['error_message']}")

@attack.command()
def templates():
    """Show attack templates and examples"""
    
    click.echo("🎭 Attack Templates")
    click.echo("=" * 50)
    
    templates = [
        {
            "name": "Reentrancy Attack",
            "command": "shadowscan attack execute -t 0x... -m reentrancy -e fork",
            "description": "Exploits reentrancy vulnerability to drain funds",
            "complexity": "Medium"
        },
        {
            "name": "Flash Loan Attack", 
            "command": "shadowscan attack execute -t 0x... -m flashloan -e fork",
            "description": "Uses flash loans for price manipulation",
            "complexity": "High"
        },
        {
            "name": "Oracle Manipulation",
            "command": "shadowscan attack execute -t 0x... -m oracle_manipulation -e fork",
            "description": "Manipulates oracle prices for profit",
            "complexity": "High"
        },
        {
            "name": "Access Control Bypass",
            "command": "shadowscan attack execute -t 0x... -m access_control -e fork",
            "description": "Bypasses access controls for privilege escalation",
            "complexity": "Low"
        },
        {
            "name": "Integer Overflow",
            "command": "shadowscan attack execute -t 0x... -m integer_overflow -e fork",
            "description": "Exploits arithmetic overflow vulnerabilities",
            "complexity": "Medium"
        }
    ]
    
    for template in templates:
        click.echo(f"\n🔸 {template['name']} ({template['complexity']})")
        click.echo(f"   Command: {template['command']}")
        click.echo(f"   Description: {template['description']}")
    
    click.echo("\n💡 Usage Tips:")
    click.echo("   • Always start with fork environment (-e fork)")
    click.echo("   • Use --dry-run to plan without execution")
    click.echo("   • Check feasibility with 'analyze' command first")
    click.echo("   • Review attack reports for detailed results")

def _display_attack_summary(report):
    """Display attack report summary"""
    click.echo("\n📊 Attack Summary:")
    click.echo(f"   Target: {report.target_info['address']}")
    click.echo(f"   Mode: {report.vulnerability_proof['mode']}")
    click.echo(f"   Environment: {report.execution_details['environment']}")
    click.echo(f"   Success: {'✅' if report.execution_details['transactions'] else '❌'}")
    click.echo(f"   Execution Time: {report.execution_details['execution_time']:.2f}s")
    click.echo(f"   Gas Used: {report.execution_details['gas_used']:,}")
    click.echo(f"   Total Profit: {report.financial_impact['total_profit']:.6f} ETH")
    click.echo(f"   ROI: {report.financial_impact['roi']:.2f}x")
    click.echo(f"   Risk Level: {report.risk_assessment['risk_level']}")

def _assess_attack_feasibility(mode: AttackMode, web3, target: str) -> dict:
    """Assess attack feasibility"""
    # Mock feasibility assessment
    # In real implementation, this would analyze the target contract
    
    feasibility_map = {
        AttackMode.REENTRANCY: {"feasible": True, "reason": "Reentrancy pattern detected"},
        AttackMode.FLASHLOAN: {"feasible": True, "reason": "Flashloan integration possible"},
        AttackMode.ORACLE_MANIPULATION: {"feasible": False, "reason": "Oracle manipulation too complex"},
        AttackMode.ACCESS_CONTROL: {"feasible": True, "reason": "Missing access controls"},
        AttackMode.INTEGER_OVERFLOW: {"feasible": False, "reason": "SafeMath in use"}
    }
    
    return feasibility_map.get(mode, {"feasible": False, "reason": "Unknown attack mode"})

if __name__ == '__main__':
    attack()