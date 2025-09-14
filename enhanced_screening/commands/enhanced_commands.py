"""
Enhanced Screening Commands
Deep vulnerability scanning with advanced detection capabilities
"""

import click
import json
import os
import sys
from pathlib import Path
from datetime import datetime
import logging
import asyncio

from enhanced_engine import EnhancedScreeningEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@click.group()
@click.option('--target', '-t', required=True, help='Target contract address')
@click.option('--chain', '-c', default='ethereum', help='Blockchain network')
@click.option('--mode', '-m', default='fork', help='Analysis mode: fork/mainnet')
@click.option('--output', '-o', default='reports/enhanced', help='Output directory')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def enhanced(ctx, target, chain, mode, output, verbose):
    """
    🔍 Enhanced Deep Screening Commands
    
    Advanced vulnerability detection with deep scanning capabilities.
    Supports 20+ vulnerability types with multiple analysis methods.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('shadowscan').setLevel(logging.DEBUG)
    
    ctx.ensure_object(dict)
    ctx.obj['target'] = target
    ctx.obj['chain'] = chain
    ctx.obj['mode'] = mode
    ctx.obj['output'] = output
    ctx.obj['verbose'] = verbose

@enhanced.command()
@click.option('--depth', '-d', default='deep', 
              type=click.Choice(['basic', 'deep', 'intensive'], case_sensitive=False),
              help='Scan depth: basic/fast, deep/comprehensive, intensive/thorough')
@click.option('--vulnerability-types', '-v', multiple=True,
              help='Specific vulnerability types to scan for')
@click.option('--intensity', '-i', default='deep',
              type=click.Choice(['basic', 'deep', 'intensive'], case_sensitive=False),
              help='Analysis intensity level')
@click.option('--with-ecosystem/--no-ecosystem', default=True,
              help='Include ecosystem analysis')
@click.option('--with-economic/--no-economic', default=True,
              help='Include economic impact assessment')
@click.option('--with-exploitation/--no-exploitation', default=True,
              help='Include exploitation path planning')
@click.pass_context
def scan(ctx, depth, vulnerability_types, intensity, with_ecosystem, with_economic, with_exploitation):
    """
    🔬 Run Enhanced Deep Vulnerability Scan
    
    Perform comprehensive vulnerability analysis with multiple detection methods:
    - Pattern Matching
    - Symbolic Execution  
    - Taint Analysis
    - Constraint Solving
    - Formal Verification
    - Dynamic Analysis
    """
    
    target = ctx.obj['target']
    chain = ctx.obj['chain']
    mode = ctx.obj['mode']
    output = ctx.obj['output']
    verbose = ctx.obj['verbose']
    
    click.echo("🔬 Enhanced Deep Vulnerability Scan")
    click.echo("=" * 50)
    click.echo(f"🎯 Target: {target}")
    click.echo(f"🌐 Chain: {chain}")
    click.echo(f"🔗 Mode: {mode}")
    click.echo(f"📊 Depth: {depth}")
    click.echo(f"🔬 Intensity: {intensity}")
    
    if vulnerability_types:
        click.echo(f"🎯 Vulnerability Types: {', '.join(vulnerability_types)}")
    else:
        click.echo(f"🎯 Vulnerability Types: All (20+ types)")
    
    click.echo()
    
    try:
        # Initialize enhanced screening engine
        rpc_url = os.getenv('TENDERLY_RPC')
        etherscan_key = os.getenv('ETHERSCAN_API_KEY')
        
        if not rpc_url:
            click.echo("❌ TENDERLY_RPC not found in environment variables")
            sys.exit(1)
        
        engine = EnhancedScreeningEngine(rpc_url, etherscan_key)
        
        # Prepare options
        opts = {
            'output': output,
            'with_ecosystem': with_ecosystem,
            'with_economic': with_economic,
            'with_exploitation': with_exploitation
        }
        
        # Run enhanced screening
        click.echo("🚀 Starting enhanced deep scan...")
        click.echo()
        
        result = asyncio.run(engine.run_enhanced_screening(
            target=target,
            chain=chain,
            mode=mode,
            scan_depth=depth,
            vulnerability_types=list(vulnerability_types) if vulnerability_types else None,
            intensity=intensity,
            opts=opts
        ))
        
        if result['success']:
            _print_enhanced_results(result)
            _save_enhanced_report(result, output)
        else:
            click.echo("❌ Enhanced screening failed")
            sys.exit(1)
            
    except KeyboardInterrupt:
        click.echo("\n⚠️  Enhanced screening interrupted by user")
        sys.exit(130)
    except Exception as e:
        click.echo(f"\n❌ Error during enhanced screening: {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

@enhanced.command()
@click.pass_context
def vulns(ctx):
    """📋 List Available Vulnerability Types"""
    
    click.echo("📋 Available Vulnerability Types (20+ Types)")
    click.echo("=" * 60)
    
    categories = {
        "🏦 Financial": [
            "reentrancy - Reentrancy Attack (CRITICAL)",
            "flashloan - Flash Loan Attack (CRITICAL)",
            "integer_overflow - Integer Overflow/Underflow (HIGH)",
            "timestamp_dependency - Timestamp Dependency (MEDIUM)",
            "front_running - Front Running (HIGH)"
        ],
        "🔐 Access Control": [
            "ownership_hijack - Ownership Hijacking (CRITICAL)",
            "access_control_bypass - Access Control Bypass (HIGH)",
            "unprotected_function - Unprotected Critical Function (MEDIUM)",
            "delegatecall_injection - Delegatecall Injection (CRITICAL)"
        ],
        "🧠 Logical": [
            "oracle_manipulation - Oracle Manipulation (HIGH)",
            "gas_limit_griefing - Gas Limit Griefing (MEDIUM)",
            "denial_of_service - Denial of Service (MEDIUM)",
            "race_condition - Race Condition (HIGH)"
        ],
        "🔐 Cryptographic": [
            "weak_randomness - Weak Randomness (MEDIUM)",
            "signature_malleability - Signature Malleability (HIGH)",
            "hardcoded_secrets - Hardcoded Secrets (CRITICAL)"
        ],
        "💰 Economic": [
            "arbitrage_opportunity - Arbitrage Opportunity (MEDIUM)",
            "sandwich_attack - Sandwich Attack (MEDIUM)",
            "mev_extraction - MEV Extraction (HIGH)"
        ],
        "🔗 Protocol": [
            "proxy_collision - Proxy Collision (CRITICAL)",
            "upgrade_vulnerability - Upgrade Vulnerability (HIGH)",
            "initialization_vulnerability - Initialization Vulnerability (HIGH)"
        ]
    }
    
    for category, vulns in categories.items():
        click.echo(f"\n{category}:")
        for vuln in vulns:
            severity = vuln.split('(')[-1].rstrip(')')
            emoji = "🔴" if "CRITICAL" in severity else "🟠" if "HIGH" in severity else "🟡"
            click.echo(f"  {emoji} {vuln}")
    
    click.echo(f"\n📊 Total: {sum(len(vulns) for vulns in categories.values())} vulnerability types")
    click.echo("\n💡 Usage: enhanced scan -v reentrancy -v flashloan")

@enhanced.command()
@click.option('--vulnerability', '-v', required=True, 
              help='Vulnerability type to deep scan')
@click.option('--method', '-m', default='all',
              type=click.Choice(['pattern_matching', 'symbolic_execution', 'taint_analysis', 
                                'constraint_solving', 'formal_verification', 'dynamic_analysis', 'all']),
              help='Detection method to use')
@click.option('--timeout', '-t', default=600, type=int, help='Analysis timeout in seconds')
@click.pass_context
def deep(ctx, vulnerability, method, timeout):
    """
    🔍 Deep Dive Analysis for Specific Vulnerability
    
    Run intensive analysis for a single vulnerability type using
    advanced detection methods and deep symbolic execution.
    """
    
    target = ctx.obj['target']
    chain = ctx.obj['chain']
    mode = ctx.obj['mode']
    output = ctx.obj['output']
    
    click.echo(f"🔍 Deep Dive: {vulnerability}")
    click.echo("=" * 40)
    click.echo(f"🎯 Target: {target}")
    click.echo(f"🔬 Method: {method}")
    click.echo(f"⏱️  Timeout: {timeout}s")
    click.echo()
    
    try:
        rpc_url = os.getenv('TENDERLY_RPC')
        etherscan_key = os.getenv('ETHERSCAN_API_KEY')
        
        if not rpc_url:
            click.echo("❌ TENDERLY_RPC not found in environment variables")
            sys.exit(1)
        
        engine = EnhancedScreeningEngine(rpc_url, etherscan_key)
        
        # Select detection methods
        if method == 'all':
            methods = ['pattern_matching', 'symbolic_execution', 'taint_analysis', 
                       'constraint_solving', 'formal_verification', 'dynamic_analysis']
        else:
            methods = [method]
        
        click.echo(f"🔬 Running deep analysis with methods: {', '.join(methods)}")
        click.echo()
        
        # Run deep analysis
        result = asyncio.run(engine.run_enhanced_screening(
            target=target,
            chain=chain,
            mode=mode,
            scan_depth='intensive',
            vulnerability_types=[vulnerability],
            intensity='intensive',
            opts={'output': output, 'timeout': timeout}
        ))
        
        if result['success']:
            _print_deep_analysis_results(result, vulnerability)
        else:
            click.echo("❌ Deep analysis failed")
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Error during deep analysis: {str(e)}")
        sys.exit(1)

@enhanced.command()
@click.option('--ecosystem-depth', '-e', default='comprehensive',
              type=click.Choice(['direct', 'extended', 'comprehensive']),
              help='Ecosystem analysis depth')
@click.pass_context
def ecosystem(ctx, ecosystem_depth):
    """
    🌐 Comprehensive Ecosystem Analysis
    
    Analyze contract's role in broader DeFi ecosystem including:
    - DEX relationships and liquidity pools
    - Oracle dependencies and price feeds
    - Token ecosystems and governance
    - Protocol interconnections
    - Systemic risk assessment
    """
    
    target = ctx.obj['target']
    chain = ctx.obj['chain']
    output = ctx.obj['output']
    
    click.echo("🌐 Comprehensive Ecosystem Analysis")
    click.echo("=" * 50)
    click.echo(f"🎯 Target: {target}")
    click.echo(f"🔗 Ecosystem Depth: {ecosystem_depth}")
    click.echo()
    
    try:
        rpc_url = os.getenv('TENDERLY_RPC')
        etherscan_key = os.getenv('ETHERSCAN_API_KEY')
        
        if not rpc_url:
            click.echo("❌ TENDERLY_RPC not found in environment variables")
            sys.exit(1)
        
        engine = EnhancedScreeningEngine(rpc_url, etherscan_key)
        
        # Run ecosystem-focused analysis
        result = asyncio.run(engine.run_enhanced_screening(
            target=target,
            chain=chain,
            mode='fork',
            scan_depth='deep',
            vulnerability_types=[],  # Skip vulnerability scanning for ecosystem focus
            intensity='deep',
            opts={
                'output': output,
                'ecosystem_depth': ecosystem_depth,
                'focus_ecosystem': True
            }
        ))
        
        if result['success']:
            _print_ecosystem_results(result)
        else:
            click.echo("❌ Ecosystem analysis failed")
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Error during ecosystem analysis: {str(e)}")
        sys.exit(1)

def _print_enhanced_results(result: dict):
    """Print enhanced screening results"""
    enhanced_summary = result.get('enhanced_report', {})
    deep_scan = result.get('deep_scan_result', {})
    
    click.echo("🎉 Enhanced Screening Results")
    click.echo("=" * 50)
    
    # Basic vs Enhanced comparison
    basic = enhanced_summary.get('basic_screening', {})
    enhanced = enhanced_summary.get('enhanced_metrics', {})
    
    click.echo("📊 Screening Comparison:")
    click.echo(f"   Basic vulns found: {basic.get('vulnerabilities_found', 0)}")
    click.echo(f"   Deep vulns found: {enhanced.get('deep_vulnerabilities_found', 0)}")
    click.echo(f"   Code coverage: {enhanced.get('code_coverage', 0):.1f}%")
    click.echo(f"   Scan depth: {enhanced.get('scan_depth', 'unknown')}")
    click.echo()
    
    # Ecosystem analysis
    ecosystem = enhanced_summary.get('ecosystem_analysis', {})
    click.echo("🌐 Ecosystem Analysis:")
    click.echo(f"   DEX relations: {ecosystem.get('dex_relations_count', 0)}")
    click.echo(f"   Oracle deps: {ecosystem.get('oracle_dependencies_count', 0)}")
    click.echo(f"   Protocol relationships: {ecosystem.get('protocol_relationships_count', 0)}")
    click.echo(f"   Ecosystem risk: {ecosystem.get('ecosystem_risk_score', 0):.2f}")
    click.echo()
    
    # Vulnerability breakdown
    breakdown = enhanced_summary.get('vulnerability_breakdown', {})
    click.echo("🔍 Vulnerability Breakdown:")
    by_severity = breakdown.get('by_severity', {})
    for severity, count in by_severity.items():
        emoji = "🔴" if severity == "critical" else "🟠" if severity == "high" else "🟡" if severity == "medium" else "🟢"
        click.echo(f"   {emoji} {severity.title()}: {count}")
    
    # Economic impact
    economic = result.get('economic_impact', {})
    if economic:
        click.echo(f"\n💰 Economic Impact:")
        click.echo(f"   Potential loss: ${economic.get('total_potential_loss', 0):,.2f}")
        click.echo(f"   Exploit feasibility: {economic.get('exploit_feasibility', 0):.1%}")
    
    # Performance metrics
    click.echo(f"\n⏱️  Performance:")
    click.echo(f"   Execution time: {enhanced.get('execution_time', 0):.2f}s")
    click.echo(f"   Symbolic states: {enhanced.get('symbolic_states_analyzed', 0):,}")
    click.echo(f"   Constraints solved: {enhanced.get('constraints_solved', 0):,}")
    
    # Top critical findings
    critical_vulns = breakdown.get('top_critical_vulnerabilities', [])
    if critical_vulns:
        click.echo(f"\n🚨 Top Critical Vulnerabilities:")
        for i, vuln in enumerate(critical_vulns[:3], 1):
            click.echo(f"   {i}. {vuln['type']} (confidence: {vuln['confidence']:.1%})")
            click.echo(f"      {vuln['description'][:80]}...")
    
    click.echo(f"\n📄 Full report: {enhanced_summary.get('session_file', '')}")

def _print_deep_analysis_results(result: dict, vulnerability: str):
    """Print deep analysis results for specific vulnerability"""
    click.echo(f"🔬 Deep Analysis Results: {vulnerability}")
    click.echo("=" * 50)
    
    vulnerabilities = result.get('deep_scan_result', {}).get('vulnerabilities', [])
    
    if not vulnerabilities:
        click.echo("✅ No vulnerabilities found")
        return
    
    for i, vuln in enumerate(vulnerabilities, 1):
        click.echo(f"\n🎯 Finding {i}:")
        click.echo(f"   Type: {vuln.vulnerability_type}")
        click.echo(f"   Severity: {vuln.severity.value.upper()}")
        click.echo(f"   Confidence: {vuln.confidence:.1%}")
        click.echo(f"   Impact Score: {vuln.impact_score:.2f}")
        click.echo(f"   Detection Methods: {', '.join([m.value for m in vuln.detection_methods])}")
        click.echo(f"   Description: {vuln.description}")
        
        if vuln.exploitation_path:
            click.echo(f"   Exploitation Path:")
            for step in vuln.exploitation_path:
                click.echo(f"     - {step}")
        
        if vuln.mitigation_suggestions:
            click.echo(f"   Mitigation:")
            for suggestion in vuln.mitigation_suggestions:
                click.echo(f"     • {suggestion}")

def _print_ecosystem_results(result: dict):
    """Print ecosystem analysis results"""
    ecosystem_data = result.get('ecosystem_data', {})
    
    click.echo("🌐 Ecosystem Analysis Results")
    click.echo("=" * 40)
    
    # DEX relationships
    dex_relations = ecosystem_data.get('dex_relations', [])
    click.echo(f"🕸️  DEX Relationships: {len(dex_relations)}")
    for dex in dex_relations[:5]:  # Show first 5
        click.echo(f"   • {dex.get('name', 'Unknown')} - Liquidity: ${dex.get('liquidity_usd', 0):,.2f}")
    
    # Oracle dependencies
    oracle_deps = ecosystem_data.get('oracle_dependencies', [])
    click.echo(f"\n🔮 Oracle Dependencies: {len(oracle_deps)}")
    for oracle in oracle_deps[:3]:
        click.echo(f"   • {oracle.get('type', 'Unknown')} - Risk: {oracle.get('risk_score', 0):.2f}")
    
    # Risk assessment
    risk_assessment = ecosystem_data.get('risk_assessment', {})
    click.echo(f"\n⚖️  Ecosystem Risk Assessment:")
    click.echo(f"   Overall Risk Score: {risk_assessment.get('overall_risk_score', 0):.2f}")
    click.echo(f"   Cascade Potential: {risk_assessment.get('cascade_potential', 'unknown')}")
    click.echo(f"   Mitigation Priority: {risk_assessment.get('mitigation_priority', 'unknown')}")

def _save_enhanced_report(result: dict, output_dir: str):
    """Save enhanced report to file"""
    try:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = output_path / f"enhanced_report_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        
        click.echo(f"\n💾 Enhanced report saved to: {report_file}")
        
    except Exception as e:
        logger.error(f"Error saving enhanced report: {e}")

if __name__ == '__main__':
    enhanced()