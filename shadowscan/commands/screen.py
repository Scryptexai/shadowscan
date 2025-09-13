# shadowscan/commands/screen.py
"""Enhanced screen command with comprehensive analysis and shorthand flags."""

import click
import json
import os
import sys
from pathlib import Path
from datetime import datetime
import logging

from shadowscan.core.pipeline.screening_engine import ScreeningEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@click.command()
@click.option('--target', '-t', required=True, help='Target contract address to screen')
@click.option('--chain', '-c', default='ethereum', 
              type=click.Choice(['ethereum', 'polygon', 'bsc', 'arbitrum'], case_sensitive=False),
              help='Blockchain network')
@click.option('--mode', '-m', default='f', 
              type=click.Choice(['f', 'M', 'fork', 'mainnet'], case_sensitive=False),
              help='Screening mode: f/fork for development, M/mainnet for read-only')
@click.option('--with-graph/--no-graph', '-g/-ng', default=True, 
              help='Build and export relationship graph')
@click.option('--with-events/--no-events', '-e/-ne', default=True,
              help='Collect and analyze contract events')
@click.option('--with-state/--no-state', '-S/-nS', default=True,
              help='Collect contract state snapshots')
@click.option('--depth', '-d', default='s',
              type=click.Choice(['s', 'f', 'shallow', 'full'], case_sensitive=False),
              help='Analysis depth: s/shallow for quick scan, f/full for comprehensive')
@click.option('--output', '-o', default='reports/findings',
              help='Output directory for reports and artifacts')
@click.option('--concurrency', '-n', default=8, type=int,
              help='Maximum parallel RPC calls')
@click.option('--timeout', '-T', default=300, type=int,
              help='RPC timeout in seconds')
@click.option('--rpc-url', help='Custom RPC URL (overrides default for chain)')
@click.option('--etherscan-key', help='Etherscan API key for enhanced data')
@click.option('--no-cache', '-N', is_flag=True, help='Disable caching')
@click.option('--force', '-F', is_flag=True, help='Force refresh even if cached')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--with-graph-html', is_flag=True, help='Generate HTML graph visualization')
@click.pass_context
def screen(ctx, target, chain, mode, with_graph, with_events, with_state, depth, 
          output, concurrency, timeout, rpc_url, etherscan_key, no_cache, force, 
          verbose, with_graph_html):
    """
    🔍 Screen a smart contract for security vulnerabilities and patterns.
    
    This command performs comprehensive analysis including:
    - Bytecode and ABI analysis
    - Proxy pattern detection  
    - Transaction and event analysis
    - DEX relationship discovery
    - Oracle intelligence gathering
    - Vulnerability pattern detection
    - Interaction graph generation
    
    Examples:
      shadowscan s -t 0x30a25... -c ethereum -m f -g -e -S -d f
      shadowscan screen --target 0xUSDT... --chain ethereum --mode mainnet
    """
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('shadowscan').setLevel(logging.DEBUG)
    
    try:
        # Print header
        _print_header()
        
        # Normalize inputs
        target_address = target.strip()
        chain_name = chain.lower()
        screening_mode = _normalize_mode(mode)
        analysis_depth = _normalize_depth(depth)
        
        # Validate target address
        if not _is_valid_ethereum_address(target_address):
            click.echo(f"❌ Invalid Ethereum address: {target_address}", err=True)
            sys.exit(1)
        
        # Setup RPC URL
        if not rpc_url:
            rpc_url = _get_default_rpc_url(chain_name)
            if not rpc_url:
                click.echo(f"❌ No RPC URL available for chain: {chain_name}", err=True)
                click.echo("   Please provide --rpc-url parameter", err=True)
                sys.exit(1)
        
        # Setup API key
        if not etherscan_key:
            etherscan_key = os.getenv('ETHERSCAN_API_KEY')
        
        # Print scan configuration
        _print_scan_config(target_address, chain_name, screening_mode, analysis_depth, rpc_url)
        
        # Initialize screening engine
        click.echo("🔧 Initializing screening engine...")
        engine = ScreeningEngine(rpc_url, etherscan_key)
        
        # Prepare options
        options = {
            'with_graph': with_graph,
            'with_events': with_events,
            'with_state': with_state,
            'with_graph_html': with_graph_html,
            'concurrency': concurrency,
            'timeout': timeout,
            'output': output,
            'no_cache': no_cache,
            'force': force
        }
        
        # Run screening
        click.echo("🚀 Starting comprehensive security screening...")
        click.echo()
        
        result = engine.run_screening(
            target=target_address,
            chain=chain_name,
            mode=screening_mode,
            depth=analysis_depth,
            opts=options
        )
        
        # Handle results
        if result['success']:
            _print_success_summary(result['summary'], result['session_file'])
            
            # Print detailed analysis
            _print_detailed_analysis(result['summary'])
            
            # Print file locations
            _print_output_files(result, options)
            
            click.echo("\n✅ Screening completed successfully!")
            
        else:
            _print_error_summary(result)
            sys.exit(1)
            
    except KeyboardInterrupt:
        click.echo("\n⚠️  Screening interrupted by user")
        sys.exit(130)
        
    except Exception as e:
        click.echo(f"\n❌ Unexpected error during screening: {str(e)}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

def _print_header():
    """Print ShadowScan header."""
    click.echo("=" * 70)
    click.echo("🔍 ShadowScan - Advanced Smart Contract Security Analysis")
    click.echo("=" * 70)

def _normalize_mode(mode: str) -> str:
    """Normalize mode input to standard format."""
    mode_lower = mode.lower()
    if mode_lower in ['f', 'fork']:
        return 'fork'
    elif mode_lower in ['m', 'mainnet']:
        return 'mainnet'
    else:
        return 'mainnet'  # Default to mainnet

def _normalize_depth(depth: str) -> str:
    """Normalize depth input to standard format."""
    depth_lower = depth.lower()
    if depth_lower in ['s', 'shallow']:
        return 'shallow'
    elif depth_lower in ['f', 'full']:
        return 'full'
    else:
        return 'shallow'  # Default to shallow

def _is_valid_ethereum_address(address: str) -> bool:
    """Validate Ethereum address format."""
    if not address.startswith('0x'):
        return False
    if len(address) != 42:
        return False
    try:
        int(address[2:], 16)
        return True
    except ValueError:
        return False

def _get_default_rpc_url(chain: str) -> str:
    """Get default RPC URL for chain."""
    rpc_urls = {
        'ethereum': 'https://eth.llamarpc.com',
        'polygon': 'https://polygon.llamarpc.com', 
        'bsc': 'https://bsc.llamarpc.com',
        'arbitrum': 'https://arbitrum.llamarpc.com'
    }
    return rpc_urls.get(chain)

def _print_scan_config(target: str, chain: str, mode: str, depth: str, rpc_url: str):
    """Print scanning configuration."""
    click.echo(f"🎯 Target Contract: {target}")
    click.echo(f"🌐 Network: {chain.title()}")
    click.echo(f"🔗 RPC: {rpc_url}")
    click.echo(f"📊 Mode: {mode.title()} | Depth: {depth.title()}")
    click.echo()

def _print_success_summary(summary: dict, session_file: str):
    """Print success summary with key metrics."""
    click.echo("=" * 70)
    click.echo("📊 SCREENING SUMMARY")
    click.echo("=" * 70)
    
    # Contract info
    click.echo(f"Contract: {summary['target_address']}")
    click.echo(f"Chain: {summary['chain'].title()}")
    click.echo(f"Block: {summary['block_number']:,}")
    click.echo(f"Verified: {'✅' if summary['is_verified'] else '❌'}")
    
    # Proxy info
    if summary['is_proxy']:
        proxy_type = summary.get('proxy_type', 'Unknown')
        click.echo(f"Proxy: ✅ {proxy_type}")
    else:
        click.echo("Proxy: ❌")
    
    # Function analysis
    click.echo(f"Functions: {summary['function_count']}")
    
    # DEX analysis
    dex_count = summary['dex_count']
    total_liquidity = summary['total_liquidity_usd']
    click.echo(f"DEX Links: {dex_count}")
    if total_liquidity > 0:
        click.echo(f"Total Liquidity: ${total_liquidity:,.2f}")
    
    # Oracle analysis
    oracle_sources = summary['oracle_sources']
    oracle_risk = summary['oracle_risk_score']
    if oracle_sources > 0:
        click.echo(f"Oracle Sources: {oracle_sources}")
        risk_emoji = "🔴" if oracle_risk > 0.7 else "🟡" if oracle_risk > 0.4 else "🟢"
        click.echo(f"Oracle Risk: {risk_emoji} {oracle_risk:.2f}")

def _print_detailed_analysis(summary: dict):
    """Print detailed vulnerability analysis."""
    click.echo()
    
    # Vulnerability summary
    vuln_counts = summary['vulnerabilities_by_severity']
    total_vulns = sum(vuln_counts.values())
    
    click.echo(f"⚠️  VULNERABILITY ANALYSIS")
    click.echo("-" * 30)
    
    if total_vulns == 0:
        click.echo("✅ No vulnerabilities detected")
    else:
        click.echo(f"Total Issues: {total_vulns}")
        
        # Show by severity with emojis
        severity_emojis = {
            'critical': '🔴',
            'high': '🟠', 
            'medium': '🟡',
            'low': '🟢'
        }
        
        for severity in ['critical', 'high', 'medium', 'low']:
            count = vuln_counts.get(severity, 0)
            if count > 0:
                emoji = severity_emojis[severity]
                click.echo(f"  {emoji} {severity.upper()}: {count}")
    
    # Top hypotheses
    top_hypotheses = summary.get('top_hypotheses', [])
    if top_hypotheses:
        click.echo(f"\n🔍 TOP FINDINGS:")
        click.echo("-" * 20)
        
        for i, hyp in enumerate(top_hypotheses[:3], 1):
            severity = hyp['severity']
            emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(severity, '⚪')
            confidence = hyp['confidence']
            category = hyp['category'].replace('_', ' ').title()
            
            click.echo(f"{i}. {emoji} {category} (confidence: {confidence:.1%})")
            click.echo(f"   {hyp['description']}")
            if i < len(top_hypotheses):
                click.echo()

def _print_output_files(result: dict, options: dict):
    """Print generated output files."""
    click.echo(f"\n📁 OUTPUT FILES:")
    click.echo("-" * 20)
    
    session_file = result['session_file']
    click.echo(f"📄 Main Report: {session_file}")
    
    # Check for graph files
    session_dir = Path(session_file).parent
    session_basename = Path(session_file).stem
    
    # Look for graph files
    graph_json = session_dir / f"graph_{session_basename.split('_', 1)[1]}.json"
    if graph_json.exists():
        click.echo(f"🕸️  Graph Data: {graph_json}")
    
    graph_html = session_dir / f"graph_{session_basename.split('_', 1)[1]}.html"
    if graph_html.exists():
        click.echo(f"🌐 Graph Visualization: {graph_html}")
    
    # Performance info
    execution_time = result.get('execution_time', 0)
    click.echo(f"\n⏱️  Completed in {execution_time:.2f}s")

def _print_error_summary(result: dict):
    """Print error summary."""
    click.echo("=" * 70)
    click.echo("❌ SCREENING FAILED")
    click.echo("=" * 70)
    
    summary = result.get('summary', {})
    error_msg = summary.get('error', 'Unknown error')
    
    click.echo(f"Error: {error_msg}")
    
    if result.get('session_id'):
        click.echo(f"Session ID: {result['session_id']}")
    
    execution_time = result.get('execution_time', 0)
    click.echo(f"Failed after: {execution_time:.2f}s")

# ===================================================================
# shadowscan/cli.py  
"""Main CLI entry point with shorthand command mapping."""

import click
import logging
from shadowscan.commands.screen import screen

@click.group()
@click.version_option(version='2.0.0-AI-A')
def cli():
    """
    🔍 ShadowScan - Advanced Smart Contract Security Analysis Tool
    
    AI-Enhanced comprehensive screening and vulnerability detection for 
    Ethereum smart contracts with advanced pattern recognition.
    
    Use 's' as shorthand for 'screen' command:
      shadowscan s -t 0x... -c ethereum -g -e
    """
    pass

@cli.command()
@click.option('--target', '-t', required=True, help='Target contract address')
@click.option('--chain', '-c', default='ethereum', help='Blockchain network') 
@click.option('--mode', '-m', default='f', help='Mode: f/fork or M/mainnet')
@click.option('--with-graph/--no-graph', '-g/-ng', default=True, help='Build graph')
@click.option('--with-events/--no-events', '-e/-ne', default=True, help='Collect events')
@click.option('--with-state/--no-state', '-S/-nS', default=True, help='Collect state')
@click.option('--depth', '-d', default='s', help='Depth: s/shallow or f/full')
@click.option('--output', '-o', default='reports/findings', help='Output directory')
@click.option('--concurrency', '-n', default=8, type=int, help='Max parallel calls')
@click.option('--timeout', '-T', default=300, type=int, help='Timeout seconds')
@click.option('--rpc-url', help='Custom RPC URL')
@click.option('--etherscan-key', help='Etherscan API key')
@click.option('--no-cache', '-N', is_flag=True, help='Disable cache')
@click.option('--force', '-F', is_flag=True, help='Force refresh')
@click.option('--verbose', '-v', is_flag=True, help='Verbose logging')
@click.option('--with-graph-html', is_flag=True, help='Generate HTML visualization')
@click.pass_context
def s(ctx, **kwargs):
    """🔍 Shorthand for screen command - comprehensive contract analysis."""
    # This is the shorthand version that delegates to the main screen command
    ctx.invoke(screen, **kwargs)

# Register the full screen command
cli.add_command(screen)

def main():
    """Main CLI entry point."""
    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\n⚠️  Operation cancelled by user")
    except Exception as e:
        click.echo(f"❌ Unexpected error: {str(e)}", err=True)
        raise

if __name__ == '__main__':
    main()
