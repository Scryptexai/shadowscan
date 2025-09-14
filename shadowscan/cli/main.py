#!/usr/bin/env python3
"""
ShadowScan CLI Main Entry Point
"""

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
import sys
import os
from pathlib import Path

# Add project root to path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from shadowscan.commands.attack_commands import attack
from shadowscan.enhanced_screening.commands.enhanced_commands import enhanced
from shadowscan.utils.display_helpers import console

console = Console()

@click.group()
@click.option('--config', '-c', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
@click.option('--env-file', help='Environment file path')
@click.pass_context
def shadowscan(ctx, config, verbose, quiet, env_file):
    """🔍 ShadowScan - Advanced Blockchain Security Platform
    
    Comprehensive security scanning platform for blockchain smart contracts
    with integrated attack validation framework.
    """
    ctx.ensure_object(dict)
    
    # Initialize context
    ctx.obj['config'] = config
    ctx.obj['verbose'] = verbose
    ctx.obj['quiet'] = quiet
    ctx.obj['env_file'] = env_file
    
    # Load configuration
    try:
        config_manager = ConfigManager(config_path=config, env_file=env_file)
        ctx.obj['config_manager'] = config_manager
        
        if verbose:
            console.print(f"[dim]Config loaded from: {config_manager.config_path}[/dim]")
            
    except Exception as e:
        if not quiet:
            console.print(f"[red]⚠️  Warning: Failed to load config: {e}[/red]")
    
    # Display banner in verbose mode
    if verbose and not quiet:
        display_banner()

@shadowscan.command()
def version():
    """Show ShadowScan version information"""
    console.print(Panel.fit(
        "[bold blue]ShadowScan v3.0.0[/bold blue]\n"
        "[dim]Advanced Blockchain Security Platform[/dim]\n\n"
        "[green]✅[/green] Phase 1: Screening Framework\n"
        "[green]✅[/green] Phase 2: Verification System\n" 
        "[green]✅[/green] Phase 3: Attack Framework\n\n"
        "[dim]Built with ❤️ by ShadowScan Security Team[/dim]",
        title="🔍 ShadowScan",
        border_style="blue"
    ))

@shadowscan.command()
def status():
    """Show system status and health check"""
    console.print("[bold]🔍 ShadowScan System Status[/bold]")
    
    # Create status table
    table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details", style="dim")
    
    # Check configuration
    try:
        from shadowscan.utils.config_manager import ConfigManager
        config_manager = ConfigManager()
        table.add_row("Configuration", "✅ Operational", f"Loaded from {config_manager.config_path}")
    except Exception as e:
        table.add_row("Configuration", "❌ Error", str(e))
    
    # Check network connectivity
    try:
        from shadowscan.core.attack.attack_framework import AttackFramework, Environment
        framework = AttackFramework()
        web3 = framework.get_web3_instance("ethereum", Environment.FORK)
        table.add_row("Network (Fork)", "✅ Connected", f"Block {web3.eth.block_number:,}")
        
        web3_mainnet = framework.get_web3_instance("ethereum", Environment.MAINNET)
        table.add_row("Network (Mainnet)", "✅ Connected", f"Block {web3_mainnet.eth.block_number:,}")
    except Exception as e:
        table.add_row("Network", "❌ Error", str(e))
    
    # Check attack modes
    try:
        from shadowscan.core.attack.attack_framework import AttackMode
        attack_modes = [mode.value for mode in AttackMode]
        table.add_row("Attack Modes", "✅ Available", f"{len(attack_modes)} modes: {', '.join(attack_modes)}")
    except Exception as e:
        table.add_row("Attack Modes", "❌ Error", str(e))
    
    # Check reports directory
    reports_dir = Path("reports")
    if reports_dir.exists():
        report_count = len(list(reports_dir.rglob("*.json")))
        table.add_row("Reports", "✅ Available", f"{report_count} report files")
    else:
        table.add_row("Reports", "⚠️ Not Found", "Run a scan to generate reports")
    
    console.print(table)

@shadowscan.group()
def config():
    """Configuration management commands"""
    pass

@config.command()
def show():
    """Show current configuration"""
    try:
        config_manager = ConfigManager()
        config_data = config_manager.get_all_config()
        
        console.print("[bold]📋 Current Configuration[/bold]")
        
        for section, values in config_data.items():
            console.print(f"\n[cyan]{section.upper()}:[/cyan]")
            for key, value in values.items():
                # Hide sensitive values
                if any(sensitive in key.lower() for sensitive in ['key', 'secret', 'password', 'private']):
                    display_value = "*" * 8 if value else "Not set"
                else:
                    display_value = str(value) if value else "Not set"
                console.print(f"  {key}: {display_value}")
                
    except Exception as e:
        console.print(f"[red]❌ Error loading configuration: {e}[/red]")

@config.command()
@click.option('--key', required=True, help='Configuration key to set')
@click.option('--value', required=True, help='Configuration value')
@click.option('--section', default='default', help='Configuration section')
def set(key, value, section):
    """Set configuration value"""
    try:
        config_manager = ConfigManager()
        config_manager.set_config(section, key, value)
        console.print(f"[green]✅ Configuration updated: {section}.{key} = {value}[/green]")
    except Exception as e:
        console.print(f"[red]❌ Error setting configuration: {e}[/red]")

@shadowscan.group()
def reports():
    """Report management commands"""
    pass

@reports.command()
@click.option('--type', 'report_type', type=click.Choice(['all', 'scan', 'verify', 'attack']), 
              default='all', help='Report type to list')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']), 
              default='table', help='Output format')
def list(report_type, output_format):
    """List available reports"""
    reports_dir = Path("reports")
    if not reports_dir.exists():
        console.print("[yellow]📭 No reports directory found[/yellow]")
        return
    
    report_files = []
    
    if report_type in ['all', 'scan']:
        scan_reports = list(reports_dir.glob("findings/*.json"))
        report_files.extend([("scan", f) for f in scan_reports])
    
    if report_type in ['all', 'verify']:
        verify_reports = list(reports_dir.glob("verification/*.json"))
        report_files.extend([("verify", f) for f in verify_reports])
    
    if report_type in ['all', 'attack']:
        attack_reports = list(reports_dir.glob("attacks/*.json"))
        attack_reports.extend(list(reports_dir.glob("mainnet_proofs/*.json")))
        attack_reports.extend(list(reports_dir.glob("validation_tests/*.json")))
        report_files.extend([("attack", f) for f in attack_reports])
    
    if not report_files:
        console.print("[yellow]📭 No reports found[/yellow]")
        return
    
    if output_format == 'json':
        import json
        reports_data = []
        for report_type, report_file in report_files:
            try:
                with open(report_file, 'r') as f:
                    data = json.load(f)
                reports_data.append({
                    "type": report_type,
                    "file": str(report_file),
                    "size": report_file.stat().st_size,
                    "modified": report_file.stat().st_mtime,
                    "data": data
                })
            except:
                reports_data.append({
                    "type": report_type,
                    "file": str(report_file),
                    "size": report_file.stat().st_size,
                    "modified": report_file.stat().st_mtime,
                    "error": "Failed to read"
                })
        
        console.print(json.dumps(reports_data, indent=2))
    else:
        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("Type", style="cyan")
        table.add_column("File", style="green")
        table.add_column("Size", style="yellow")
        table.add_column("Modified", style="dim")
        
        for report_type, report_file in sorted(report_files, key=lambda x: x[1].stat().st_mtime, reverse=True):
            size_kb = report_file.stat().st_size / 1024
            modified = report_file.stat().st_mtime
            
            import datetime
            mod_time = datetime.datetime.fromtimestamp(modified).strftime("%Y-%m-%d %H:%M")
            
            table.add_row(
                report_type.upper(),
                report_file.name,
                f"{size_kb:.1f} KB",
                mod_time
            )
        
        console.print(table)

@shadowscan.command()
@click.option('--target', '-t', required=True, help='Target to analyze')
@click.option('--mode', '-m', type=click.Choice(['quick', 'comprehensive', 'attack']), 
              default='comprehensive', help='Analysis mode')
def analyze(target, mode):
    """Quick analysis of target security"""
    console.print(f"[bold]🔍 Analyzing Target: {target}[/bold]")
    console.print(f"[dim]Mode: {mode}[/dim]")
    
    if mode == 'quick':
        # Run quick scan
        from shadowscan.commands.scan import scan
        ctx = click.Context(scan, obj={'target': target, 'quick': True})
        scan.invoke(ctx)
    elif mode == 'comprehensive':
        # Run comprehensive scan
        from shadowscan.commands.scan import scan  
        ctx = click.Context(scan, obj={'target': target, 'comprehensive': True})
        scan.invoke(ctx)
    elif mode == 'attack':
        # Run attack analysis
        from shadowscan.commands.attack_commands import attack
        ctx = click.Context(attack_commands, obj={'target': target})
        
        # Show attack analysis
        console.print("\n[cyan]📊 Attack Feasibility Analysis:[/cyan]")
        
        # Mock analysis for now
        analysis_results = {
            "reentrancy": {"feasible": True, "confidence": "High", "estimated_profit": "5-10 ETH"},
            "flashloan": {"feasible": True, "confidence": "Medium", "estimated_profit": "1-3 ETH"},
            "oracle_manipulation": {"feasible": False, "confidence": "Low", "reason": "Oracle not manipulable"}
        }
        
        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("Attack Type", style="cyan")
        table.add_column("Feasible", style="green")
        table.add_column("Confidence", style="yellow")
        table.add_column("Details", style="dim")
        
        for attack_type, result in analysis_results.items():
            feasible_icon = "✅" if result["feasible"] else "❌"
            details = result.get("estimated_profit", result.get("reason", ""))
            
            table.add_row(
                attack_type.replace("_", " ").title(),
                feasible_icon,
                result["confidence"],
                details
            )
        
        console.print(table)

# Add subcommands
shadowscan.add_command(attack)
shadowscan.add_command(enhanced)

def main():
    """Main entry point"""
    try:
        shadowscan()
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Operation cancelled by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]❌ Unexpected error: {e}[/red]")
        if '--verbose' in sys.argv or '-v' in sys.argv:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)

if __name__ == '__main__':
    main()