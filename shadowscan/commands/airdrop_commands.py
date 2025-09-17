#!/usr/bin/env python3
"""
ShadowScan Airdrop Scanner CLI Command
Khusus untuk scanning website airdrop dan token claim vulnerabilities
"""

import asyncio
import json
import click
from pathlib import Path
from typing import Dict, Any

from shadowscan.modules.airdrop_scanner import AirdropWebsiteScanner
try:
    from shadowscan.utils.config import ConfigLoader
    from shadowscan.utils.console import console, print_banner
except ImportError:
    # Use fallback imports
    from rich.console import Console
    console = Console()
    def print_banner():
        pass
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from datetime import datetime

@click.command()
@click.option('-t', '--target', required=True, help='Target website URL')
@click.option('-o', '--output', help='Output file for report')
@click.option('-v', '--verbose', is_flag=True, help='Verbose output')
@click.option('--timeout', default=30, help='Request timeout in seconds')
@click.option('--max-requests', default=50, help='Maximum requests to send')
def scan_airdrop(target, output, verbose, timeout, max_requests):
    """
    Scan airdrop website for token claim vulnerabilities
    
    Examples:
    shadowscan scan-airdrop -t https://airdrop.boundless.network/
    shadowscan scan-airdrop -t https://airdrop.example.com/ -o report.json
    """
    
    print_banner()
    
    console.print(Panel.fit(
        f"[bold blue]🎯 Airdrop Website Scanner[/bold blue]\n"
        f"Target: [cyan]{target}[/cyan]\n"
        f"Mode: {'Verbose' if verbose else 'Standard'}",
        title="🔍 Airdrop Security Scan"
    ))
    
    try:
        # Validate URL
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
        
        # Initialize scanner
        scanner = AirdropWebsiteScanner(target)
        
        # Set timeout
        scanner.session.timeout = timeout
        
        console.print("[yellow]🚀 Starting comprehensive airdrop scan...[/yellow]")
        
        # Run scan
        results = asyncio.run(scanner.scan_comprehensive(max_requests=max_requests))
        
        # Display results
        display_results(results, verbose)
        
        # Save report
        if output:
            save_report(results, output)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_output = f"airdrop_scan_{timestamp}.json"
            save_report(results, default_output)
        
        console.print("[green]✅ Scan completed successfully![/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.ClickException(str(e))

def display_results(results: Dict[str, Any], verbose: bool = False):
    """Display scan results"""
    
    # Technology Stack
    tech_stack = results.get('technology_stack', {})
    if tech_stack:
        console.print("\n[bold blue]📊 Technology Stack[/bold blue]")
        tech_table = Table()
        tech_table.add_column("Component", style="cyan")
        tech_table.add_column("Details", style="white")
        
        for key, value in tech_stack.items():
            if value and (isinstance(value, str) or (isinstance(value, list) and value)):
                tech_table.add_row(key.replace('_', ' ').title(), str(value))
        
        console.print(tech_table)
    
    # Claim Mechanism
    claim_info = results.get('claim_mechanism', {})
    if claim_info:
        console.print("\n[bold blue]🎯 Claim Mechanism Analysis[/bold blue]")
        claim_table = Table()
        claim_table.add_column("Feature", style="cyan")
        claim_table.add_column("Status", style="white")
        
        for key, value in claim_info.items():
            status = "[green]✅[/green]" if value else "[red]❌[/red]"
            claim_table.add_row(key.replace('_', ' ').title(), f"{status} {value}")
        
        console.print(claim_table)
    
    # Endpoints
    endpoints = results.get('endpoints', [])
    if endpoints:
        console.print(f"\n[bold blue]🔍 Endpoints Discovered ({len(endpoints)})[/bold blue]")
        endpoint_table = Table()
        endpoint_table.add_column("Method", style="cyan")
        endpoint_table.add_column("URL", style="white")
        endpoint_table.add_column("Source", style="yellow")
        
        for endpoint in endpoints[:10]:  # Show first 10
            endpoint_table.add_row(
                endpoint.get('method', 'GET'),
                endpoint.get('url', 'N/A')[:80] + '...' if len(endpoint.get('url', '')) > 80 else endpoint.get('url', 'N/A'),
                endpoint.get('source', 'Unknown')
            )
        
        console.print(endpoint_table)
        
        if len(endpoints) > 10:
            console.print(f"[dim]... and {len(endpoints) - 10} more endpoints[/dim]")
    
    # Vulnerabilities
    vulnerabilities = results.get('vulnerabilities', [])
    if vulnerabilities:
        console.print(f"\n[bold red]🚨 Vulnerabilities Found ({len(vulnerabilities)})[/bold red]")
        
        for vuln in vulnerabilities:
            severity_color = {
                'Critical': 'bold red',
                'High': 'red',
                'Medium': 'yellow',
                'Low': 'green'
            }.get(vuln.get('severity', 'Info'), 'white')
            
            console.print(Panel(
                f"[{severity_color}]{vuln.get('severity', 'Info')}[/{severity_color}] [bold]{vuln.get('type', 'Unknown')}[/bold]\n\n"
                f"[dim]Description:[/dim] {vuln.get('description', 'N/A')}\n\n"
                f"[dim]Impact:[/dim] {vuln.get('impact', 'N/A')}\n\n"
                f"[dim]Remediation:[/dim] {vuln.get('remediation', 'N/A')}\n\n"
                f"[dim]Proof:[/dim] {vuln.get('proof', 'N/A')}",
                title="🚨 Vulnerability Found",
                border_style="red"
            ))
    else:
        console.print("\n[green]✅ No vulnerabilities detected[/green]")
    
    # Recommendations
    recommendations = results.get('recommendations', [])
    if recommendations:
        console.print(f"\n[bold blue]💡 Security Recommendations ({len(recommendations)})[/bold blue]")
        
        rec_table = Table()
        rec_table.add_column("Priority", style="cyan")
        rec_table.add_column("Category", style="white")
        rec_table.add_column("Recommendation", style="yellow")
        
        for rec in recommendations:
            priority_color = {
                'Critical': 'bold red',
                'High': 'red',
                'Medium': 'yellow',
                'Low': 'green'
            }.get(rec.get('priority', 'Medium'), 'white')
            
            rec_table.add_row(
                f"[{priority_color}]{rec.get('priority', 'Medium')}[/{priority_color}]",
                rec.get('category', 'General'),
                rec.get('recommendation', 'N/A')[:80] + '...' if len(rec.get('recommendation', '')) > 80 else rec.get('recommendation', 'N/A')
            )
        
        console.print(rec_table)
    
    # Error information
    if 'error' in results:
        console.print(f"\n[red]❌ Scan Error: {results['error']}[/red]")

def save_report(results: Dict[str, Any], output_file: str):
    """Save detailed report to file"""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        console.print(f"[green]📄 Detailed report saved to: {output_file}[/green]")
    except Exception as e:
        console.print(f"[red]❌ Error saving report: {e}[/red]")

@click.command()
@click.option('-f', '--file', required=True, help='Report file to analyze')
@click.option('-s', '--summary', is_flag=True, help='Show summary only')
def analyze_report(file, summary):
    """
    Analyze airdrop security report file
    
    Examples:
    shadowscan analyze-report -f airdrop_scan_20250916_120000.json
    shadowscan analyze-report -f report.json -s
    """
    
    try:
        with open(file, 'r') as f:
            results = json.load(f)
        
        console.print(Panel.fit(
            f"[bold blue]📊 Airdrop Security Report Analysis[/bold blue]\n"
            f"File: [cyan]{file}[/cyan]",
            title="📈 Analysis"
        ))
        
        if summary:
            show_summary(results)
        else:
            display_results(results, verbose=True)
        
    except FileNotFoundError:
        console.print(f"[red]❌ Report file not found: {file}[/red]")
        raise click.ClickException(f"Report file not found: {file}")
    except json.JSONDecodeError:
        console.print(f"[red]❌ Invalid JSON in report file: {file}[/red]")
        raise click.ClickException(f"Invalid JSON in report file: {file}")

def show_summary(results: Dict[str, Any]):
    """Show executive summary of results"""
    
    summary_table = Table()
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")
    
    # Basic info
    target = results.get('target_url', 'Unknown')
    summary_table.add_row("Target URL", target)
    
    # Technology stack
    tech_stack = results.get('technology_stack', {})
    framework = tech_stack.get('framework', 'Unknown')
    backend = tech_stack.get('backend', 'Unknown')
    summary_table.add_row("Framework", framework)
    summary_table.add_row("Backend", backend)
    
    # Endpoints
    endpoints = results.get('endpoints', [])
    summary_table.add_row("Endpoints Discovered", str(len(endpoints)))
    
    # Vulnerabilities
    vulnerabilities = results.get('vulnerabilities', [])
    critical_count = len([v for v in vulnerabilities if v.get('severity') == 'Critical'])
    high_count = len([v for v in vulnerabilities if v.get('severity') == 'High'])
    medium_count = len([v for v in vulnerabilities if v.get('severity') == 'Medium'])
    low_count = len([v for v in vulnerabilities if v.get('severity') == 'Low'])
    
    vuln_summary = f"Critical: {critical_count}, High: {high_count}, Medium: {medium_count}, Low: {low_count}"
    summary_table.add_row("Vulnerabilities", vuln_summary)
    
    console.print(summary_table)
    
    # Risk assessment
    if critical_count > 0:
        console.print("\n[bold red]🚨 CRITICAL RISK: Immediate action required![/bold red]")
    elif high_count > 0:
        console.print("\n[bold red]🚨 HIGH RISK: Action required before launch[/bold red]")
    elif medium_count > 0:
        console.print("\n[bold yellow]⚠️  MEDIUM RISK: Consider addressing before launch[/bold yellow]")
    else:
        console.print("\n[bold green]✅ LOW RISK: Ready for launch[/bold green]")

# Add commands to CLI
if __name__ == '__main__':
    scan_airdrop()