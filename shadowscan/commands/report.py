# shadowscan/commands/report.py
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel

from shadowscan.core.professional_engine import ProfessionalPenetrationEngine
from ..utils.display_helpers import console, generate_professional_report

@click.command()
@click.option("--target", "-t", required=True,
              help="Target contract address")
@click.option("--chain", "-c", default="ethereum",
              help="Blockchain network")
@click.option("--output", "-o",
              help="Output directory for reports")
@click.option("--format", "-f", type=click.Choice(['html', 'json', 'pdf']),
              default='html', help="Report format")
def report(target: str, chain: str, output: Optional[str], format: str):
    """Generate comprehensive professional penetration test report."""
    global current_engine

    if not current_engine:
        console.print("[bold red]❌ No active session.[/bold red]")
        console.print("Run 'shadowscan run' for full engagement or 'shadowscan screen' + 'shadowscan verify' for staged approach.")
        return

    if not output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = f"reports/shadowscan_professional_{timestamp}.{format}"

    Path("reports").mkdir(exist_ok=True)

    try:
        console.print("[bold blue]📋 Generating Professional Report...[/bold blue]")
        generate_professional_report({}, output, format, False)
        console.print(f"[bold green]✅ Professional report generated:[/bold green] {output}")

    except Exception as e:
        console.print(f"[bold red]❌ Report generation failed:[/bold red] {str(e)}")
        sys.exit(1)
