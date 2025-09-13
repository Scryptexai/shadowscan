# shadowscan/commands/run.py
import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel

from shadowscan.core.professional_engine import ProfessionalPenetrationEngine
from ..utils.display_helpers import console, generate_professional_report

global current_engine

@click.command()
@click.option("--target", "-t", required=True,
              help="Target contract address")
@click.option("--type", "-T", type=click.Choice(['blockchain', 'web', 'all']),
              default='blockchain', help="Scan type")
@click.option("--chain", "-c", default="ethereum",
              help="Blockchain network")
@click.option("--output", "-o",
              help="Output file for report")
@click.option("--format", "-f", type=click.Choice(['html', 'json', 'pdf']),
              default='html', help="Report format")
@click.option("--stealth", is_flag=True,
              help="Enable stealth mode (minimal logging)")
def run(target: str, type: str, chain: str, output: Optional[str],
        format: str, stealth: bool):
    """Execute complete professional penetration test (all 3 stages)."""
    global current_engine

    if not stealth:
        console.print(Panel.fit(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Type:[/bold] {type.upper()}\n"
            f"[bold]Chain:[/bold] {chain.upper()}\n"
            f"[bold]Methodology:[/bold] 3-Stage Professional",
            title="[bold cyan]Complete Professional Engagement[/bold cyan]"
        ))

    if not output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = f"reports/shadowscan_professional_{timestamp}.{format}"

    Path("reports").mkdir(exist_ok=True)

    try:
        current_engine = ProfessionalPenetrationEngine(
            target=target,
            scan_type=type,
            chain=chain
        )
        results = asyncio.run(current_engine.execute_full_professional_test())
        generate_professional_report(results, output, format, stealth)
        if not stealth:
            console.print(f"\n[bold green]✅ Complete professional report:[/bold green] {output}")
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠️ Professional engagement interrupted[/bold yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]❌ Engagement failed:[/bold red] {str(e)}")
        sys.exit(1)
