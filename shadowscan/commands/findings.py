# shadowscan/commands/findings.py
import json
from datetime import datetime
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from shadowscan.core.hypothesis_storage import HypothesisStorage, HypothesisStatus
from ..utils.display_helpers import console

@click.command()
@click.option("--target", "-t", help="Filter by target contract address")
@click.option("--status", type=click.Choice(['hypothesis', 'verified_true', 'verified_false', 'inconclusive']),
              help="Filter by hypothesis status")
@click.option("--category", help="Filter by vulnerability category")
@click.option("--export", help="Export findings to file")
def findings(target: Optional[str], status: Optional[str], category: Optional[str], export: Optional[str]):
    """List and manage vulnerability hypotheses."""
    storage = HypothesisStorage()

    status_filter = None
    if status:
        try:
            status_filter = HypothesisStatus.from_str(status)
        except ValueError as e:
            console.print(f"[bold red]❌ Invalid status: {status}[/bold red]")
            console.print("Valid statuses: hypothesis, verified_true, verified_false, inconclusive")
            return

    hypotheses = storage.list_hypotheses(
        target=target,
        status=status_filter,
        category=category
    )

    if not hypotheses:
        console.print("[yellow]No hypotheses found matching criteria.[/yellow]")
        console.print("\nTo generate hypotheses, run:")
        console.print("  shadowscan screen --target <contract_address> --chain <chain>")
        return

    stats = storage.get_statistics()
    console.print(Panel.fit(
        f"[bold]Total Hypotheses:[/bold] {stats['total_hypotheses']}\n"
        f"[bold]Targets Scanned:[/bold] {stats['targets_scanned']}\n"
        f"[bold]Showing:[/bold] {len(hypotheses)} results",
        title="[bold cyan]Findings Database[/bold cyan]"
    ))

    table = Table(title="Vulnerability Hypotheses")
    table.add_column("ID", style="cyan", no_wrap=True, width=25)
    table.add_column("Status", style="bold", width=15)
    table.add_column("Category", style="magenta", width=30)
    table.add_column("Target", style="blue", width=15)
    table.add_column("Exploitability", justify="right", width=12)
    table.add_column("Created", style="dim", width=10)

    for hyp in hypotheses:
        status_colors = {
            HypothesisStatus.HYPOTHESIS: "yellow",
            HypothesisStatus.VERIFIED_TRUE: "bright_red",
            HypothesisStatus.VERIFIED_FALSE: "green",
            HypothesisStatus.INCONCLUSIVE: "orange"
        }
        status_color = status_colors.get(hyp.status, "white")
        status_display = f"[{status_color}]{hyp.status.value.upper().replace('_', ' ')}[/{status_color}]"
        target_display = hyp.target[:10] + "..." if len(hyp.target) > 13 else hyp.target
        exploitability = f"{hyp.exploitability_score:.1f}"
        created_date = hyp.created_at[:10]

        table.add_row(
            hyp.id,
            status_display,
            hyp.category.replace("ORACLE_MANIP_", ""),
            target_display,
            exploitability,
            created_date
        )

    console.print(table)

    # ... (SELURUH KODE LAINNYA SAMA — TIDAK PERLU DIUBAH)
