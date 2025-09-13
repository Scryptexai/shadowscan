# shadowscan/commands/attack.py
import click
from rich.console import Console
from rich.panel import Panel
from typing import Optional  # ✅ Tambahkan ini!

from ..utils.display_helpers import console, simulate_flashloan_education, simulate_oracle_manipulation_education, simulate_reentrancy_education

@click.command()
@click.option("--scenario", type=click.Choice(['flashloan', 'oracle_manipulation', 'reentrancy']),
              required=True, help="Attack scenario to simulate")
@click.option("--dry-run", is_flag=True,
              help="Dry run mode (simulation only)")
@click.option("--target", "-t",
              help="Specific target for red team simulation")
def attack(scenario: str, dry_run: bool, target: Optional[str]):
    """Red Team simulation mode - Educational attack scenario simulation."""
    if not dry_run:
        console.print("[bold red]❌ Live attack mode disabled.[/bold red]")
        console.print("Only --dry-run mode is available for educational simulation.")
        return

    console.print(Panel.fit(
        f"[bold]Scenario:[/bold] {scenario.upper()}\n"
        f"[bold]Mode:[/bold] DRY RUN (Educational)\n"
        f"[bold]Target:[/bold] {target or 'Generic Pattern'}\n"
        f"[bold]Environment:[/bold] ISOLATED SIMULATION",
        title="[bold yellow]Red Team Educational Simulation[/bold yellow]"
    ))

    try:
        if scenario == "flashloan":
            simulate_flashloan_education()
        elif scenario == "oracle_manipulation":
            simulate_oracle_manipulation_education()
        elif scenario == "reentrancy":
            simulate_reentrancy_education()
    except Exception as e:
        console.print(f"[bold red]❌ Simulation failed:[/bold red] {str(e)}")
