# shadowscan/commands/defend.py
import asyncio
import click
from rich.console import Console
from rich.panel import Panel

from shadowscan.core.professional_engine import ProfessionalPenetrationEngine
from ..utils.display_helpers import console, generate_defense_recommendations, display_defense_analysis

@click.command()
@click.option("--target", "-t", required=True,
              help="Target contract address for defense analysis")
@click.option("--chain", "-c", default="ethereum",
              help="Blockchain network")
def defend(target: str, chain: str):
    """Blue Team defense analysis and hardening recommendations."""
    console.print(Panel.fit(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Chain:[/bold] {chain.upper()}\n"
        f"[bold]Focus:[/bold] DEFENSIVE HARDENING",
        title="[bold blue]Blue Team Defense Analysis[/bold blue]"
    ))

    try:
        engine = ProfessionalPenetrationEngine(
            target=target,
            scan_type="blockchain",
            chain=chain
        )
        results = asyncio.run(engine.screen_only_mode())
        recommendations = generate_defense_recommendations(results)
        display_defense_analysis(recommendations)
    except Exception as e:
        console.print(f"[bold red]❌ Defense analysis failed:[/bold red] {str(e)}")
        sys.exit(1)
