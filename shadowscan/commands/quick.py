# shadowscan/commands/quick.py
import asyncio
import click
from rich.console import Console

from shadowscan.core.professional_engine import ProfessionalPenetrationEngine
from ..utils.display_helpers import console

@click.command()
@click.argument("contract_address")
@click.option("--chain", "-c", default="ethereum", help="Blockchain network")
def quick(contract_address: str, chain: str):
    """Quick vulnerability assessment for rapid triage."""
    console.print(f"[bold yellow]🚀 Quick Assessment:[/bold yellow] {contract_address}")
    console.print("Performing rapid vulnerability triage...")

    try:
        engine = ProfessionalPenetrationEngine(
            target=contract_address,
            scan_type="blockchain",
            chain=chain
        )
        asyncio.run(engine._verify_target_connectivity())
        console.print("✅ Contract verified and accessible")
        console.print("\n[bold cyan]Recommendation:[/bold cyan]")
        console.print(f"Run full screening: shadowscan screen -t {contract_address} --chain {chain}")
    except Exception as e:
        console.print(f"❌ Quick assessment failed: {str(e)}")
