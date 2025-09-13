# shadowscan/commands/verify.py
import asyncio
import sys
import json
from datetime import datetime
from typing import Optional, Dict, Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

from shadowscan.core.professional_engine import ProfessionalPenetrationEngine
from shadowscan.core.hypothesis_storage import HypothesisStorage, HypothesisStatus
from shadowscan.core.execution_mode import ExecutionMode, ExecutionContext
from dataclasses import asdict
from ..utils.display_helpers import display_verification_results

console = Console()

@click.command()
@click.option("--hyp", required=True,
              help="Hypothesis ID to verify (from findings database)")
@click.option("--sim", type=click.Choice(['anvil', 'tenderly']), default='tenderly',
              help="Simulation backend (for simulator mode)")
@click.option("--mode", type=click.Choice(['simulator', 'mainnet']), default='simulator',
              help="Execution mode: simulator (safe) or mainnet (real)")
@click.option("--rpc-url", help="Custom RPC URL (required for mainnet mode)")
@click.option("--fork-block", type=int,
              help="Specific block number to fork from (simulator mode)")
@click.option("--output", "-o",
              help="Output file for verification results")
def verify(hyp: str, sim: str, mode: str, rpc_url: Optional[str], fork_block: Optional[int], output: Optional[str]):
    """Verify stored hypothesis through controlled simulation or mainnet execution."""
    storage = HypothesisStorage()

    # Load hypothesis from storage
    hypothesis = storage.get_hypothesis(hyp)
    if not hypothesis:
        console.print(f"[bold red]❌ Hypothesis not found:[/bold red] {hyp}")
        console.print("Use 'shadowscan findings' to see available hypotheses.")
        return

    # Set execution mode
    exec_mode = ExecutionMode(mode)
    context = ExecutionContext(
        mode=exec_mode,
        target_chain=hypothesis.chain,
        target_contract=hypothesis.target,
        rpc_url=rpc_url,
        fork_block=fork_block or hypothesis.block_number
    )

    # Safety warning for mainnet mode
    if exec_mode == ExecutionMode.MAINNET:
        console.print(Panel.fit(
            "[bold red]⚠️  DANGER: MAINNET EXECUTION MODE[/bold red]\n"
            "You are about to execute verification on REAL mainnet.\n"
            "This may cost real gas and interact with live contracts.\n"
            "Are you absolutely sure?",
            title="[bold red]WARNING[/bold red]"
        ))
        if not Confirm.ask("Proceed with mainnet execution?"):
            console.print("[bold yellow]Aborted by user.[/bold yellow]")
            return

    console.print(Panel.fit(
        f"[bold]Hypothesis:[/bold] {hyp}\n"
        f"[bold]Target:[/bold] {hypothesis.target}\n"
        f"[bold]Category:[/bold] {hypothesis.category}\n"
        f"[bold]Mode:[/bold] {mode.upper()}\n"
        f"[bold]{'Simulator' if mode == 'simulator' else 'RPC URL'}:[/bold] {sim.upper() if mode == 'simulator' else rpc_url}\n"
        f"[bold]Fork Block:[/bold] {context.fork_block or 'LATEST'}\n"
        f"[bold]Safety:[/bold] {'SANDBOX ONLY' if mode == 'simulator' else 'REAL MAINNET'}",
        title=f"[bold {'red' if mode == 'mainnet' else 'green'}]{'⚠️  MAINNET EXECUTION' if mode == 'mainnet' else '🛡️  Controlled Exploitation Verification'}[/bold]"
    ))

    try:
        # Initialize engine for verification
        engine = ProfessionalPenetrationEngine(
            target=hypothesis.target,
            scan_type="blockchain",
            chain=hypothesis.chain
        )

        # Convert hypothesis back to finding format for verification
        finding_dict = {
            "id": hypothesis.category,
            "title": hypothesis.title,
            "description": hypothesis.description,
            "category": "oracle_manipulation" if "ORACLE" in hypothesis.category else "unknown",
            "vulnerability_type": hypothesis.category.lower().replace("oracle_manip_", ""),
            "evidence": hypothesis.evidence,
            "target_contract": hypothesis.target,
            "exploitability_score": hypothesis.exploitability_score
        }

        # Execute verification
        if exec_mode == ExecutionMode.SIMULATOR:
            verification_result = asyncio.run(engine.oracle_verifier.verify_vulnerability(
                target_contract=hypothesis.target,
                vulnerability=finding_dict,
                fork_block=context.fork_block
            ))
        else:
            # Mainnet mode — jalankan tanpa fork (hati-hati!)
            verification_result = asyncio.run(engine.oracle_verifier.verify_vulnerability_on_mainnet(
                target_contract=hypothesis.target,
                vulnerability=finding_dict,
                rpc_url=context.get_rpc_url()
            ))

        # Create proof of concept if verification succeeded
        poc = None
        if verification_result.vulnerability_confirmed:
            poc = asyncio.run(engine.oracle_verifier.create_proof_of_concept(
                finding_dict, verification_result
            ))

        # Update hypothesis status in storage
        storage.mark_verified(hyp, asdict(verification_result), poc)

        # Display verification results
        display_verification_results({
            "hypothesis_id": hyp,
            "verification_result": verification_result,
            "verified": verification_result.vulnerability_confirmed if verification_result else False
        })

        # Save results if requested
        if output:
            results_data = {
                "hypothesis_id": hyp,
                "hypothesis": asdict(hypothesis),
                "verification_result": asdict(verification_result) if verification_result else None,
                "proof_of_concept": poc,
                "timestamp": datetime.now().isoformat(),
                "execution_mode": mode,
                "rpc_url": context.get_rpc_url() if mode == "mainnet" else None
            }

            with open(output, 'w') as f:
                json.dump(results_data, f, indent=2, default=str)
            console.print(f"\n[bold green]✅ Verification results saved:[/bold green] {output}")

        # Show next steps
        if verification_result.vulnerability_confirmed:
            console.print(f"\n[bold red]🚨 CRITICAL FINDING VERIFIED[/bold red]")
            if exec_mode == ExecutionMode.SIMULATOR:
                console.print("💡 Consider running on mainnet for final validation (use --mode mainnet)")
            console.print("Next steps:")
            console.print("1. Review proof-of-concept details")
            console.print("2. Implement recommended remediation")
            console.print("3. Generate professional report for stakeholders")

    except Exception as e:
        console.print(f"[bold red]❌ Verification failed:[/bold red] {str(e)}")
        sys.exit(1)
