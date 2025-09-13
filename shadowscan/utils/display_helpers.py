# shadowscan/utils/display_helpers.py
from rich.table import Table
from rich.console import Console
import json
from pathlib import Path
from typing import Dict, Any

console = Console()

def display_screening_summary(results: Dict[str, Any]):
    """Display screening results summary."""
    intelligence = results.get("intelligence_data", {})
    findings = results.get("all_findings", [])

    table = Table(title="Contract Intelligence Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Total Functions", str(len(getattr(intelligence, 'functions', []))))
    table.add_row("Sensitive Functions", str(len(getattr(intelligence, 'sensitive_functions', []))))
    table.add_row("Is Proxy", str(getattr(intelligence, 'is_proxy', False)))
    table.add_row("Is Upgradeable", str(getattr(intelligence, 'upgradeable', False)))
    table.add_row("Potential Vulnerabilities", str(len(findings)))

    console.print(table)

    if findings:
        console.print(f"\n[bold yellow]🔍 POTENTIAL VULNERABILITIES:[/bold yellow]")
        for finding in findings:
            severity_colors = {
                "CRITICAL": "bright_red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "blue"
            }
            color = severity_colors.get(finding.get("severity", "MEDIUM"), "white")
            score = finding.get("exploitability_score", 0)
            console.print(f"  [{color}]{finding.get('id')}[/{color}] - Exploitability: {score:.1f}")
            console.print(f"    {finding.get('description', 'No description')}")

def display_verification_results(results: Dict[str, Any]):
    """Display verification results."""
    verification_result = results.get("verification_result", {})
    verified = results.get("verified", False)
    hyp_id = results.get("hypothesis_id", "Unknown")

    if verified and verification_result:
        evidence = verification_result.get("evidence", {}) if hasattr(verification_result, 'evidence') else {}
        console.print(f"[bold green]✅ VULNERABILITY CONFIRMED: {hyp_id}[/bold green]")
        console.print("[bold red]This hypothesis has been successfully verified as exploitable.[/bold red]")
        if evidence:
            console.print(f"\nExploitation Evidence:")
            console.print(f"  Net Profit: ${evidence.get('net_profit', 0):.2f}")
            console.print(f"  Price Impact: {evidence.get('price_change_percent', 0):.1f}%")
            console.print(f"  Manipulation Cost: ${evidence.get('manipulation_cost', 0):.2f}")
            console.print(f"  Gas Used: {evidence.get('gas_used', 0):,}")
        console.print(f"\nStatus: VERIFIED EXPLOITABLE")
    else:
        error_msg = "Unable to confirm exploitation"
        if verification_result and hasattr(verification_result, 'error'):
            error_msg = verification_result.error
        elif isinstance(verification_result, dict):
            error_msg = verification_result.get("error", error_msg)
        console.print(f"[bold yellow]⚠️ VERIFICATION INCONCLUSIVE: {hyp_id}[/bold yellow]")
        console.print(f"Reason: {error_msg}")
        console.print("This does not necessarily mean the vulnerability is invalid.")
        console.print("Consider manual analysis or different verification parameters.")

def save_screening_results(results: Dict[str, Any], output_path: str, format: str):
    """Save screening results to file."""
    if format == "json":
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    elif format == "html":
        pass  # Would generate HTML report

def generate_professional_report(results: Dict[str, Any], output_path: str,
                               format: str, stealth: bool = False):
    """Generate professional report."""
    if not stealth:
        console.print(f"[bold blue]📄 Generating professional {format.upper()} report...[/bold blue]")

    # Would use ReportGenerator to create professional report
    # For now, save as JSON
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)

def simulate_flashloan_education():
    """Educational flash loan attack simulation."""
    console.print("\n[bold yellow]📚 Flash Loan Attack Education[/bold yellow]")
    console.print("1. Borrow large amount (no collateral required)")
    console.print("2. Manipulate market/oracle price")
    console.print("3. Execute profitable action with manipulated price")
    console.print("4. Restore market state")
    console.print("5. Repay loan + fees, keep profit")
    console.print("\n[bold blue]Key Insight:[/bold blue] Atomicity enables risk-free arbitrage")


def simulate_oracle_manipulation_education():
    """Educational oracle manipulation simulation."""
    console.print("\n[bold yellow]📚 Oracle Manipulation Education[/bold yellow]")
    console.print("1. Identify price oracle dependency")
    console.print("2. Calculate manipulation cost vs potential profit")
    console.print("3. Execute large trade to skew oracle price")
    console.print("4. Call vulnerable function during manipulation")
    console.print("5. Extract profit and restore state")
    console.print("\n[bold blue]Key Insight:[/bold blue] DEX-based oracles are manipulatable")


def simulate_reentrancy_education():
    """Educational reentrancy attack simulation."""
    console.print("\n[bold yellow]📚 Reentrancy Attack Education[/bold yellow]")
    console.print("1. Call vulnerable function")
    console.print("2. Function makes external call to attacker")
    console.print("3. Attacker re-enters before state update")
    console.print("4. Drain funds through repeated calls")
    console.print("5. Original function completes with outdated state")
    console.print("\n[bold blue]Key Insight:[/bold blue] Check-effects-interactions pattern prevents this")

# ✅ Tambahkan fungsi-fungsi defense di sini
def generate_defense_recommendations(screening_results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate defense recommendations based on screening."""
    findings = screening_results.get("all_findings", [])
    intelligence = screening_results.get("intelligence_data", {})

    recommendations = {
        "immediate_actions": [],
        "monitoring_setup": [],
        "architectural_improvements": [],
        "incident_response": []
    }

    # Analyze findings and generate specific recommendations
    for finding in findings:
        if "oracle" in finding.get("category", ""):
            recommendations["immediate_actions"].append("Implement multi-oracle price validation")
            recommendations["monitoring_setup"].append("Set up price deviation alerts")

        if finding.get("exploitability_score", 0) > 0.8:
            recommendations["immediate_actions"].append(f"Address {finding.get('id')} (high exploitability)")

    # Check for upgradeable contracts
    if getattr(intelligence, 'upgradeable', False):
        recommendations["architectural_improvements"].append("Implement upgrade timelock mechanism")

    return recommendations


def display_defense_analysis(recommendations: Dict[str, Any]):
    """Display defense analysis results."""
    console.print("[bold blue]🛡️ DEFENSE RECOMMENDATIONS[/bold blue]")

    for category, items in recommendations.items():
        if items:
            console.print(f"\n[bold]{category.replace('_', ' ').title()}:[/bold]")
            for item in items:
                console.print(f"  • {item}")
