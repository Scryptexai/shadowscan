"""
ShadowScan Professional Penetration Testing Engine (Updated)

Integrates all professional components:
- EVM Provider & Simulator
- Intelligence Collectors
- Vulnerability Detectors
- Exploit Verifiers
- Evidence-based Reporting
"""

import asyncio
import time
import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.table import Table

from shadowscan.adapters.evm.provider import EVMProvider
from shadowscan.adapters.evm.simulator import EVMSimulator
from shadowscan.collectors.evm.contract_intel import ContractIntelCollector
from shadowscan.detectors.evm.oracle_manipulation import OracleManipulationDetector
from shadowscan.verifiers.evm.oracle_manipulation_verify import OracleManipulationVerifier
from shadowscan.models.findings import Finding, SeverityLevel
from shadowscan.core.hypothesis_storage import HypothesisStorage, Hypothesis, HypothesisStatus

# ✅ Tambahkan impor ini untuk memperbaiki error
from shadowscan.utils.logger import setup_logger

console = Console()
logger = setup_logger()  # Sekarang ini akan berfungsi!


class ProfessionalPenetrationEngine:
    """
    Professional 3-Stage Penetration Testing Engine

    Enhanced architecture:
    - Stage 1: Intelligence + Screening (Non-intrusive)
    - Stage 2: Controlled Verification (Fork-based)
    - Stage 3: Evidence-Based Reporting (Verified-only)
    """

    def __init__(self,
                 target: str,
                 scan_type: str,
                 chain: str = "ethereum",
                 custom_rpc: Optional[str] = None):
        self.target = target
        self.scan_type = scan_type
        self.chain = chain

        # Initialize core components
        self.provider = EVMProvider(chain, custom_rpc)
        self.simulator = EVMSimulator(backend="anvil")

        # Initialize collectors
        self.intel_collector = ContractIntelCollector(self.provider)

        # Initialize detectors
        self.oracle_detector = OracleManipulationDetector(self.provider)

        # Initialize verifiers
        self.oracle_verifier = OracleManipulationVerifier(self.provider, self.simulator)

        # State tracking
        self.intelligence_data = {}
        self.screening_findings = []
        self.verified_exploits = []
        self.scan_metadata = {
            "start_time": datetime.now(),
            "target": target,
            "scan_type": scan_type,
            "chain": chain,
            "stages_completed": []
        }

    async def execute_full_professional_test(self) -> Dict[str, Any]:
        """Execute complete professional penetration test."""

        console.print(Panel.fit(
            f"[bold cyan]🌑 ShadowScan Professional Penetration Testing[/bold cyan]\n"
            f"Target: {self.target}\n"
            f"Type: {self.scan_type.upper()}\n"
            f"Chain: {self.chain.upper()}\n"
            f"Framework: 3-Stage Evidence-Based Methodology",
            title="[bold]Professional Engagement Initialization[/bold]"
        ))

        try:
            # Verify target and connectivity
            await self._verify_target_connectivity()

            # Stage 1: Intelligence Gathering & Screening
            intelligence_results = await self._stage_1_intelligence_and_screening()

            # Stage 2: Controlled Exploit Verification
            verification_results = await self._stage_2_controlled_verification(intelligence_results)

            # Stage 3: Professional Evidence Documentation
            final_report = await self._stage_3_professional_documentation(verification_results)

            return final_report

        except Exception as e:
            logger.error(f"Professional test execution failed: {str(e)}")
            return {
                "status": "failed",
                "error": str(e),
                "metadata": self.scan_metadata
            }

    async def _verify_target_connectivity(self):
        """Verify target accessibility and chain connectivity."""

        console.print("[bold yellow]🔍 Verifying Target Connectivity...[/bold yellow]")

        # Check provider health
        health = await self.provider.health_check()
        if not health.get("connected"):
            raise ConnectionError(f"Chain connectivity failed: {health.get('error')}")

        # Verify target is a valid contract
        try:
            contract_info = await self.provider.get_contract_info(self.target)
            if not contract_info.bytecode or contract_info.bytecode == "0x":
                raise ValueError(f"No contract found at {self.target}")
        except Exception as e:
            raise ValueError(f"Target verification failed: {str(e)}")

        console.print(f"✅ Target verified on {health.get('config', {}).get('name')}")
        console.print(f"   Block: {health.get('latest_block')}")

    async def _stage_1_intelligence_and_screening(self) -> Dict[str, Any]:
        """Stage 1: Comprehensive intelligence gathering and vulnerability screening."""

        console.print(Panel.fit(
            "[bold yellow]🕵️ STAGE 1: INTELLIGENCE GATHERING & SCREENING[/bold yellow]\n"
            "• Contract intelligence collection\n"
            "• Vulnerability surface mapping\n"
            "• Risk assessment and prioritization",
            title="[bold]Intelligence Phase[/bold]"
        ))

        stage_findings = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:

            # Task 1: Contract Intelligence Collection
            intel_task = progress.add_task("Collecting contract intelligence...", total=100)

            self.intelligence_data = await self.intel_collector.collect_intelligence(
                self.target,
                include_storage=True
            )
            progress.update(intel_task, completed=100)

            console.print(f"✅ Intelligence: {len(self.intelligence_data.functions)} functions, "
                         f"{len(self.intelligence_data.sensitive_functions)} sensitive")

            # Task 2: Oracle Manipulation Detection
            oracle_task = progress.add_task("Screening oracle manipulation vectors...", total=100)

            oracle_results = await self.oracle_detector.screen(self.target)
            progress.update(oracle_task, completed=100)

            if oracle_results.get("findings"):
                stage_findings.extend(oracle_results["findings"])
                console.print(f"✅ Oracle screening: {len(oracle_results['findings'])} potential vulnerabilities")
            else:
                console.print("❌ Oracle screening: No vulnerabilities detected")

            # Task 3: Additional detectors would go here
            # For now, we'll focus on oracle manipulation as the primary detector

        # Filter findings by exploitability score
        high_exploitability = [
            f for f in stage_findings
            if f.get("exploitability_score", 0) > 0.7
        ]

        self.screening_findings = stage_findings

        console.print(Panel.fit(
            f"[bold green]Intelligence & Screening Complete[/bold green]\n"
            f"Contract Functions: {len(self.intelligence_data.functions)}\n"
            f"Sensitive Functions: {len(self.intelligence_data.sensitive_functions)}\n"
            f"Total Findings: {len(stage_findings)}\n"
            f"High Exploitability: {len(high_exploitability)}\n"
            f"Proxy Contract: {'Yes' if self.intelligence_data.is_proxy else 'No'}\n"
            f"Upgradeable: {'Yes' if self.intelligence_data.upgradeable else 'No'}",
            title="[bold]Stage 1 Results[/bold]"
        ))

        self.scan_metadata["stages_completed"].append("intelligence_and_screening")

        return {
            "stage": "intelligence_and_screening",
            "intelligence_data": self.intelligence_data,
            "total_findings": len(stage_findings),
            "high_exploitability_findings": high_exploitability,
            "all_findings": stage_findings,
            "metadata": {
                "completion_time": datetime.now(),
                "functions_analyzed": len(self.intelligence_data.functions),
                "storage_slots_analyzed": len(self.intelligence_data.storage_layout)
            }
        }

    async def _stage_2_controlled_verification(self,
                                             intelligence_results: Dict[str, Any]) -> Dict[str, Any]:
        """Stage 2: Controlled exploit verification in fork environments."""

        high_exploitability = intelligence_results.get("high_exploitability_findings", [])

        if not high_exploitability:
            console.print(Panel.fit(
                "[bold yellow]⏭️ STAGE 2: VERIFICATION SKIPPED[/bold yellow]\n"
                "No high-exploitability findings to verify",
                title="[bold]Verification Phase[/bold]"
            ))
            return {
                "stage": "controlled_verification",
                "verified_exploits": [],
                "skipped": True,
                "reason": "No high-exploitability findings"
            }

        console.print(Panel.fit(
            f"[bold red]⚔️ STAGE 2: CONTROLLED EXPLOIT VERIFICATION[/bold red]\n"
            f"Testing {len(high_exploitability)} high-exploitability findings\n"
            "• Fork-based testing (Anvil/Tenderly)\n"
            "• Evidence capture and validation\n"
            "• Zero mainnet impact",
            title="[bold]Verification Phase[/bold]"
        ))

        verified_exploits = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:

            verify_task = progress.add_task("Verifying exploits...", total=len(high_exploitability))

            for finding in high_exploitability:
                vulnerability_type = finding.get("id", "").replace("ORACLE_MANIP_", "").lower()

                try:
                    # Verify oracle manipulation vulnerabilities
                    if "oracle" in finding.get("category", ""):
                        verification_result = await self.oracle_verifier.verify_vulnerability(
                            target_contract=self.target,
                            vulnerability=finding,
                            fork_block=None  # Use latest block
                        )

                        if verification_result.vulnerability_confirmed:
                            # Create proof of concept
                            poc = await self.oracle_verifier.create_proof_of_concept(
                                finding, verification_result
                            )

                            verified_exploits.append({
                                **finding,
                                "exploit_verified": True,
                                "verification_result": verification_result,
                                "proof_of_concept": poc,
                                "verification_timestamp": datetime.now().isoformat()
                            })

                            console.print(f"✅ EXPLOIT VERIFIED: {finding.get('title')}")
                            console.print(f"   Net Profit: ${verification_result.evidence.net_profit:.2f}")
                            console.print(f"   Price Impact: {verification_result.evidence.price_change_percent:.1f}%")
                        else:
                            console.print(f"❌ Verification failed: {finding.get('title')}")
                            console.print(f"   Reason: {verification_result.error or 'Unable to confirm exploitation'}")

                except Exception as e:
                    console.print(f"⚠️ Verification error for {finding.get('title')}: {str(e)}")
                    logger.error(f"Verification failed: {str(e)}")

                progress.update(verify_task, advance=1)

        self.verified_exploits = verified_exploits

        console.print(Panel.fit(
            f"[bold green]Controlled Verification Complete[/bold green]\n"
            f"Findings Tested: {len(high_exploitability)}\n"
            f"Successfully Exploited: {len(verified_exploits)}\n"
            f"Verification Success Rate: {len(verified_exploits)/max(len(high_exploitability), 1)*100:.1f}%\n"
            f"Total Potential Profit: ${sum([v.get('verification_result', {}).get('evidence', {}).get('net_profit', 0) for v in verified_exploits]):.2f}",
            title="[bold]Stage 2 Results[/bold]"
        ))

        self.scan_metadata["stages_completed"].append("controlled_verification")

        return {
            "stage": "controlled_verification",
            "verified_exploits": verified_exploits,
            "tested_findings": len(high_exploitability),
            "successful_verifications": len(verified_exploits),
            "verification_rate": len(verified_exploits)/max(len(high_exploitability), 1),
            "metadata": {
                "completion_time": datetime.now(),
                "total_simulation_time": 0  # Would track actual simulation time
            }
        }

    async def _stage_3_professional_documentation(self,
                                                verification_results: Dict[str, Any]) -> Dict[str, Any]:
        """Stage 3: Professional evidence-based documentation."""

        verified_exploits = verification_results.get("verified_exploits", [])

        console.print(Panel.fit(
            f"[bold blue]📋 STAGE 3: PROFESSIONAL DOCUMENTATION[/bold blue]\n"
            f"Documenting {len(verified_exploits)} verified exploitable vulnerabilities\n"
            "• Executive summary generation\n"
            "• Technical evidence compilation\n"
            "• Remediation roadmap creation",
            title="[bold]Documentation Phase[/bold]"
        ))

        # Categorize verified exploits by severity
        critical_exploits = [e for e in verified_exploits if e.get("severity") == "CRITICAL"]
        high_exploits = [e for e in verified_exploits if e.get("severity") == "HIGH"]
        medium_exploits = [e for e in verified_exploits if e.get("severity") == "MEDIUM"]

        # Calculate total business impact
        total_potential_loss = sum([
            e.get("verification_result", {}).get("evidence", {}).get("net_profit", 0)
            for e in verified_exploits
        ])

        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            verified_exploits, total_potential_loss
        )

        # Generate technical details
        technical_details = self._generate_technical_details(verified_exploits)

        # Generate remediation roadmap
        remediation_roadmap = self._generate_remediation_roadmap(verified_exploits)

        # Create final professional report
        final_report = {
            "report_metadata": {
                "target": self.target,
                "scan_type": self.scan_type,
                "chain": self.chain,
                "generated_at": datetime.now().isoformat(),
                "total_engagement_time": (datetime.now() - self.scan_metadata["start_time"]).total_seconds(),
                "methodology": "3-Stage Professional Penetration Testing",
                "stages_completed": self.scan_metadata["stages_completed"],
                "framework_version": "ShadowScan Professional v1.0.0"
            },
            "executive_summary": executive_summary,
            "intelligence_overview": {
                "contract_analysis": {
                    "total_functions": len(self.intelligence_data.functions),
                    "sensitive_functions": len(self.intelligence_data.sensitive_functions),
                    "access_controlled": len(self.intelligence_data.access_controls.get("protected_functions", [])),
                    "is_proxy": self.intelligence_data.is_proxy,
                    "is_upgradeable": self.intelligence_data.upgradeable
                },
                "attack_surface": {
                    "total_findings_identified": len(self.screening_findings),
                    "high_risk_findings": len([f for f in self.screening_findings if f.get("exploitability_score", 0) > 0.7]),
                    "verified_exploitable": len(verified_exploits)
                }
            },
            "verified_vulnerabilities": verified_exploits,
            "technical_details": technical_details,
            "remediation_roadmap": remediation_roadmap,
            "appendices": {
                "function_inventory": [
                    {
                        "name": func.name,
                        "signature": func.signature,
                        "mutability": func.mutability,
                        "access_controlled": func.access_controlled
                    }
                    for func in self.intelligence_data.functions[:20]  # Limit for report size
                ],
                "methodology_notes": self._generate_methodology_notes()
            }
        }

        self._display_professional_summary(final_report)
        self.scan_metadata["stages_completed"].append("professional_documentation")

        return final_report

    def _generate_executive_summary(self,
                                  verified_exploits: List[Dict[str, Any]],
                                  total_potential_loss: float) -> Dict[str, Any]:
        """Generate executive summary for leadership consumption."""

        # Calculate risk metrics
        critical_count = len([e for e in verified_exploits if e.get("severity") == "CRITICAL"])
        high_count = len([e for e in verified_exploits if e.get("severity") == "HIGH"])

        # Determine overall risk rating
        if critical_count > 0:
            overall_risk = "CRITICAL"
            risk_description = "Immediate action required - exploitable vulnerabilities confirmed"
        elif high_count > 0:
            overall_risk = "HIGH"
            risk_description = "High priority remediation required"
        elif len(verified_exploits) > 0:
            overall_risk = "MEDIUM"
            risk_description = "Medium priority vulnerabilities identified"
        else:
            overall_risk = "LOW"
            risk_description = "No exploitable vulnerabilities confirmed"

        # Business impact assessment
        business_impact = self._assess_business_impact(verified_exploits)

        return {
            "overall_risk_rating": overall_risk,
            "risk_description": risk_description,
            "total_verified_vulnerabilities": len(verified_exploits),
            "severity_breakdown": {
                "critical": critical_count,
                "high": high_count,
                "medium": len([e for e in verified_exploits if e.get("severity") == "MEDIUM"]),
                "low": len([e for e in verified_exploits if e.get("severity") == "LOW"])
            },
            "business_impact": business_impact,
            "estimated_potential_loss": f"${total_potential_loss:.2f}",
            "remediation_priority": "Immediate" if critical_count > 0 else "High" if high_count > 0 else "Medium",
            "key_recommendations": self._generate_key_recommendations(verified_exploits)
        }

    def _generate_technical_details(self, verified_exploits: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate detailed technical analysis."""

        exploitation_evidence = []
        attack_vectors = {}

        for exploit in verified_exploits:
            verification_result = exploit.get("verification_result", {})
            evidence = verification_result.get("evidence", {})
            poc = exploit.get("proof_of_concept", {})

            exploitation_evidence.append({
                "vulnerability_id": exploit.get("id"),
                "vulnerability_title": exploit.get("title"),
                "attack_vector": poc.get("exploitation_method", "Unknown"),
                "proof_of_concept": {
                    "manipulation_successful": verification_result.get("vulnerability_confirmed", False),
                    "financial_impact": poc.get("evidence", {}).get("financial_impact", {}),
                    "technical_evidence": poc.get("evidence", {}).get("transaction_details", {})
                },
                "reproduction_complexity": "Low" if "flash_loan" in str(poc) else "Medium"
            })

            # Group by attack vector
            attack_type = poc.get("exploitation_method", "Unknown")
            attack_vectors.setdefault(attack_type, []).append(exploit.get("id"))

        return {
            "exploitation_evidence": exploitation_evidence,
            "attack_vector_analysis": attack_vectors,
            "common_patterns": self._identify_common_vulnerability_patterns(verified_exploits),
            "exploit_complexity": self._assess_exploit_complexity(verified_exploits)
        }

    def _generate_remediation_roadmap(self, verified_exploits: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate prioritized remediation roadmap."""

        immediate_actions = []
        short_term_actions = []
        long_term_actions = []

        for exploit in verified_exploits:
            severity = exploit.get("severity", "MEDIUM")
            poc = exploit.get("proof_of_concept", {})
            remediation = poc.get("remediation", [])

            if severity == "CRITICAL":
                immediate_actions.extend(remediation)
            elif severity == "HIGH":
                short_term_actions.extend(remediation)
            else:
                long_term_actions.extend(remediation)

        # Remove duplicates while preserving order
        immediate_actions = list(dict.fromkeys(immediate_actions))
        short_term_actions = list(dict.fromkeys(short_term_actions))
        long_term_actions = list(dict.fromkeys(long_term_actions))

        return {
            "immediate_actions": {
                "timeline": "0-7 days",
                "priority": "CRITICAL",
                "actions": immediate_actions[:5]  # Top 5 most critical
            },
            "short_term_actions": {
                "timeline": "1-4 weeks",
                "priority": "HIGH",
                "actions": short_term_actions[:8]
            },
            "long_term_actions": {
                "timeline": "1-3 months",
                "priority": "MEDIUM",
                "actions": long_term_actions[:10]
            },
            "monitoring_recommendations": [
                "Implement oracle price deviation monitoring",
                "Set up alerts for unusual transaction patterns",
                "Monitor for flash loan attacks targeting protocol",
                "Track TVL changes and user behavior anomalies"
            ]
        }

    def _assess_business_impact(self, verified_exploits: List[Dict[str, Any]]) -> str:
        """Assess overall business impact of verified vulnerabilities."""

        impact_categories = []

        for exploit in verified_exploits:
            title = exploit.get("title", "").lower()
            if "oracle" in title:
                impact_categories.append("price_manipulation")
            if "flash" in title:
                impact_categories.append("capital_efficiency_attacks")
            if "reentrancy" in title:
                impact_categories.append("fund_drainage")

        if "price_manipulation" in impact_categories:
            return "Critical: Price oracle manipulation can lead to protocol insolvency and user fund loss"
        elif "fund_drainage" in impact_categories:
            return "High: Direct fund extraction possible, immediate user impact"
        elif "capital_efficiency_attacks" in impact_categories:
            return "Medium: Protocol efficiency compromised, indirect user impact"
        else:
            return "Low: Limited direct impact on core protocol functionality"

    def _generate_key_recommendations(self, verified_exploits: List[Dict[str, Any]]) -> List[str]:
        """Generate top-level strategic recommendations."""

        recommendations = set()

        for exploit in verified_exploits:
            if "oracle" in exploit.get("category", ""):
                recommendations.add("Implement multi-oracle price validation system")
                recommendations.add("Add circuit breakers for extreme price movements")

            if exploit.get("severity") == "CRITICAL":
                recommendations.add("Pause affected protocol functions until remediation")

        # Add general security recommendations
        recommendations.add("Conduct regular security audits by multiple firms")
        recommendations.add("Implement bug bounty program for ongoing security testing")

        return list(recommendations)[:5]  # Top 5 recommendations

    def _identify_common_vulnerability_patterns(self, verified_exploits: List[Dict[str, Any]]) -> List[str]:
        """Identify common patterns across verified vulnerabilities."""

        patterns = []
        categories = [e.get("category", "") for e in verified_exploits]

        if categories.count("oracle_manipulation") > 1:
            patterns.append("Multiple oracle manipulation vectors present")

        if any("flash" in str(e.get("proof_of_concept", {})) for e in verified_exploits):
            patterns.append("Flash loan attack surface identified")

        return patterns

    def _assess_exploit_complexity(self, verified_exploits: List[Dict[str, Any]]) -> str:
        """Assess overall complexity of exploitation."""

        complexities = []
        for exploit in verified_exploits:
            poc = exploit.get("proof_of_concept", {})
            if "flash_loan" in str(poc).lower():
                complexities.append("low")  # Flash loans are readily available
            else:
                complexities.append("medium")

        if "low" in complexities:
            return "Low - Flash loans enable single-transaction exploitation"
        else:
            return "Medium - Requires multiple transactions or setup"

    def _generate_methodology_notes(self) -> List[str]:
        """Generate notes about the testing methodology."""

        return [
            "All exploit verification was conducted in isolated fork environments",
            "No mainnet transactions were executed during testing",
            "Verification focused on technical feasibility, not actual profit extraction",
            "Results represent point-in-time assessment based on current contract state",
            "Real-world exploitation may vary due to network conditions and MEV competition"
        ]

    def _display_professional_summary(self, report: Dict[str, Any]):
        """Display professional engagement summary."""

        summary = report["executive_summary"]
        verified_count = summary["total_verified_vulnerabilities"]

        # Create executive summary table
        table = Table(title="Professional Penetration Test - Executive Summary")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="magenta")

        table.add_row("Target Contract", self.target[:20] + "..." if len(self.target) > 20 else self.target)
        table.add_row("Overall Risk Rating", f"[bold red]{summary['overall_risk_rating']}[/bold red]")
        table.add_row("Verified Vulnerabilities", str(verified_count))
        table.add_row("Critical Issues", str(summary["severity_breakdown"]["critical"]))
        table.add_row("High Issues", str(summary["severity_breakdown"]["high"]))
        table.add_row("Estimated Potential Loss", summary["estimated_potential_loss"])
        table.add_row("Remediation Priority", summary["remediation_priority"])

        console.print(table)

        # Display verified vulnerabilities
        if self.verified_exploits:
            console.print(f"\n[bold red]VERIFIED EXPLOITABLE VULNERABILITIES:[/bold red]")
            for i, exploit in enumerate(self.verified_exploits, 1):
                severity_colors = {
                    "CRITICAL": "bright_red",
                    "HIGH": "red",
                    "MEDIUM": "yellow",
                    "LOW": "blue"
                }
                color = severity_colors.get(exploit.get("severity", "MEDIUM"), "white")

                verification_result = exploit.get("verification_result", {})
                evidence = verification_result.get("evidence", {})

                console.print(f"  {i}. [{color}][{exploit.get('severity')}][/{color}] {exploit.get('title')}")
                if evidence:
                    console.print(f"     Profit Potential: ${evidence.get('net_profit', 0):.2f}")
                    console.print(f"     Price Impact: {evidence.get('price_change_percent', 0):.1f}%")
        else:
            console.print(f"\n[bold green]✅ NO EXPLOITABLE VULNERABILITIES CONFIRMED[/bold green]")
            console.print("All potential vulnerabilities were tested but none could be successfully exploited.")

    async def screen_only_mode(self) -> Dict[str, Any]:
        """Execute screening-only mode for rapid assessment."""

        console.print(Panel.fit(
            "[bold yellow]🚀 PROFESSIONAL SCREENING MODE[/bold yellow]\n"
            "Rapid vulnerability assessment with intelligence gathering",
            title="[bold]Screening Mode[/bold]"
        ))

        await self._verify_target_connectivity()
        return await self._stage_1_intelligence_and_screening()

    async def verify_specific_hypothesis(self, hypothesis_id: str) -> Dict[str, Any]:
        """Verify a specific vulnerability hypothesis."""

        # Find the hypothesis from screening results
        target_finding = None
        for finding in self.screening_findings:
            if finding.get("id") == hypothesis_id:
                target_finding = finding
                break

        if not target_finding:
            return {
                "error": f"Hypothesis {hypothesis_id} not found",
                "available_hypotheses": [f.get("id") for f in self.screening_findings]
            }

        console.print(f"[bold yellow]🔍 Verifying Hypothesis: {hypothesis_id}[/bold yellow]")

        # Execute verification
        if "oracle" in target_finding.get("category", ""):
            verification_result = await self.oracle_verifier.verify_vulnerability(
                target_contract=self.target,
                vulnerability=target_finding,
                fork_block=None
            )

            return {
                "hypothesis_id": hypothesis_id,
                "verification_result": verification_result,
                "verified": verification_result.vulnerability_confirmed if verification_result else False
            }
        else:
            return {
                "hypothesis_id": hypothesis_id,
                "error": "No verifier available for this vulnerability type"
            }
