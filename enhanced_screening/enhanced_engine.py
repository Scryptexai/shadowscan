"""
Enhanced Screening Engine
Advanced contract analysis with deep vulnerability scanning
"""

import asyncio
import logging
import json
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from web3 import Web3

from shadowscan.core.pipeline.screening_engine import ScreeningEngine
from detectors.enhanced_detector import (
    EnhancedVulnerabilityDetector, 
    DeepScanResult,
    VulnerabilityFinding
)
from shadowscan.collectors.evm.dex_discovery import DexDiscovery
from shadowscan.collectors.evm.oracle_intel import OracleIntel

logger = logging.getLogger(__name__)

class EnhancedScreeningEngine(ScreeningEngine):
    """Enhanced screening engine with deep vulnerability scanning"""
    
    def __init__(self, rpc_url: str, etherscan_api_key: Optional[str] = None):
        # Initialize parent screening engine
        super().__init__(rpc_url, etherscan_api_key)
        
        # Initialize enhanced components
        self.enhanced_detector = EnhancedVulnerabilityDetector(self.web3)
        self.deep_scanning_enabled = True
        
        # Enhanced analysis modules
        self.ecosystem_analyzer = EcosystemAnalyzer(self.web3)
        self.economic_assessor = EconomicImpactAssessor(self.web3)
        self.exploitation_planner = ExploitationPathPlanner(self.web3)
        
        logger.info("EnhancedScreeningEngine initialized with deep scanning capabilities")
    
    async def run_enhanced_screening(self,
                                    target: str,
                                    chain: str = 'ethereum',
                                    mode: str = 'fork',
                                    scan_depth: str = 'deep',
                                    vulnerability_types: List[str] = None,
                                    intensity: str = 'deep',
                                    opts: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run enhanced screening with deep vulnerability scanning
        
        Args:
            target: Target contract address
            chain: Blockchain network
            mode: fork or mainnet
            scan_depth: basic, deep, or intensive
            vulnerability_types: Specific vulnerability types to scan
            intensity: Analysis intensity level
            opts: Additional options
        """
        logger.info(f"🚀 Starting enhanced screening for {target}")
        logger.info(f"📊 Scan depth: {scan_depth}, Intensity: {intensity}")
        
        start_time = time.time()
        
        # Prepare options
        if opts is None:
            opts = {}
        
        # Step 1: Run basic screening first
        logger.info("🔍 Phase 1: Basic screening...")
        basic_result = await self._run_basic_screening(target, chain, mode, opts)
        
        # Step 2: Enhanced ecosystem analysis
        logger.info("🌐 Phase 2: Enhanced ecosystem analysis...")
        ecosystem_data = await self._enhanced_ecosystem_analysis(target, basic_result)
        
        # Step 3: Deep vulnerability scanning
        logger.info("🔬 Phase 3: Deep vulnerability scanning...")
        deep_scan_result = await self._run_deep_vulnerability_scan(
            target, scan_depth, vulnerability_types, intensity
        )
        
        # Step 4: Economic impact assessment
        logger.info("💰 Phase 4: Economic impact assessment...")
        economic_impact = await self._assess_economic_impact(
            target, deep_scan_result.vulnerabilities, ecosystem_data
        )
        
        # Step 5: Exploitation path planning
        logger.info("⚔️  Phase 5: Exploitation path planning...")
        exploitation_plans = await self._plan_exploitation_paths(
            target, deep_scan_result.vulnerabilities
        )
        
        # Step 6: Generate comprehensive report
        logger.info("📊 Phase 6: Generating enhanced report...")
        enhanced_report = self._generate_enhanced_report(
            target, chain, mode, basic_result, ecosystem_data, 
            deep_scan_result, economic_impact, exploitation_plans
        )
        
        total_time = time.time() - start_time
        
        logger.info(f"✅ Enhanced screening completed in {total_time:.2f}s")
        logger.info(f"📊 Found {len(deep_scan_result.vulnerabilities)} vulnerabilities")
        logger.info(f"🔬 Scan depth: {scan_depth}, Code coverage: {deep_scan_result.code_coverage:.1f}%")
        
        return {
            'success': True,
            'enhanced_report': enhanced_report,
            'deep_scan_result': deep_scan_result,
            'ecosystem_data': ecosystem_data,
            'economic_impact': economic_impact,
            'exploitation_plans': exploitation_plans,
            'execution_time': total_time,
            'session_file': enhanced_report.get('session_file', '')
        }
    
    async def _run_basic_screening(self,
                                  target: str,
                                  chain: str,
                                  mode: str,
                                  opts: Dict[str, Any]) -> Dict[str, Any]:
        """Run basic screening using parent engine"""
        try:
            # Use parent screening engine for basic analysis
            return super().run_screening(target, chain, mode, 'full', opts)
        except Exception as e:
            logger.error(f"Basic screening failed: {e}")
            return {'success': False, 'error': str(e)}
    
    async def _enhanced_ecosystem_analysis(self,
                                           target: str,
                                           basic_result: Dict) -> Dict[str, Any]:
        """Enhanced ecosystem analysis with deep relationship discovery"""
        ecosystem_data = {
            'target_contract': target,
            'direct_interactions': [],
            'indirect_relationships': [],
            'protocol_connections': [],
            'token_relationships': [],
            'governance_connections': [],
            'risk_assessment': {}
        }
        
        try:
            # Enhanced DEX discovery
            logger.info("🕸️  Enhanced DEX relationship discovery...")
            dex_relations = await self._enhanced_dex_discovery(target)
            ecosystem_data['dex_relations'] = dex_relations
            
            # Enhanced oracle analysis
            logger.info("🔮 Enhanced oracle dependency analysis...")
            oracle_deps = await self._enhanced_oracle_analysis(target)
            ecosystem_data['oracle_dependencies'] = oracle_deps
            
            # Protocol relationship analysis
            logger.info("🔗 Protocol relationship analysis...")
            protocol_rels = await self._analyze_protocol_relationships(target)
            ecosystem_data['protocol_relationships'] = protocol_rels
            
            # Token ecosystem analysis
            logger.info("🪙 Token ecosystem analysis...")
            token_ecosystem = await self._analyze_token_ecosystem(target)
            ecosystem_data['token_ecosystem'] = token_ecosystem
            
            # Governance connections
            logger.info("🏛️  Governance connection analysis...")
            governance_connections = await self._analyze_governance_connections(target)
            ecosystem_data['governance_connections'] = governance_connections
            
            # Comprehensive risk assessment
            logger.info("⚖️  Ecosystem risk assessment...")
            risk_assessment = await self._assess_ecosystem_risk(ecosystem_data)
            ecosystem_data['risk_assessment'] = risk_assessment
            
        except Exception as e:
            logger.error(f"Ecosystem analysis error: {e}")
        
        return ecosystem_data
    
    async def _run_deep_vulnerability_scan(self,
                                          target: str,
                                          scan_depth: str,
                                          vulnerability_types: List[str],
                                          intensity: str) -> DeepScanResult:
        """Run deep vulnerability scanning"""
        try:
            return await self.enhanced_detector.deep_scan_contract(
                contract_address=target,
                scan_depth=scan_depth,
                vulnerability_types=vulnerability_types,
                intensity=intensity
            )
        except Exception as e:
            logger.error(f"Deep scan error: {e}")
            return DeepScanResult(
                vulnerabilities=[],
                scan_depth=scan_depth,
                analysis_methods=[],
                execution_time=0,
                code_coverage=0,
                symbolic_states=0,
                constraints_solved=0,
                ecosystem_impact={}
            )
    
    async def _assess_economic_impact(self,
                                     target: str,
                                     vulnerabilities: List[VulnerabilityFinding],
                                     ecosystem_data: Dict) -> Dict[str, Any]:
        """Assess economic impact of vulnerabilities"""
        return await self.economic_assessor.assess_impact(
            target, vulnerabilities, ecosystem_data
        )
    
    async def _plan_exploitation_paths(self,
                                      target: str,
                                      vulnerabilities: List[VulnerabilityFinding]) -> List[Dict]:
        """Plan exploitation paths for discovered vulnerabilities"""
        plans = []
        
        for vuln in vulnerabilities:
            plan = await self.exploitation_planner.plan_exploitation(target, vuln)
            if plan:
                plans.append(plan)
        
        return plans
    
    def _generate_enhanced_report(self,
                                 target: str,
                                 chain: str,
                                 mode: str,
                                 basic_result: Dict,
                                 ecosystem_data: Dict,
                                 deep_scan_result: DeepScanResult,
                                 economic_impact: Dict,
                                 exploitation_plans: List[Dict]) -> Dict[str, Any]:
        """Generate enhanced screening report"""
        
        # Generate session ID
        session_id = f"enhanced_{target[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Prepare enhanced summary
        enhanced_summary = {
            'session_id': session_id,
            'target_address': target,
            'chain': chain,
            'mode': mode,
            'scan_type': 'enhanced_deep_scan',
            'timestamp': datetime.now().isoformat(),
            'basic_screening': {
                'success': basic_result.get('success', False),
                'vulnerabilities_found': len(basic_result.get('summary', {}).get('vulnerabilities_by_severity', {})),
                'execution_time': basic_result.get('execution_time', 0)
            },
            'enhanced_metrics': {
                'deep_vulnerabilities_found': len(deep_scan_result.vulnerabilities),
                'scan_depth': deep_scan_result.scan_depth,
                'code_coverage': deep_scan_result.code_coverage,
                'symbolic_states_analyzed': deep_scan_result.symbolic_states,
                'constraints_solved': deep_scan_result.constraints_solved,
                'analysis_methods_used': deep_scan_result.analysis_methods,
                'execution_time': deep_scan_result.execution_time
            },
            'ecosystem_analysis': {
                'dex_relations_count': len(ecosystem_data.get('dex_relations', [])),
                'oracle_dependencies_count': len(ecosystem_data.get('oracle_dependencies', [])),
                'protocol_relationships_count': len(ecosystem_data.get('protocol_relationships', [])),
                'token_ecosystem_size': len(ecosystem_data.get('token_ecosystem', {})),
                'governance_connections_count': len(ecosystem_data.get('governance_connections', [])),
                'ecosystem_risk_score': ecosystem_data.get('risk_assessment', {}).get('overall_risk_score', 0)
            },
            'vulnerability_breakdown': self._analyze_vulnerability_breakdown(deep_scan_result.vulnerabilities),
            'economic_impact': economic_impact,
            'exploitation_feasibility': self._assess_exploitation_feasibility(exploitation_plans),
            'recommendations': self._generate_recommendations(deep_scan_result.vulnerabilities, ecosystem_data)
        }
        
        # Save enhanced session data
        output_dir = Path(opts.get('output', 'reports/enhanced')) if opts else Path('reports/enhanced')
        output_dir.mkdir(parents=True, exist_ok=True)
        
        session_file = output_dir / f"enhanced_session_{session_id}.json"
        
        session_data = {
            'session_id': session_id,
            'enhanced_summary': enhanced_summary,
            'vulnerabilities': [self._serialize_vulnerability(v) for v in deep_scan_result.vulnerabilities],
            'ecosystem_data': ecosystem_data,
            'economic_impact': economic_impact,
            'exploitation_plans': exploitation_plans,
            'deep_scan_metrics': {
                'scan_depth': deep_scan_result.scan_depth,
                'analysis_methods': deep_scan_result.analysis_methods,
                'code_coverage': deep_scan_result.code_coverage,
                'symbolic_states': deep_scan_result.symbolic_states,
                'constraints_solved': deep_scan_result.constraints_solved,
                'execution_time': deep_scan_result.execution_time
            }
        }
        
        with open(session_file, 'w') as f:
            json.dump(session_data, f, indent=2, default=str)
        
        enhanced_summary['session_file'] = str(session_file)
        
        return enhanced_summary
    
    def _analyze_vulnerability_breakdown(self, vulnerabilities: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Analyze vulnerability breakdown by type and severity"""
        breakdown = {
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'by_category': {},
            'by_type': {},
            'confidence_distribution': {'high': 0, 'medium': 0, 'low': 0},
            'top_critical_vulnerabilities': []
        }
        
        for vuln in vulnerabilities:
            # Count by severity
            severity_key = vuln.severity.value.lower()
            breakdown['by_severity'][severity_key] += 1
            
            # Count by category
            category = vuln.category
            breakdown['by_category'][category] = breakdown['by_category'].get(category, 0) + 1
            
            # Count by type
            vuln_type = vuln.vulnerability_type
            breakdown['by_type'][vuln_type] = breakdown['by_type'].get(vuln_type, 0) + 1
            
            # Confidence distribution
            if vuln.confidence >= 0.8:
                breakdown['confidence_distribution']['high'] += 1
            elif vuln.confidence >= 0.5:
                breakdown['confidence_distribution']['medium'] += 1
            else:
                breakdown['confidence_distribution']['low'] += 1
            
            # Top critical vulnerabilities
            if vuln.severity == VulnerabilitySeverity.CRITICAL:
                breakdown['top_critical_vulnerabilities'].append({
                    'type': vuln.vulnerability_type,
                    'confidence': vuln.confidence,
                    'impact_score': vuln.impact_score,
                    'description': vuln.description
                })
        
        return breakdown
    
    def _assess_exploitation_feasibility(self, plans: List[Dict]) -> Dict[str, Any]:
        """Assess overall exploitation feasibility"""
        if not plans:
            return {'overall_feasibility': 0.0, 'feasible_attacks': 0, 'complexity': 'high'}
        
        total_feasibility = sum(plan.get('feasibility_score', 0) for plan in plans)
        feasible_count = sum(1 for plan in plans if plan.get('feasibility_score', 0) > 0.5)
        
        avg_feasibility = total_feasibility / len(plans)
        
        complexity = 'low' if avg_feasibility > 0.8 else 'medium' if avg_feasibility > 0.5 else 'high'
        
        return {
            'overall_feasibility': avg_feasibility,
            'feasible_attacks': feasible_count,
            'total_plans': len(plans),
            'complexity': complexity
        }
    
    def _generate_recommendations(self,
                                vulnerabilities: List[VulnerabilityFinding],
                                ecosystem_data: Dict) -> List[str]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Critical vulnerabilities first
        critical_vulns = [v for v in vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL]
        for vuln in critical_vulns:
            recommendations.extend(vuln.mitigation_suggestions)
        
        # High severity vulnerabilities
        high_vulns = [v for v in vulnerabilities if v.severity == VulnerabilitySeverity.HIGH]
        for vuln in high_vulns:
            recommendations.extend(vuln.mitigation_suggestions[:2])  # Top 2 suggestions
        
        # Ecosystem-level recommendations
        ecosystem_risk = ecosystem_data.get('risk_assessment', {}).get('overall_risk_score', 0)
        if ecosystem_risk > 0.7:
            recommendations.append("🌐 Implement comprehensive ecosystem monitoring due to high systemic risk")
        elif ecosystem_risk > 0.4:
            recommendations.append("🌐 Consider ecosystem-wide security measures")
        
        # General recommendations
        if len(vulnerabilities) > 10:
            recommendations.append("📊 Consider implementing formal verification tools")
            recommendations.append("🔒 Implement multi-layer security controls")
        
        return recommendations
    
    def _serialize_vulnerability(self, vulnerability: VulnerabilityFinding) -> Dict[str, Any]:
        """Serialize vulnerability finding for JSON storage"""
        return {
            'vulnerability_type': vulnerability.vulnerability_type,
            'severity': vulnerability.severity.value,
            'category': vulnerability.category,
            'description': vulnerability.description,
            'location': vulnerability.location,
            'confidence': vulnerability.confidence,
            'impact_score': vulnerability.impact_score,
            'detection_methods': [m.value for m in vulnerability.detection_methods],
            'evidence': vulnerability.evidence,
            'exploitation_path': vulnerability.exploitation_path,
            'mitigation_suggestions': vulnerability.mitigation_suggestions,
            'related_contracts': vulnerability.related_contracts,
            'economic_impact': vulnerability.economic_impact
        }
    
    # Enhanced ecosystem analysis methods (simplified implementations)
    async def _enhanced_dex_discovery(self, target: str) -> List[Dict]:
        """Enhanced DEX relationship discovery"""
        try:
            dex_discovery = DexDiscovery(self.web3)
            return await dex_discovery.discover_dex_relations(target, self.web3, 'ethereum')
        except Exception as e:
            logger.error(f"Enhanced DEX discovery error: {e}")
            return []
    
    async def _enhanced_oracle_analysis(self, target: str) -> List[Dict]:
        """Enhanced oracle dependency analysis"""
        try:
            oracle_intel = OracleIntel(self.web3)
            # This would need implementation in OracleIntel class
            return []
        except Exception as e:
            logger.error(f"Enhanced oracle analysis error: {e}")
            return []
    
    async def _analyze_protocol_relationships(self, target: str) -> List[Dict]:
        """Analyze protocol relationships"""
        # Simplified implementation
        return []
    
    async def _analyze_token_ecosystem(self, target: str) -> Dict[str, Any]:
        """Analyze token ecosystem relationships"""
        # Simplified implementation
        return {}
    
    async def _analyze_governance_connections(self, target: str) -> List[Dict]:
        """Analyze governance connections"""
        # Simplified implementation
        return []
    
    async def _assess_ecosystem_risk(self, ecosystem_data: Dict) -> Dict[str, Any]:
        """Assess overall ecosystem risk"""
        # Simplified risk assessment
        return {
            'overall_risk_score': 0.5,
            'systemic_risk_factors': [],
            'cascade_potential': 'medium',
            'mitigation_priority': 'medium'
        }

class EcosystemAnalyzer:
    """Enhanced ecosystem relationship analyzer"""
    
    def __init__(self, web3: Web3):
        self.web3 = web3

class EconomicImpactAssessor:
    """Economic impact assessment engine"""
    
    def __init__(self, web3: Web3):
        self.web3 = web3
    
    async def assess_impact(self, target: str, vulnerabilities: List, ecosystem_data: Dict) -> Dict:
        """Assess economic impact"""
        return {'total_potential_loss': 0.0, 'exploit_feasibility': 0.0}

class ExploitationPathPlanner:
    """Exploitation path planning engine"""
    
    def __init__(self, web3: Web3):
        self.web3 = web3
    
    async def plan_exploitation(self, target: str, vulnerability: VulnerabilityFinding) -> Dict:
        """Plan exploitation path for vulnerability"""
        return {'feasibility_score': 0.0, 'steps': [], 'complexity': 'high'}