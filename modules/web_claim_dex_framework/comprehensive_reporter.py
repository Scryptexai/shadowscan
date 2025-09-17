#!/usr/bin/env python3
"""
Comprehensive Reporting System
Advanced reporting and visualization for multi-layer security analysis
"""

import json
import asyncio
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
import logging
from pathlib import Path
import os
from datetime import datetime
import csv
import xml.etree.ElementTree as ET

# Import the analysis modules
from web_application_tester import WebApplicationTester, test_web_application
from api_endpoint_tester import APIEndpointTester, test_api_endpoints
from smart_contract_analyzer import SmartContractAnalyzer, analyze_contracts_from_website
from blockchain_exploit_tester import BlockchainExploitTester, test_blockchain_exploits

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class AnalysisReport:
    target_url: str
    timestamp: datetime
    analysis_duration: float
    web_analysis: Dict[str, Any]
    api_analysis: Dict[str, Any]
    contract_analysis: Dict[str, Any]
    blockchain_analysis: Dict[str, Any]
    overall_security_score: int
    vulnerability_summary: Dict[str, Any]
    recommendations: List[str]
    executive_summary: str

class ComprehensiveReportingSystem:
    def __init__(self):
        self.reports_directory = Path("reports")
        self.reports_directory.mkdir(exist_ok=True)
        
        # Severity colors for console output
        self.severity_colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',     # Yellow
            'MEDIUM': '\033[96m',   # Cyan
            'LOW': '\033[92m',      # Green
            'INFO': '\033[94m',     # Blue
            'RESET': '\033[0m'      # Reset
        }
        
        # Risk assessment matrix
        self.risk_matrix = {
            'web_application': {
                'weight': 0.2,
                'factors': ['xss', 'sql_injection', 'csrf', 'security_headers']
            },
            'api_endpoints': {
                'weight': 0.25,
                'factors': ['broken_auth', 'rate_limiting', 'cors', 'business_logic']
            },
            'smart_contracts': {
                'weight': 0.3,
                'factors': ['access_control', 'reentrancy', 'overflow', 'gas_optimization']
            },
            'blockchain_exploits': {
                'weight': 0.25,
                'factors': ['exploit_success', 'critical_vulns', 'function_vulnerabilities']
            }
        }

    async def generate_comprehensive_report(self, target_url: str, network: str = 'bsc') -> AnalysisReport:
        logger.info(f"📊 Starting comprehensive security analysis for: {target_url}")
        
        start_time = time.time()
        
        # Layer 1: Web Application Analysis
        logger.info("🌐 Analyzing web application layer...")
        web_analysis = await test_web_application(target_url)
        
        # Layer 2: API Endpoint Analysis
        logger.info("🔗 Analyzing API endpoints...")
        api_analysis = await test_api_endpoints(target_url, web_analysis)
        
        # Layer 3: Smart Contract Analysis
        logger.info("🔍 Analyzing smart contracts...")
        contract_analysis = await analyze_contracts_from_website(target_url, network)
        
        # Layer 4: Blockchain Exploit Analysis
        logger.info("🔐 Testing blockchain exploits...")
        # Extract contract addresses from web analysis
        contract_addresses = self._extract_contract_addresses(web_analysis)
        blockchain_analysis = {}
        
        if contract_addresses:
            for address in contract_addresses[:3]:  # Limit to first 3 contracts
                try:
                    blockchain_analysis[address] = await test_blockchain_exploits(address, network)
                except Exception as e:
                    logger.error(f"Error analyzing contract {address}: {e}")
        
        # Layer 5: Comprehensive Analysis
        overall_security_score = self._calculate_overall_security_score(
            web_analysis, api_analysis, contract_analysis, blockchain_analysis
        )
        
        # Layer 6: Vulnerability Summary
        vulnerability_summary = self._create_vulnerability_summary(
            web_analysis, api_analysis, contract_analysis, blockchain_analysis
        )
        
        # Layer 7: Recommendations
        recommendations = self._generate_comprehensive_recommendations(
            web_analysis, api_analysis, contract_analysis, blockchain_analysis
        )
        
        # Layer 8: Executive Summary
        executive_summary = self._generate_executive_summary(
            target_url, overall_security_score, vulnerability_summary, recommendations
        )
        
        analysis_duration = time.time() - start_time
        
        return AnalysisReport(
            target_url=target_url,
            timestamp=datetime.now(),
            analysis_duration=analysis_duration,
            web_analysis=web_analysis,
            api_analysis=api_analysis,
            contract_analysis=contract_analysis,
            blockchain_analysis=blockchain_analysis,
            overall_security_score=overall_security_score,
            vulnerability_summary=vulnerability_summary,
            recommendations=recommendations,
            executive_summary=executive_summary
        )

    def _extract_contract_addresses(self, web_analysis: Dict[str, Any]) -> List[str]:
        addresses = []
        
        try:
            # Extract from content
            content = web_analysis.get('technology_stack', {}).get('content', '')
            
            # Look for Ethereum addresses in content
            import re
            address_pattern = r'0x[a-fA-F0-9]{40}'
            addresses.extend(re.findall(address_pattern, content))
            
            # Extract from API endpoints
            api_endpoints = web_analysis.get('api_endpoints', [])
            for endpoint in api_endpoints:
                addresses.extend(re.findall(address_pattern, endpoint))
            
            # Remove duplicates and validate
            unique_addresses = []
            for addr in addresses:
                if len(addr) == 42 and addr.startswith('0x'):
                    unique_addresses.append(addr)
            
            return list(set(unique_addresses))
            
        except Exception as e:
            logger.error(f"Error extracting contract addresses: {e}")
            return []

    def _calculate_overall_security_score(self, *analyses) -> int:
        scores = []
        weights = []
        
        for i, analysis in enumerate(analyses):
            if analysis and 'analysis_summary' in analysis:
                score = analysis['analysis_summary'].get('security_score', 50)
                scores.append(score)
                weights.append(0.25)  # Equal weight for each layer
            elif analysis and isinstance(analysis, dict):
                # Handle blockchain analysis which is per-contract
                for contract_addr, contract_analysis in analysis.items():
                    if 'security_metrics' in contract_analysis:
                        score = contract_analysis['security_metrics'].get('security_score', 50)
                        scores.append(score)
                        weights.append(0.25)
        
        if not scores:
            return 50
        
        # Calculate weighted average
        weighted_sum = sum(score * weight for score, weight in zip(scores, weights))
        total_weight = sum(weights)
        
        return int(weighted_sum / total_weight) if total_weight > 0 else 50

    def _create_vulnerability_summary(self, *analyses) -> Dict[str, Any]:
        summary = {
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'low_vulnerabilities': 0,
            'by_category': {},
            'by_severity': {
                'CRITICAL': [],
                'HIGH': [],
                'MEDIUM': [],
                'LOW': []
            }
        }
        
        category_names = ['web_application', 'api_endpoints', 'smart_contracts', 'blockchain_exploits']
        
        for i, analysis in enumerate(analyses):
            if not analysis:
                continue
                
            category = category_names[i]
            summary['by_category'][category] = {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
            
            if 'vulnerabilities' in analysis:
                vulns = analysis['vulnerabilities']
                summary['by_category'][category]['total'] = len(vulns)
                
                for vuln in vulns:
                    severity = vuln.get('severity', 'LOW').upper()
                    if severity in summary['by_severity']:
                        summary['by_severity'][severity].append({
                            'category': category,
                            'type': vuln.get('type', 'Unknown'),
                            'description': vuln.get('description', 'No description')
                        })
                        
                        if severity == 'CRITICAL':
                            summary['by_category'][category]['critical'] += 1
                            summary['critical_vulnerabilities'] += 1
                        elif severity == 'HIGH':
                            summary['by_category'][category]['high'] += 1
                            summary['high_vulnerabilities'] += 1
                        elif severity == 'MEDIUM':
                            summary['by_category'][category]['medium'] += 1
                            summary['medium_vulnerabilities'] += 1
                        else:
                            summary['by_category'][category]['low'] += 1
                            summary['low_vulnerabilities'] += 1
            
            # Handle blockchain analysis (per-contract)
            elif isinstance(analysis, dict):
                for contract_addr, contract_analysis in analysis.items():
                    if 'exploits_attempted' in contract_analysis:
                        exploits = contract_analysis['exploits_attempted']
                        summary['by_category']['blockchain_exploits']['total'] += len(exploits)
                        
                        for exploit in exploits:
                            if exploit.get('success', False):
                                severity = exploit.get('severity', 'LOW').upper()
                                if severity in summary['by_severity']:
                                    summary['by_severity'][severity].append({
                                        'category': 'blockchain_exploits',
                                        'type': exploit.get('exploit_type', 'Unknown'),
                                        'description': exploit.get('description', 'No description')
                                    })
                                    
                                    if severity == 'CRITICAL':
                                        summary['by_category']['blockchain_exploits']['critical'] += 1
                                        summary['critical_vulnerabilities'] += 1
                                    elif severity == 'HIGH':
                                        summary['by_category']['blockchain_exploits']['high'] += 1
                                        summary['high_vulnerabilities'] += 1
                                    elif severity == 'MEDIUM':
                                        summary['by_category']['blockchain_exploits']['medium'] += 1
                                        summary['medium_vulnerabilities'] += 1
                                    else:
                                        summary['by_category']['blockchain_exploits']['low'] += 1
                                        summary['low_vulnerabilities'] += 1
        
        summary['total_vulnerabilities'] = (
            summary['critical_vulnerabilities'] +
            summary['high_vulnerabilities'] +
            summary['medium_vulnerabilities'] +
            summary['low_vulnerabilities']
        )
        
        return summary

    def _generate_comprehensive_recommendations(self, *analyses) -> List[str]:
        all_recommendations = []
        
        category_names = ['web_application', 'api_endpoints', 'smart_contracts', 'blockchain_exploits']
        
        for i, analysis in enumerate(analyses):
            if not analysis:
                continue
                
            category = category_names[i]
            
            if 'recommendations' in analysis:
                for rec in analysis['recommendations']:
                    all_recommendations.append(f"[{category.upper()}] {rec}")
            
            # Handle blockchain analysis
            elif isinstance(analysis, dict):
                for contract_addr, contract_analysis in analysis.items():
                    if 'recommendations' in contract_analysis:
                        for rec in contract_analysis['recommendations']:
                            all_recommendations.append(f"[BLOCKCHAIN] {rec}")
        
        # Add general recommendations
        all_recommendations.extend([
            "[GENERAL] Implement continuous security monitoring",
            "[GENERAL] Conduct regular security audits",
            "[GENERAL] Use established security frameworks and standards",
            "[GENERAL] Implement proper logging and monitoring",
            "[GENERAL] Have an incident response plan in place"
        ])
        
        return list(set(all_recommendations))  # Remove duplicates

    def _generate_executive_summary(self, target_url: str, security_score: int, vulnerability_summary: Dict[str, Any], recommendations: List[str]) -> str:
        risk_level = "LOW"
        if security_score < 30:
            risk_level = "CRITICAL"
        elif security_score < 50:
            risk_level = "HIGH"
        elif security_score < 70:
            risk_level = "MEDIUM"
        
        total_vulns = vulnerability_summary['total_vulnerabilities']
        critical_vulns = vulnerability_summary['critical_vulnerabilities']
        
        summary = f"""
🎯 EXECUTIVE SUMMARY - SECURITY ANALYSIS REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 ANALYSIS OVERVIEW:
├── Target URL: {target_url}
├── Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
├── Overall Security Score: {security_score}/100
├── Risk Level: {risk_level}
├── Total Vulnerabilities: {total_vulns}
└── Critical Vulnerabilities: {critical_vulns}

🛡️ SECURITY ASSESSMENT:
"""
        
        if security_score >= 80:
            summary += "✅ GOOD - The target demonstrates strong security practices with minimal vulnerabilities.\n"
        elif security_score >= 60:
            summary += "⚠️  MODERATE - The target has some security issues that should be addressed.\n"
        elif security_score >= 40:
            summary += "🔴 POOR - The target has significant security vulnerabilities requiring immediate attention.\n"
        else:
            summary += "🚨 CRITICAL - The target has severe security vulnerabilities that pose immediate risks.\n"
        
        summary += f"""
📋 KEY FINDINGS:
• Total vulnerabilities discovered: {total_vulns}
• Critical issues requiring immediate action: {critical_vulns}
• Overall security posture: {'Strong' if security_score >= 80 else 'Moderate' if security_score >= 60 else 'Weak'}
• Multi-layer defense effectiveness: {'Robust' if security_score >= 70 else 'Adequate' if security_score >= 50 else 'Insufficient'}

🎯 RECOMMENDATIONS:
• {len(recommendations)} total recommendations provided
• Prioritize addressing critical vulnerabilities first
• Implement continuous security monitoring
• Consider professional security audit for complex issues

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        
        return summary

    def generate_json_report(self, report: AnalysisReport) -> str:
        """Generate JSON format report"""
        json_report = {
            'report_metadata': {
                'target_url': report.target_url,
                'timestamp': report.timestamp.isoformat(),
                'analysis_duration': report.analysis_duration,
                'overall_security_score': report.overall_security_score,
                'risk_level': self._get_risk_level(report.overall_security_score)
            },
            'executive_summary': report.executive_summary,
            'vulnerability_summary': report.vulnerability_summary,
            'detailed_analysis': {
                'web_application': report.web_analysis,
                'api_endpoints': report.api_analysis,
                'smart_contracts': report.contract_analysis,
                'blockchain_exploits': report.blockchain_analysis
            },
            'recommendations': report.recommendations,
            'security_metrics': {
                'overall_score': report.overall_security_score,
                'vulnerability_count': report.vulnerability_summary['total_vulnerabilities'],
                'critical_vulnerabilities': report.vulnerability_summary['critical_vulnerabilities'],
                'high_vulnerabilities': report.vulnerability_summary['high_vulnerabilities'],
                'medium_vulnerabilities': report.vulnerability_summary['medium_vulnerabilities'],
                'low_vulnerabilities': report.vulnerability_summary['low_vulnerabilities']
            }
        }
        
        return json.dumps(json_report, indent=2, ensure_ascii=False)

    def generate_html_report(self, report: AnalysisReport) -> str:
        """Generate HTML format report"""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report - {report.target_url}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .score-section {{
            display: flex;
            justify-content: space-around;
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }}
        .score-card {{
            text-align: center;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            min-width: 150px;
        }}
        .score-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .score-label {{
            color: #666;
            font-size: 0.9em;
        }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .good {{ color: #28a745; }}
        .warning {{ color: #ffc107; }}
        .danger {{ color: #dc3545; }}
        .content {{
            padding: 30px;
        }}
        .section {{
            margin-bottom: 30px;
            padding: 20px;
            border: 1px solid #dee2e6;
            border-radius: 8px;
        }}
        .section h2 {{
            color: #495057;
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
        }}
        .vulnerability-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .vuln-card {{
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            background: #f8f9fa;
        }}
        .vuln-type {{
            font-weight: bold;
            color: #495057;
        }}
        .vuln-severity {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
            margin-left: 10px;
        }}
        .severity-critical {{ background: #dc3545; }}
        .severity-high {{ background: #fd7e14; }}
        .severity-medium {{ background: #ffc107; color: #333; }}
        .severity-low {{ background: #28a745; }}
        .recommendations {{
            background: #e7f3ff;
            border-left: 4px solid #007bff;
        }}
        .recommendations ul {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        .executive-summary {{
            background: #f8f9fa;
            border-left: 4px solid #007bff;
            white-space: pre-line;
            font-family: monospace;
        }}
        .analysis-tabs {{
            display: flex;
            border-bottom: 1px solid #dee2e6;
            margin-bottom: 20px;
        }}
        .tab {{
            padding: 10px 20px;
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-bottom: none;
            cursor: pointer;
            margin-right: 5px;
        }}
        .tab.active {{
            background: white;
            border-bottom: 1px solid white;
            margin-bottom: -1px;
        }}
        .tab-content {{
            display: none;
        }}
        .tab-content.active {{
            display: block;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Analysis Report</h1>
            <h2>{report.target_url}</h2>
            <p>Generated on {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="score-section">
            <div class="score-card">
                <div class="score-label">Overall Score</div>
                <div class="score-value {self._get_score_class(report.overall_security_score)}">{report.overall_security_score}</div>
                <div class="score-label">out of 100</div>
            </div>
            <div class="score-card">
                <div class="score-label">Risk Level</div>
                <div class="score-value {self._get_risk_class(report.overall_security_score)}">{self._get_risk_level(report.overall_security_score)}</div>
                <div class="score-label">assessment</div>
            </div>
            <div class="score-card">
                <div class="score-label">Total Issues</div>
                <div class="score-value critical">{report.vulnerability_summary['total_vulnerabilities']}</div>
                <div class="score-label">vulnerabilities</div>
            </div>
            <div class="score-card">
                <div class="score-label">Critical Issues</div>
                <div class="score-value critical">{report.vulnerability_summary['critical_vulnerabilities']}</div>
                <div class="score-label">require attention</div>
            </div>
        </div>
        
        <div class="content">
            <div class="section executive-summary">
                <h2>📋 Executive Summary</h2>
                <div>{report.executive_summary}</div>
            </div>
            
            <div class="section">
                <h2>🚨 Vulnerabilities by Severity</h2>
                <div class="vulnerability-grid">
                    <div class="vuln-card">
                        <div class="vuln-type">Critical</div>
                        <div class="vuln-severity severity-critical">{report.vulnerability_summary['critical_vulnerabilities']}</div>
                        <p>Immediate action required</p>
                    </div>
                    <div class="vuln-card">
                        <div class="vuln-type">High</div>
                        <div class="vuln-severity severity-high">{report.vulnerability_summary['high_vulnerabilities']}</div>
                        <p>Address soon</p>
                    </div>
                    <div class="vuln-card">
                        <div class="vuln-type">Medium</div>
                        <div class="vuln-severity severity-medium">{report.vulnerability_summary['medium_vulnerabilities']}</div>
                        <p>Should be fixed</p>
                    </div>
                    <div class="vuln-card">
                        <div class="vuln-type">Low</div>
                        <div class="vuln-severity severity-low">{report.vulnerability_summary['low_vulnerabilities']}</div>
                        <p>Minor issues</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>🎯 Detailed Analysis</h2>
                <div class="analysis-tabs">
                    <div class="tab active" onclick="showTab('web-tab')">Web Application</div>
                    <div class="tab" onclick="showTab('api-tab')">API Endpoints</div>
                    <div class="tab" onclick="showTab('contract-tab')">Smart Contracts</div>
                    <div class="tab" onclick="showTab('blockchain-tab')">Blockchain Exploits</div>
                </div>
                
                <div id="web-tab" class="tab-content active">
                    <h3>🌐 Web Application Analysis</h3>
                    <pre>{json.dumps(report.web_analysis, indent=2)}</pre>
                </div>
                
                <div id="api-tab" class="tab-content">
                    <h3>🔗 API Endpoints Analysis</h3>
                    <pre>{json.dumps(report.api_analysis, indent=2)}</pre>
                </div>
                
                <div id="contract-tab" class="tab-content">
                    <h3>🔍 Smart Contracts Analysis</h3>
                    <pre>{json.dumps(report.contract_analysis, indent=2)}</pre>
                </div>
                
                <div id="blockchain-tab" class="tab-content">
                    <h3>🔐 Blockchain Exploits Analysis</h3>
                    <pre>{json.dumps(report.blockchain_analysis, indent=2)}</pre>
                </div>
            </div>
            
            <div class="section recommendations">
                <h2>💡 Recommendations</h2>
                <ul>
                    {''.join([f'<li>{rec}</li>' for rec in report.recommendations])}
                </ul>
            </div>
        </div>
    </div>
    
    <script>
        function showTab(tabId) {{
            // Hide all tab contents
            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Remove active class from all tabs
            const tabs = document.querySelectorAll('.tab');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Show selected tab content
            document.getElementById(tabId).classList.add('active');
            
            // Add active class to clicked tab
            event.target.classList.add('active');
        }}
    </script>
</body>
</html>
"""
        
        return html_content

    def generate_csv_report(self, report: AnalysisReport) -> str:
        """Generate CSV format report"""
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Category', 'Type', 'Severity', 'Description', 'Target', 'Recommendation'])
        
        # Write web application vulnerabilities
        if 'vulnerabilities' in report.web_analysis:
            for vuln in report.web_analysis['vulnerabilities']:
                writer.writerow([
                    'Web Application',
                    vuln.get('type', 'Unknown'),
                    vuln.get('severity', 'LOW'),
                    vuln.get('description', 'No description'),
                    report.target_url,
                    'See detailed report'
                ])
        
        # Write API vulnerabilities
        if 'vulnerabilities' in report.api_analysis:
            for vuln in report.api_analysis['vulnerabilities']:
                writer.writerow([
                    'API Endpoints',
                    vuln.get('type', 'Unknown'),
                    vuln.get('severity', 'LOW'),
                    vuln.get('description', 'No description'),
                    report.target_url,
                    'See detailed report'
                ])
        
        # Write smart contract vulnerabilities
        if 'contracts' in report.contract_analysis:
            for contract in report.contract_analysis['contracts']:
                for vuln in contract.get('vulnerabilities', []):
                    writer.writerow([
                        'Smart Contract',
                        vuln.get('type', 'Unknown'),
                        vuln.get('severity', 'LOW'),
                        vuln.get('description', 'No description'),
                        contract.get('address', 'Unknown'),
                        vuln.get('recommendation', 'See detailed report')
                    ])
        
        # Write blockchain exploits
        for contract_addr, blockchain_data in report.blockchain_analysis.items():
            if 'exploits_attempted' in blockchain_data:
                for exploit in blockchain_data['exploits_attempted']:
                    if exploit.get('success', False):
                        writer.writerow([
                            'Blockchain Exploit',
                            exploit.get('exploit_type', 'Unknown'),
                            exploit.get('severity', 'LOW'),
                            exploit.get('description', 'No description'),
                            contract_addr,
                            exploit.get('mitigation', 'See detailed report')
                        ])
        
        return output.getvalue()

    def generate_xml_report(self, report: AnalysisReport) -> str:
        """Generate XML format report"""
        root = ET.Element('SecurityAnalysisReport')
        
        # Metadata
        metadata = ET.SubElement(root, 'Metadata')
        ET.SubElement(metadata, 'TargetURL').text = report.target_url
        ET.SubElement(metadata, 'Timestamp').text = report.timestamp.isoformat()
        ET.SubElement(metadata, 'OverallSecurityScore').text = str(report.overall_security_score)
        ET.SubElement(metadata, 'RiskLevel').text = self._get_risk_level(report.overall_security_score)
        
        # Executive Summary
        exec_summary = ET.SubElement(root, 'ExecutiveSummary')
        exec_summary.text = report.executive_summary
        
        # Vulnerability Summary
        vuln_summary = ET.SubElement(root, 'VulnerabilitySummary')
        ET.SubElement(vuln_summary, 'TotalVulnerabilities').text = str(report.vulnerability_summary['total_vulnerabilities'])
        ET.SubElement(vuln_summary, 'CriticalVulnerabilities').text = str(report.vulnerability_summary['critical_vulnerabilities'])
        ET.SubElement(vuln_summary, 'HighVulnerabilities').text = str(report.vulnerability_summary['high_vulnerabilities'])
        ET.SubElement(vuln_summary, 'MediumVulnerabilities').text = str(report.vulnerability_summary['medium_vulnerabilities'])
        ET.SubElement(vuln_summary, 'LowVulnerabilities').text = str(report.vulnerability_summary['low_vulnerabilities'])
        
        # Recommendations
        recommendations = ET.SubElement(root, 'Recommendations')
        for rec in report.recommendations:
            ET.SubElement(recommendations, 'Recommendation').text = rec
        
        # Detailed Analysis
        detailed = ET.SubElement(root, 'DetailedAnalysis')
        
        # Web Application Analysis
        web_analysis = ET.SubElement(detailed, 'WebApplicationAnalysis')
        web_analysis.text = json.dumps(report.web_analysis)
        
        # API Analysis
        api_analysis = ET.SubElement(detailed, 'APIAnalysis')
        api_analysis.text = json.dumps(report.api_analysis)
        
        # Contract Analysis
        contract_analysis = ET.SubElement(detailed, 'SmartContractAnalysis')
        contract_analysis.text = json.dumps(report.contract_analysis)
        
        # Blockchain Analysis
        blockchain_analysis = ET.SubElement(detailed, 'BlockchainAnalysis')
        blockchain_analysis.text = json.dumps(report.blockchain_analysis)
        
        return ET.tostring(root, encoding='unicode')

    def _get_risk_level(self, score: int) -> str:
        if score >= 80:
            return "LOW"
        elif score >= 60:
            return "MEDIUM"
        elif score >= 40:
            return "HIGH"
        else:
            return "CRITICAL"

    def _get_score_class(self, score: int) -> str:
        if score >= 80:
            return "good"
        elif score >= 60:
            return "warning"
        else:
            return "danger"

    def _get_risk_class(self, score: int) -> str:
        if score >= 80:
            return "good"
        elif score >= 60:
            return "warning"
        else:
            return "danger"

    def print_console_report(self, report: AnalysisReport):
        """Print colored console report"""
        print("\n" + "="*80)
        print(f"🛡️  SECURITY ANALYSIS REPORT - {report.target_url}")
        print("="*80)
        
        # Executive Summary
        print(f"\n📋 EXECUTIVE SUMMARY")
        print(f"   Target URL: {report.target_url}")
        print(f"   Analysis Date: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   Duration: {report.analysis_duration:.2f} seconds")
        print(f"   Overall Security Score: {report.overall_security_score}/100")
        print(f"   Risk Level: {self._get_risk_level(report.overall_security_score)}")
        
        # Score visualization
        score_color = self.severity_colors['RESET']
        if report.overall_security_score >= 80:
            score_color = self.severity_colors['LOW']
        elif report.overall_security_score >= 60:
            score_color = self.severity_colors['MEDIUM']
        else:
            score_color = self.severity_colors['CRITICAL']
        
        print(f"   Security Score: {score_color}{report.overall_security_score}/100{self.severity_colors['RESET']}")
        
        # Vulnerability Summary
        print(f"\n🚨 VULNERABILITY SUMMARY")
        print(f"   Total Vulnerabilities: {report.vulnerability_summary['total_vulnerabilities']}")
        print(f"   Critical: {self.severity_colors['CRITICAL']}{report.vulnerability_summary['critical_vulnerabilities']}{self.severity_colors['RESET']}")
        print(f"   High: {self.severity_colors['HIGH']}{report.vulnerability_summary['high_vulnerabilities']}{self.severity_colors['RESET']}")
        print(f"   Medium: {self.severity_colors['MEDIUM']}{report.vulnerability_summary['medium_vulnerabilities']}{self.severity_colors['RESET']}")
        print(f"   Low: {self.severity_colors['LOW']}{report.vulnerability_summary['low_vulnerabilities']}{self.severity_colors['RESET']}")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS")
        for i, rec in enumerate(report.recommendations[:10], 1):
            print(f"   {i}. {rec}")
        
        if len(report.recommendations) > 10:
            print(f"   ... and {len(report.recommendations) - 10} more recommendations")
        
        print("\n" + "="*80)

    async def save_report(self, report: AnalysisReport, formats: List[str] = None) -> Dict[str, str]:
        """Save report in multiple formats"""
        if formats is None:
            formats = ['json', 'html', 'csv', 'xml']
        
        timestamp = report.timestamp.strftime('%Y%m%d_%H%M%S')
        base_filename = f"security_analysis_{timestamp}"
        saved_files = {}
        
        for format_type in formats:
            try:
                if format_type == 'json':
                    content = self.generate_json_report(report)
                    filename = f"{base_filename}.json"
                elif format_type == 'html':
                    content = self.generate_html_report(report)
                    filename = f"{base_filename}.html"
                elif format_type == 'csv':
                    content = self.generate_csv_report(report)
                    filename = f"{base_filename}.csv"
                elif format_type == 'xml':
                    content = self.generate_xml_report(report)
                    filename = f"{base_filename}.xml"
                else:
                    continue
                
                filepath = self.reports_directory / filename
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                saved_files[format_type] = str(filepath)
                logger.info(f"Report saved as {filename}")
                
            except Exception as e:
                logger.error(f"Error saving {format_type} report: {e}")
        
        return saved_files

async def generate_comprehensive_analysis(target_url: str, network: str = 'bsc', formats: List[str] = None) -> Dict[str, Any]:
    """
    Generate comprehensive security analysis with multiple output formats
    """
    reporter = ComprehensiveReportingSystem()
    
    # Generate comprehensive report
    report = await reporter.generate_comprehensive_report(target_url, network)
    
    # Print console report
    reporter.print_console_report(report)
    
    # Save reports in specified formats
    saved_files = await reporter.save_report(report, formats)
    
    return {
        'report': report,
        'saved_files': saved_files,
        'summary': {
            'target_url': target_url,
            'security_score': report.overall_security_score,
            'total_vulnerabilities': report.vulnerability_summary['total_vulnerabilities'],
            'critical_vulnerabilities': report.vulnerability_summary['critical_vulnerabilities'],
            'risk_level': reporter._get_risk_level(report.overall_security_score)
        }
    }

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        network = sys.argv[2] if len(sys.argv) > 2 else 'bsc'
        formats = sys.argv[3:] if len(sys.argv) > 3 else ['json', 'html']
        
        async def run_analysis():
            result = await generate_comprehensive_analysis(target_url, network, formats)
            print(f"\n✅ Analysis complete!")
            print(f"📊 Security Score: {result['summary']['security_score']}/100")
            print(f"🚨 Total Vulnerabilities: {result['summary']['total_vulnerabilities']}")
            print(f"📁 Reports saved:")
            for format_type, filepath in result['saved_files'].items():
                print(f"   {format_type.upper()}: {filepath}")
        
        asyncio.run(run_analysis())
    else:
        print("Usage: python comprehensive_reporter.py <target_url> [network] [formats...]")
        print("Example: python comprehensive_reporter.py https://example.com bsc json html csv")