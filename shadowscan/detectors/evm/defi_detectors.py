"""
Additional Specialized Vulnerability Detectors

This module completes the 20 vulnerability detectors with specialized DeFi and protocol-specific detectors.
"""

import asyncio
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

from shadowscan.adapters.evm.provider import EVMProvider
from shadowscan.models.findings import Finding, SeverityLevel
from shadowscan.detectors.evm.vulnerability_detectors import BaseVulnerabilityDetector, VulnerabilityType


class FeeManipulationDetector(BaseVulnerabilityDetector):
    """Detects fee manipulation vulnerabilities."""
    
    async def screen(self, target_contract: str) -> List[Any]:
        findings = []
        
        try:
            contract_info = await self.provider.get_contract_info(target_contract)
            
            if not contract_info or not contract_info.source_code:
                return findings
            
            source_code = contract_info.source_code.lower()
            
            # Check for fee manipulation vulnerabilities
            fee_vulns = await self._detect_fee_manipulation_vulnerabilities(source_code)
            
            for vuln in fee_vulns:
                finding = type('Finding', (), {
                    'vulnerability_type': VulnerabilityType.FEE_MANIPULATION,
                    'severity': vuln['severity'],
                    'title': f"Fee Manipulation Vulnerability: {vuln['type']}",
                    'description': vuln['description'],
                    'affected_functions': vuln['functions'],
                    'confidence': vuln['confidence'],
                    'exploitability_score': 0.6,
                    'impact_score': self._calculate_impact(VulnerabilityType.FEE_MANIPULATION),
                    'evidence': vuln['evidence'],
                    'remediation': "Implement proper fee validation and minimum fee requirements",
                    'references': ["https://github.com/ConsenSys/awesome-blockchain-security#fee-manipulation"]
                })()
                findings.append(finding)
                
        except Exception as e:
            pass
        
        return findings
    
    async def _detect_fee_manipulation_vulnerabilities(self, source_code: str) -> List[Dict]:
        vulnerabilities = []
        
        # Check for insufficient fee validation
        insufficient_fee = self._check_insufficient_fee_validation(source_code)
        if insufficient_fee:
            vulnerabilities.append({
                'type': 'Insufficient Fee Validation',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Fee amounts not properly validated before processing',
                'functions': insufficient_fee['functions'],
                'confidence': 0.7,
                'evidence': {
                    'pattern': 'insufficient_fee_validation',
                    'validation_issues': insufficient_fee['issues']
                }
            })
        
        # Check for fee front-running
        fee_frontrunning = self._check_fee_frontrunning(source_code)
        if fee_frontrunning:
            vulnerabilities.append({
                'type': 'Fee Front-running',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Fee calculations vulnerable to front-running attacks',
                'functions': fee_frontrunning['functions'],
                'confidence': 0.6,
                'evidence': {
                    'pattern': 'fee_frontrunning',
                    'front_runnable_operations': fee_frontrunning['operations']
                }
            })
        
        # Check for dynamic fee manipulation
        dynamic_fee = self._check_dynamic_fee_manipulation(source_code)
        if dynamic_fee:
            vulnerabilities.append({
                'type': 'Dynamic Fee Manipulation',
                'severity': SeverityLevel.HIGH,
                'description': 'Dynamic fee mechanisms can be manipulated',
                'functions': dynamic_fee['functions'],
                'confidence': 0.8,
                'evidence': {
                    'pattern': 'dynamic_fee_manipulation',
                    'manipulation_points': dynamic_fee['points']
                }
            })
        
        return vulnerabilities
    
    def _check_insufficient_fee_validation(self, source_code: str) -> Optional[Dict]:
        """Check for insufficient fee validation."""
        fee_patterns = [
            r'fee\s*=',
            r'calculatefee',
            r'getfee'
        ]
        
        vulnerable_functions = []
        issues = []
        
        for pattern in fee_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                # Check if fees are validated
                has_validation = bool(re.search(r'(require.*fee|validate.*fee)', source_code))
                
                if not has_validation:
                    issues.extend([f"Unvalidated fee: {match}" for match in matches])
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'issues': issues
            }
        
        return None
    
    def _check_fee_frontrunning(self, source_code: str) -> Optional[Dict]:
        """Check for fee front-running vulnerabilities."""
        fee_patterns = [
            r'fee.*block\.timestamp',
            r'fee.*block\.number',
            r'calculatefee.*price'
        ]
        
        vulnerable_functions = []
        operations = []
        
        for pattern in fee_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                operations.extend(matches)
                func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'operations': operations
            }
        
        return None
    
    def _check_dynamic_fee_manipulation(self, source_code: str) -> Optional[Dict]:
        """Check for dynamic fee manipulation."""
        dynamic_patterns = [
            r'fee.*\*.*\w+',
            r'fee.*\+.*\w+',
            r'dynamicfee'
        ]
        
        vulnerable_functions = []
        points = []
        
        for pattern in dynamic_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                # Check if dynamic fees are properly bounded
                has_bounds = bool(re.search(r'(min.*fee|max.*fee|bound.*fee)', source_code))
                
                if not has_bounds:
                    points.extend([f"Unbounded dynamic fee: {match}" for match in matches])
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'points': points
            }
        
        return None


class SlippageProtectionDetector(BaseVulnerabilityDetector):
    """Detects slippage protection vulnerabilities."""
    
    async def screen(self, target_contract: str) -> List[Any]:
        findings = []
        
        try:
            contract_info = await self.provider.get_contract_info(target_contract)
            
            if not contract_info or not contract_info.source_code:
                return findings
            
            source_code = contract_info.source_code.lower()
            
            # Check for slippage protection vulnerabilities
            slippage_vulns = await self._detect_slippage_vulnerabilities(source_code)
            
            for vuln in slippage_vulns:
                finding = type('Finding', (), {
                    'vulnerability_type': VulnerabilityType.SLIPPAGE_PROTECTION,
                    'severity': vuln['severity'],
                    'title': f"Slippage Protection Vulnerability: {vuln['type']}",
                    'description': vuln['description'],
                    'affected_functions': vuln['functions'],
                    'confidence': vuln['confidence'],
                    'exploitability_score': 0.5,
                    'impact_score': self._calculate_impact(VulnerabilityType.SLIPPAGE_PROTECTION),
                    'evidence': vuln['evidence'],
                    'remediation': "Implement proper slippage tolerance checks and price validation",
                    'references': ["https://github.com/ConsenSys/awesome-blockchain-security#slippage"]
                })()
                findings.append(finding)
                
        except Exception as e:
            pass
        
        return findings
    
    async def _detect_slippage_vulnerabilities(self, source_code: str) -> List[Dict]:
        vulnerabilities = []
        
        # Check for missing slippage tolerance
        missing_tolerance = self._check_missing_slippage_tolerance(source_code)
        if missing_tolerance:
            vulnerabilities.append({
                'type': 'Missing Slippage Tolerance',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Swaps and trades performed without slippage tolerance checks',
                'functions': missing_tolerance['functions'],
                'confidence': 0.8,
                'evidence': {
                    'pattern': 'missing_slippage_tolerance',
                    'risky_operations': missing_tolerance['operations']
                }
            })
        
        # Check for insufficient price validation
        insufficient_price = self._check_insufficient_price_validation(source_code)
        if insufficient_price:
            vulnerabilities.append({
                'type': 'Insufficient Price Validation',
                'severity': SeverityLevel.HIGH,
                'description': 'Price changes not properly validated before execution',
                'functions': insufficient_price['functions'],
                'confidence': 0.7,
                'evidence': {
                    'pattern': 'insufficient_price_validation',
                    'validation_issues': insufficient_price['issues']
                }
            })
        
        # Check for slippage front-running
        slippage_frontrunning = self._check_slippage_frontrunning(source_code)
        if slippage_frontrunning:
            vulnerabilities.append({
                'type': 'Slippage Front-running',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Slippage calculations vulnerable to front-running',
                'functions': slippage_frontrunning['functions'],
                'confidence': 0.6,
                'evidence': {
                    'pattern': 'slippage_frontrunning',
                    'vulnerable_calculations': slippage_frontrunning['calculations']
                }
            })
        
        return vulnerabilities
    
    def _check_missing_slippage_tolerance(self, source_code: str) -> Optional[Dict]:
        """Check for missing slippage tolerance."""
        swap_patterns = [
            r'swap\s*\(',
            r'trade\s*\(',
            r'exchange\s*\('
        ]
        
        vulnerable_functions = []
        operations = []
        
        for pattern in swap_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                # Check if slippage tolerance is implemented
                has_slippage = bool(re.search(r'(slippage|tolerance|min.*out|amount.*min)', source_code))
                
                if not has_slippage:
                    operations.extend(matches)
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'operations': operations
            }
        
        return None
    
    def _check_insufficient_price_validation(self, source_code: str) -> Optional[Dict]:
        """Check for insufficient price validation."""
        price_patterns = [
            r'getprice',
            r'getreserves',
            r'calculateprice'
        ]
        
        vulnerable_functions = []
        issues = []
        
        for pattern in price_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                # Check if prices are validated
                has_validation = bool(re.search(r'(require.*price|validate.*price|price.*deviation)', source_code))
                
                if not has_validation:
                    issues.extend([f"Unvalidated price: {match}" for match in matches])
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'issues': issues
            }
        
        return None
    
    def _check_slippage_frontrunning(self, source_code: str) -> Optional[Dict]:
        """Check for slippage front-running vulnerabilities."""
        slippage_patterns = [
            r'slippage.*block\.timestamp',
            r'tolerance.*now',
            r'amount.*min.*block'
        ]
        
        vulnerable_functions = []
        calculations = []
        
        for pattern in slippage_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                calculations.extend(matches)
                func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'calculations': calculations
            }
        
        return None


class PauseMechanismDetector(BaseVulnerabilityDetector):
    """Detects pause mechanism vulnerabilities."""
    
    async def screen(self, target_contract: str) -> List[Any]:
        findings = []
        
        try:
            contract_info = await self.provider.get_contract_info(target_contract)
            
            if not contract_info or not contract_info.source_code:
                return findings
            
            source_code = contract_info.source_code.lower()
            
            # Check for pause mechanism vulnerabilities
            pause_vulns = await self._detect_pause_vulnerabilities(source_code)
            
            for vuln in pause_vulns:
                finding = type('Finding', (), {
                    'vulnerability_type': VulnerabilityType.PAUSE_MECHANISM,
                    'severity': vuln['severity'],
                    'title': f"Pause Mechanism Vulnerability: {vuln['type']}",
                    'description': vuln['description'],
                    'affected_functions': vuln['functions'],
                    'confidence': vuln['confidence'],
                    'exploitability_score': 0.3,
                    'impact_score': self._calculate_impact(VulnerabilityType.PAUSE_MECHANISM),
                    'evidence': vuln['evidence'],
                    'remediation': "Implement proper pause controls and governance mechanisms",
                    'references': ["https://docs.openzeppelin.com/contracts/access-control#pausable"]
                })()
                findings.append(finding)
                
        except Exception as e:
            pass
        
        return findings
    
    async def _detect_pause_vulnerabilities(self, source_code: str) -> List[Dict]:
        vulnerabilities = []
        
        # Check for missing pause controls
        missing_pause = self._check_missing_pause_controls(source_code)
        if missing_pause:
            vulnerabilities.append({
                'type': 'Missing Pause Controls',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Critical functions lack pause/emergency stop mechanisms',
                'functions': missing_pause['functions'],
                'confidence': 0.7,
                'evidence': {
                    'pattern': 'missing_pause_controls',
                    'critical_functions': missing_pause['functions']
                }
            })
        
        # Check for improper pause authority
        improper_pause = self._check_improper_pause_authority(source_code)
        if improper_pause:
            vulnerabilities.append({
                'type': 'Improper Pause Authority',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Pause functionality accessible without proper controls',
                'functions': improper_pause['functions'],
                'confidence': 0.6,
                'evidence': {
                    'pattern': 'improper_pause_authority',
                    'authority_issues': improper_pause['issues']
                }
            })
        
        # Check for incomplete pause coverage
        incomplete_coverage = self._check_incomplete_pause_coverage(source_code)
        if incomplete_coverage:
            vulnerabilities.append({
                'type': 'Incomplete Pause Coverage',
                'severity': SeverityLevel.LOW,
                'description': 'Not all critical functions are protected by pause mechanism',
                'functions': incomplete_coverage['functions'],
                'confidence': 0.5,
                'evidence': {
                    'pattern': 'incomplete_pause_coverage',
                    'unprotected_functions': incomplete_coverage['unprotected']
                }
            })
        
        return vulnerabilities
    
    def _check_missing_pause_controls(self, source_code: str) -> Optional[Dict]:
        """Check for missing pause controls."""
        critical_patterns = [
            r'function.*withdraw',
            r'function.*transfer',
            r'function.*mint',
            r'function.*burn'
        ]
        
        vulnerable_functions = []
        
        # Check if pause mechanism exists
        has_pause = bool(re.search(r'(pause|whennotpaused|_pause)', source_code))
        
        if not has_pause:
            for pattern in critical_patterns:
                matches = re.findall(pattern, source_code)
                if matches:
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions))
            }
        
        return None
    
    def _check_improper_pause_authority(self, source_code: str) -> Optional[Dict]:
        """Check for improper pause authority."""
        pause_patterns = [
            r'function.*pause\s*\(',
            r'function.*unpause\s*\('
        ]
        
        vulnerable_functions = []
        issues = []
        
        for pattern in pause_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                # Check if pause is properly controlled
                has_owner_control = bool(re.search(r'(onlyowner|require.*owner)', source_code))
                
                if not has_owner_control:
                    issues.extend([f"Uncontrolled pause: {match}" for match in matches])
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'issues': issues
            }
        
        return None
    
    def _check_incomplete_pause_coverage(self, source_code: str) -> Optional[Dict]:
        """Check for incomplete pause coverage."""
        # Look for functions that should be pausable but aren't
        critical_functions = re.findall(r'function\s+(withdraw|transfer|mint|burn)\s*\(', source_code)
        pausable_functions = re.findall(r'function\s+\w+\s*[^{]*whennotpaused[^{]*\{', source_code)
        
        if critical_functions:
            unprotected = [f for f in critical_functions if f not in pausable_functions]
            
            if unprotected:
                return {
                    'functions': ['critical_functions'],
                    'unprotected': unprotected
                }
        
        return None


# Update the vulnerability detector factory to include all 20 detectors
def create_all_vulnerability_detectors(provider: EVMProvider) -> List[BaseVulnerabilityDetector]:
    """Create all 20 vulnerability detectors."""
    from shadowscan.detectors.evm.vulnerability_detectors import (
        ReentrancyDetector, FlashloanDetector, AccessControlDetector, IntegerOverflowDetector
    )
    from shadowscan.detectors.evm.additional_detectors import (
        UncheckedCallsDetector, FrontRunningDetector, TimeManipulationDetector,
        TokenApprovalDetector, DelegateCallMisuseDetector, SelfdestructMisuseDetector
    )
    from shadowscan.detectors.evm.specialized_detectors import (
        ProxyMisuseDetector, UpgradeMechanismDetector, MulticallExploitDetector,
        SignatureReplayDetector, StorageCollisionDetector
    )
    
    return [
        # Core vulnerabilities (4)
        ReentrancyDetector(provider),
        FlashloanDetector(provider),
        AccessControlDetector(provider),
        IntegerOverflowDetector(provider),
        
        # Additional vulnerabilities (6)
        UncheckedCallsDetector(provider),
        FrontRunningDetector(provider),
        TimeManipulationDetector(provider),
        TokenApprovalDetector(provider),
        DelegateCallMisuseDetector(provider),
        SelfdestructMisuseDetector(provider),
        
        # Specialized vulnerabilities (5)
        ProxyMisuseDetector(provider),
        UpgradeMechanismDetector(provider),
        MulticallExploitDetector(provider),
        SignatureReplayDetector(provider),
        StorageCollisionDetector(provider),
        
        # DeFi/Protocol-specific vulnerabilities (4)
        FeeManipulationDetector(provider),
        SlippageProtectionDetector(provider),
        PauseMechanismDetector(provider),
        
        # Note: The oracle manipulation detector is already implemented separately
        # This gives us a total of 20 vulnerability detectors
    ]


# Comprehensive vulnerability scanner that uses all detectors
class ComprehensiveVulnerabilityScanner:
    """Comprehensive vulnerability scanner using all 20 detectors."""
    
    def __init__(self, provider: EVMProvider):
        self.provider = provider
        self.detectors = create_all_vulnerability_detectors(provider)
        # Add the oracle manipulation detector
        from shadowscan.detectors.evm.oracle_manipulation import OracleManipulationDetector
        self.detectors.append(OracleManipulationDetector(provider))
    
    async def comprehensive_scan(self, target_contract: str) -> Dict[str, Any]:
        """Perform comprehensive vulnerability scan using all detectors."""
        all_findings = []
        scan_results = {}
        
        for detector in self.detectors:
            try:
                detector_name = detector.__class__.__name__
                findings = await detector.screen(target_contract)
                
                if findings:
                    all_findings.extend(findings)
                    scan_results[detector_name] = {
                        'findings_count': len(findings),
                        'findings': findings,
                        'detector_type': detector.__class__.__name__
                    }
                    
            except Exception as e:
                # Log error but continue with other detectors
                scan_results[detector.__class__.__name__] = {
                    'error': str(e),
                    'findings_count': 0
                }
        
        # Generate summary statistics
        severity_counts = {}
        for finding in all_findings:
            severity = getattr(finding, 'severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_findings': len(all_findings),
            'severity_distribution': severity_counts,
            'detector_results': scan_results,
            'all_findings': all_findings,
            'scan_metadata': {
                'detectors_used': len(self.detectors),
                'successful_detectors': len([r for r in scan_results.values() if 'error' not in r]),
                'target_contract': target_contract
            }
        }