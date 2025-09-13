"""
Additional EVM Vulnerability Detectors

This module extends the vulnerability detection with more specialized detectors
for advanced attack vectors and security issues.
"""

import asyncio
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

from shadowscan.adapters.evm.provider import EVMProvider
from shadowscan.models.findings import Finding, SeverityLevel
from shadowscan.detectors.evm.vulnerability_detectors import BaseVulnerabilityDetector, VulnerabilityType


class UncheckedCallsDetector(BaseVulnerabilityDetector):
    """Detects unchecked external call vulnerabilities."""
    
    async def screen(self, target_contract: str) -> List[Any]:
        findings = []
        
        try:
            contract_info = await self.provider.get_contract_info(target_contract)
            
            if not contract_info or not contract_info.source_code:
                return findings
            
            source_code = contract_info.source_code.lower()
            
            # Check for unchecked external calls
            unchecked_vulns = await self._detect_unchecked_calls(source_code)
            
            for vuln in unchecked_vulns:
                finding = type('Finding', (), {
                    'vulnerability_type': VulnerabilityType.UNCHECKED_CALLS,
                    'severity': vuln['severity'],
                    'title': f"Unchecked External Call: {vuln['type']}",
                    'description': vuln['description'],
                    'affected_functions': vuln['functions'],
                    'confidence': vuln['confidence'],
                    'exploitability_score': 0.6,
                    'impact_score': self._calculate_impact(VulnerabilityType.UNCHECKED_CALLS),
                    'evidence': vuln['evidence'],
                    'remediation': "Always check return values of external calls or use low-level calls with proper error handling",
                    'references': ["https://consensys.github.io/smart-contract-best-practices/security-guidelines/external-calls/"]
                })()
                findings.append(finding)
                
        except Exception as e:
            pass
        
        return findings
    
    async def _detect_unchecked_calls(self, source_code: str) -> List[Dict]:
        vulnerabilities = []
        
        # Check for .call() without return value check
        unchecked_call_pattern = r'\.call\([^)]*\)(?!\s*&&|\s*\|\|)'
        unchecked_calls = re.findall(unchecked_call_pattern, source_code)
        
        if unchecked_calls:
            functions = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + unchecked_call_pattern, source_code)
            vulnerabilities.append({
                'type': 'Unchecked .call()',
                'severity': SeverityLevel.MEDIUM,
                'description': 'External .call() without return value validation',
                'functions': list(set(functions)),
                'confidence': 0.7,
                'evidence': {
                    'pattern': 'unchecked_call',
                    'call_count': len(unchecked_calls)
                }
            })
        
        # Check for .send() without return value check
        unchecked_send_pattern = r'\.send\([^)]*\)(?!\s*&&|\s*\|\|)'
        unchecked_sends = re.findall(unchecked_send_pattern, source_code)
        
        if unchecked_sends:
            functions = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + unchecked_send_pattern, source_code)
            vulnerabilities.append({
                'type': 'Unchecked .send()',
                'severity': SeverityLevel.MEDIUM,
                'description': 'External .send() without return value validation',
                'functions': list(set(functions)),
                'confidence': 0.7,
                'evidence': {
                    'pattern': 'unchecked_send',
                    'send_count': len(unchecked_sends)
                }
            })
        
        # Check for .transfer() (this is safer but can still fail)
        transfer_pattern = r'\.transfer\([^)]*\)'
        transfers = re.findall(transfer_pattern, source_code)
        
        if transfers:
            # Check if transfers are in loops (can cause out of gas)
            loop_transfers = re.findall(r'for.*\{.*\.transfer\(', source_code)
            if loop_transfers:
                vulnerabilities.append({
                    'type': 'Transfer in Loop',
                    'severity': SeverityLevel.HIGH,
                    'description': '.transfer() used inside loop can cause out of gas errors',
                    'functions': ['functions_with_loops'],
                    'confidence': 0.8,
                    'evidence': {
                        'pattern': 'transfer_in_loop',
                        'transfer_count': len(loop_transfers)
                    }
                })
        
        return vulnerabilities


class FrontRunningDetector(BaseVulnerabilityDetector):
    """Detects front-running vulnerabilities."""
    
    async def screen(self, target_contract: str) -> List[Any]:
        findings = []
        
        try:
            contract_info = await self.provider.get_contract_info(target_contract)
            
            if not contract_info or not contract_info.source_code:
                return findings
            
            source_code = contract_info.source_code.lower()
            
            # Check for front-running vulnerabilities
            frontrunning_vulns = await self._detect_frontrunning_vulnerabilities(source_code)
            
            for vuln in frontrunning_vulns:
                finding = type('Finding', (), {
                    'vulnerability_type': VulnerabilityType.FRONT_RUNNING,
                    'severity': vuln['severity'],
                    'title': f"Front-running Vulnerability: {vuln['type']}",
                    'description': vuln['description'],
                    'affected_functions': vuln['functions'],
                    'confidence': vuln['confidence'],
                    'exploitability_score': 0.5,
                    'impact_score': self._calculate_impact(VulnerabilityType.FRONT_RUNNING),
                    'evidence': vuln['evidence'],
                    'remediation': "Use commit-reveal schemes or batch processing to prevent front-running",
                    'references': ["https://consensys.github.io/smart-contract-best-practices/security-guidelines/attacks/"]
                })()
                findings.append(finding)
                
        except Exception as e:
            pass
        
        return findings
    
    async def _detect_frontrunning_vulnerabilities(self, source_code: str) -> List[Dict]:
        vulnerabilities = []
        
        # Check for publicly visible pending transactions
        public_pending = self._check_public_pending_transactions(source_code)
        if public_pending:
            vulnerabilities.append({
                'type': 'Public Pending Transactions',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Transaction details visible before execution, allowing front-running',
                'functions': public_pending['functions'],
                'confidence': 0.6,
                'evidence': {
                    'pattern': 'public_pending_transactions',
                    'visibility_points': public_pending['points']
                }
            })
        
        # Check for price oracles without proper protection
        vulnerable_oracles = self._check_vulnerable_oracles(source_code)
        if vulnerable_oracles:
            vulnerabilities.append({
                'type': 'Vulnerable Price Oracles',
                'severity': SeverityLevel.HIGH,
                'description': 'Price oracles can be manipulated or front-run',
                'functions': vulnerable_oracles['functions'],
                'confidence': 0.7,
                'evidence': {
                    'pattern': 'vulnerable_oracles',
                    'oracle_functions': vulnerable_oracles['functions']
                }
            })
        
        # Check for MEV (Maximal Extractable Value) opportunities
        mev_opportunities = self._check_mev_opportunities(source_code)
        if mev_opportunities:
            vulnerabilities.append({
                'type': 'MEV Opportunities',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Contract operations create MEV extraction opportunities',
                'functions': mev_opportunities['functions'],
                'confidence': 0.6,
                'evidence': {
                    'pattern': 'mev_opportunities',
                    'mev_operations': mev_opportunities['operations']
                }
            })
        
        return vulnerabilities
    
    def _check_public_pending_transactions(self, source_code: str) -> Optional[Dict]:
        """Check for publicly visible pending transactions."""
        # Look for functions that reveal transaction intentions
        reveal_patterns = [
            r'emit\s+\w+\s*before.*action',
            r'event\s+\w+\s*before.*transaction',
            r'public.*function.*reveals.*intent'
        ]
        
        vulnerable_functions = []
        points = []
        
        for pattern in reveal_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                points.extend(matches)
                func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'points': points
            }
        
        return None
    
    def _check_vulnerable_oracles(self, source_code: str) -> Optional[Dict]:
        """Check for vulnerable price oracles."""
        oracle_patterns = [
            r'getreserves\(\)',
            r'latestrounddata\(\)',
            r'getprice\(\)'
        ]
        
        vulnerable_functions = []
        
        for pattern in oracle_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                vulnerable_functions.extend(func_matches)
        
        # Check if oracles have proper protection
        has_protection = bool(re.search(r'(twap|time.*weighted|minimum.*delay)', source_code))
        
        if vulnerable_functions and not has_protection:
            return {
                'functions': list(set(vulnerable_functions))
            }
        
        return None
    
    def _check_mev_opportunities(self, source_code: str) -> Optional[Dict]:
        """Check for MEV extraction opportunities."""
        mev_patterns = [
            r'function.*swap.*large.*amount',
            r'function.*liquidate.*without.*delay',
            r'arbitrage.*opportunity',
            r'price.*difference'
        ]
        
        vulnerable_functions = []
        operations = []
        
        for pattern in mev_patterns:
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


class TimeManipulationDetector(BaseVulnerabilityDetector):
    """Detects time-based manipulation vulnerabilities."""
    
    async def screen(self, target_contract: str) -> List[Any]:
        findings = []
        
        try:
            contract_info = await self.provider.get_contract_info(target_contract)
            
            if not contract_info or not contract_info.source_code:
                return findings
            
            source_code = contract_info.source_code.lower()
            
            # Check for time manipulation vulnerabilities
            time_vulns = await self._detect_time_manipulation_vulnerabilities(source_code)
            
            for vuln in time_vulns:
                finding = type('Finding', (), {
                    'vulnerability_type': VulnerabilityType.TIME_MANIPULATION,
                    'severity': vuln['severity'],
                    'title': f"Time Manipulation Vulnerability: {vuln['type']}",
                    'description': vuln['description'],
                    'affected_functions': vuln['functions'],
                    'confidence': vuln['confidence'],
                    'exploitability_score': 0.4,
                    'impact_score': self._calculate_impact(VulnerabilityType.TIME_MANIPULATION),
                    'evidence': vuln['evidence'],
                    'remediation': "Use block numbers instead of timestamps for critical timing operations",
                    'references': ["https://consensys.github.io/smart-contract-best-practices/security-guidelines/timestamp-dependence/"]
                })()
                findings.append(finding)
                
        except Exception as e:
            pass
        
        return findings
    
    async def _detect_time_manipulation_vulnerabilities(self, source_code: str) -> List[Dict]:
        vulnerabilities = []
        
        # Check for timestamp dependence
        timestamp_dependence = self._check_timestamp_dependence(source_code)
        if timestamp_dependence:
            vulnerabilities.append({
                'type': 'Timestamp Dependence',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Contract logic depends on block.timestamp which miners can manipulate',
                'functions': timestamp_dependence['functions'],
                'confidence': 0.6,
                'evidence': {
                    'pattern': 'timestamp_dependence',
                    'timestamp_usages': timestamp_dependence['usages']
                }
            })
        
        # Check for insufficient time delays
        insufficient_delays = self._check_insufficient_time_delays(source_code)
        if insufficient_delays:
            vulnerabilities.append({
                'type': 'Insufficient Time Delays',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Critical operations have insufficient time delays between them',
                'functions': insufficient_delays['functions'],
                'confidence': 0.7,
                'evidence': {
                    'pattern': 'insufficient_delays',
                    'delay_operations': insufficient_delays['operations']
                }
            })
        
        # Check for time-based race conditions
        time_race_conditions = self._check_time_race_conditions(source_code)
        if time_race_conditions:
            vulnerabilities.append({
                'type': 'Time-based Race Conditions',
                'severity': SeverityLevel.HIGH,
                'description': 'Race conditions based on timing windows',
                'functions': time_race_conditions['functions'],
                'confidence': 0.8,
                'evidence': {
                    'pattern': 'time_race_conditions',
                    'race_points': time_race_conditions['points']
                }
            })
        
        return vulnerabilities
    
    def _check_timestamp_dependence(self, source_code: str) -> Optional[Dict]:
        """Check for timestamp dependence."""
        timestamp_patterns = [
            r'block\.timestamp',
            r'now\s*',
            r'timestamp\s*>'
        ]
        
        vulnerable_functions = []
        usages = []
        
        for pattern in timestamp_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                usages.extend(matches)
                func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'usages': usages
            }
        
        return None
    
    def _check_insufficient_time_delays(self, source_code: str) -> Optional[Dict]:
        """Check for insufficient time delays."""
        delay_patterns = [
            r'require\s*\(\s*block\.timestamp\s*-\s*\w+\s*<\s*\d+\s*\)',
            r'now\s*-\s*\w+\s*<\s*\d+'
        ]
        
        vulnerable_functions = []
        operations = []
        
        for pattern in delay_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                # Check if delay is too short (less than 1 hour = 3600 seconds)
                short_delays = [m for m in matches if '3600' not in m]
                if short_delays:
                    operations.extend(short_delays)
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'operations': operations
            }
        
        return None
    
    def _check_time_race_conditions(self, source_code: str) -> Optional[Dict]:
        """Check for time-based race conditions."""
        race_patterns = [
            r'if\s*\(\s*block\.timestamp\s*>\s*\w+\s*\)',
            r'if\s*\(\s*now\s*>\s*\w+\s*\)'
        ]
        
        vulnerable_functions = []
        points = []
        
        for pattern in race_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                points.extend(matches)
                func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'points': points
            }
        
        return None


class TokenApprovalDetector(BaseVulnerabilityDetector):
    """Detects token approval vulnerabilities."""
    
    async def screen(self, target_contract: str) -> List[Any]:
        findings = []
        
        try:
            contract_info = await self.provider.get_contract_info(target_contract)
            
            if not contract_info or not contract_info.source_code:
                return findings
            
            source_code = contract_info.source_code.lower()
            
            # Check for token approval vulnerabilities
            approval_vulns = await self._detect_token_approval_vulnerabilities(source_code)
            
            for vuln in approval_vulns:
                finding = type('Finding', (), {
                    'vulnerability_type': VulnerabilityType.TOKEN_APPROVAL,
                    'severity': vuln['severity'],
                    'title': f"Token Approval Vulnerability: {vuln['type']}",
                    'description': vuln['description'],
                    'affected_functions': vuln['functions'],
                    'confidence': vuln['confidence'],
                    'exploitability_score': 0.8,
                    'impact_score': self._calculate_impact(VulnerabilityType.TOKEN_APPROVAL),
                    'evidence': vuln['evidence'],
                    'remediation': "Implement proper approval patterns: first set to 0, then to new amount",
                    'references': ["https://consensys.github.io/smart-contract-best-practices/security-guidelines/erc20/"]
                })()
                findings.append(finding)
                
        except Exception as e:
            pass
        
        return findings
    
    async def _detect_token_approval_vulnerabilities(self, source_code: str) -> List[Dict]:
        vulnerabilities = []
        
        # Check for approve without setting to 0 first
        unsafe_approve = self._check_unsafe_approve_pattern(source_code)
        if unsafe_approve:
            vulnerabilities.append({
                'type': 'Unsafe Approval Pattern',
                'severity': SeverityLevel.HIGH,
                'description': 'approve() called without first setting allowance to 0',
                'functions': unsafe_approve['functions'],
                'confidence': 0.9,
                'evidence': {
                    'pattern': 'unsafe_approve',
                    'approve_operations': unsafe_approve['operations']
                }
            })
        
        # Check for unlimited approvals
        unlimited_approvals = self._check_unlimited_approvals(source_code)
        if unlimited_approvals:
            vulnerabilities.append({
                'type': 'Unlimited Approvals',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Unlimited token approvals create unnecessary risk',
                'functions': unlimited_approvals['functions'],
                'confidence': 0.7,
                'evidence': {
                    'pattern': 'unlimited_approvals',
                    'approval_amounts': unlimited_approvals['amounts']
                }
            })
        
        # Check for approval front-running
        approval_frontrunning = self._check_approval_frontrunning(source_code)
        if approval_frontrunning:
            vulnerabilities.append({
                'type': 'Approval Front-running',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Approval operations vulnerable to front-running attacks',
                'functions': approval_frontrunning['functions'],
                'confidence': 0.8,
                'evidence': {
                    'pattern': 'approval_frontrunning',
                    'vulnerable_operations': approval_frontrunning['operations']
                }
            })
        
        return vulnerabilities
    
    def _check_unsafe_approve_pattern(self, source_code: str) -> Optional[Dict]:
        """Check for unsafe approve pattern (not setting to 0 first)."""
        # Look for approve calls without preceding approve(0, ...) call
        approve_pattern = r'approve\s*\([^)]*\)'
        approve_calls = re.findall(approve_pattern, source_code)
        
        vulnerable_functions = []
        operations = []
        
        for i, approve_call in enumerate(approve_calls):
            # Check if previous call was approve(0, ...)
            if i > 0:
                prev_call = approve_calls[i-1]
                if 'approve(0' not in prev_call:
                    operations.append(approve_call)
                    # Find function containing this approve call
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + re.escape(approve_call), source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'operations': operations
            }
        
        return None
    
    def _check_unlimited_approvals(self, source_code: str) -> Optional[Dict]:
        """Check for unlimited token approvals."""
        unlimited_patterns = [
            r'approve\s*\([^)]*,\s*2\s*\*\s*256\s*-\s*1\s*\)',
            r'approve\s*\([^)]*,\s*uint256\s*\.\s*max\s*\)',
            r'approve\s*\([^)]*,\s*type\s*\([^)]*\)\.max'
        ]
        
        vulnerable_functions = []
        amounts = []
        
        for pattern in unlimited_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                amounts.extend(matches)
                func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'amounts': amounts
            }
        
        return None
    
    def _check_approval_frontrunning(self, source_code: str) -> Optional[Dict]:
        """Check for approval front-running vulnerabilities."""
        # Look for approve calls in functions that can be called by anyone
        public_approve = re.findall(r'function\s+\w+\s*[^{]*public\s*\{[^}]*approve\s*\(', source_code)
        
        if public_approve:
            return {
                'functions': ['public_approve_functions'],
                'operations': public_approve
            }
        
        return None


class DelegateCallMisuseDetector(BaseVulnerabilityDetector):
    """Detects delegatecall misuse vulnerabilities."""
    
    async def screen(self, target_contract: str) -> List[Any]:
        findings = []
        
        try:
            contract_info = await self.provider.get_contract_info(target_contract)
            
            if not contract_info or not contract_info.source_code:
                return findings
            
            source_code = contract_info.source_code.lower()
            
            # Check for delegatecall misuse vulnerabilities
            delegatecall_vulns = await self._detect_delegatecall_misuse_vulnerabilities(source_code)
            
            for vuln in delegatecall_vulns:
                finding = type('Finding', (), {
                    'vulnerability_type': VulnerabilityType.DELEGATECALL_MISUSE,
                    'severity': vuln['severity'],
                    'title': f"Delegatecall Misuse Vulnerability: {vuln['type']}",
                    'description': vuln['description'],
                    'affected_functions': vuln['functions'],
                    'confidence': vuln['confidence'],
                    'exploitability_score': 0.9,
                    'impact_score': self._calculate_impact(VulnerabilityType.DELEGATECALL_MISUSE),
                    'evidence': vuln['evidence'],
                    'remediation': "Never use delegatecall with user-provided addresses or use proxy patterns with proper validation",
                    'references': ["https://consensys.github.io/smart-contract-best-practices/security-guidelines/delegatecall/"]
                })()
                findings.append(finding)
                
        except Exception as e:
            pass
        
        return findings
    
    async def _detect_delegatecall_misuse_vulnerabilities(self, source_code: str) -> List[Dict]:
        vulnerabilities = []
        
        # Check for delegatecall with user input
        user_delegatecall = self._check_user_controlled_delegatecall(source_code)
        if user_delegatecall:
            vulnerabilities.append({
                'type': 'User-controlled Delegatecall',
                'severity': SeverityLevel.CRITICAL,
                'description': 'delegatecall used with user-provided target address',
                'functions': user_delegatecall['functions'],
                'confidence': 0.9,
                'evidence': {
                    'pattern': 'user_controlled_delegatecall',
                    'delegatecall_operations': user_delegatecall['operations']
                }
            })
        
        # Check for delegatecall without validation
        unvalidated_delegatecall = self._check_unvalidated_delegatecall(source_code)
        if unvalidated_delegatecall:
            vulnerabilities.append({
                'type': 'Unvalidated Delegatecall',
                'severity': SeverityLevel.HIGH,
                'description': 'delegatecall performed without proper target validation',
                'functions': unvalidated_delegatecall['functions'],
                'confidence': 0.8,
                'evidence': {
                    'pattern': 'unvalidated_delegatecall',
                    'validation_issues': unvalidated_delegatecall['issues']
                }
            })
        
        # Check for storage collision in delegatecall
        storage_collision = self._check_storage_collision_risk(source_code)
        if storage_collision:
            vulnerabilities.append({
                'type': 'Storage Collision Risk',
                'severity': SeverityLevel.HIGH,
                'description': 'delegatecall usage creates storage collision vulnerabilities',
                'functions': storage_collision['functions'],
                'confidence': 0.7,
                'evidence': {
                    'pattern': 'storage_collision_risk',
                    'collision_points': storage_collision['points']
                }
            })
        
        return vulnerabilities
    
    def _check_user_controlled_delegatecall(self, source_code: str) -> Optional[Dict]:
        """Check for delegatecall with user-controlled addresses."""
        # Look for delegatecall with parameters or msg.sender
        user_controlled_patterns = [
            r'delegatecall\s*\([^)]*msg\.sender[^)]*\)',
            r'delegatecall\s*\([^)]*_target[^)]*\)',
            r'delegatecall\s*\([^)]*parameter[^)]*\)'
        ]
        
        vulnerable_functions = []
        operations = []
        
        for pattern in user_controlled_patterns:
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
    
    def _check_unvalidated_delegatecall(self, source_code: str) -> Optional[Dict]:
        """Check for delegatecall without proper validation."""
        delegatecall_pattern = r'delegatecall\s*\([^)]*\)'
        delegatecall_matches = re.findall(delegatecall_pattern, source_code)
        
        vulnerable_functions = []
        issues = []
        
        if delegatecall_matches:
            # Check if there's validation before delegatecall
            for match in delegatecall_matches:
                # Simple check for validation patterns
                has_validation = bool(re.search(r'(require|assert|if).*' + re.escape(match), source_code))
                
                if not has_validation:
                    issues.append(f"Unvalidated delegatecall: {match}")
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + re.escape(match), source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'issues': issues
            }
        
        return None
    
    def _check_storage_collision_risk(self, source_code: str) -> Optional[Dict]:
        """Check for storage collision risk with delegatecall."""
        # Look for delegatecall in contracts with state variables
        has_delegatecall = bool(re.search(r'delegatecall', source_code))
        has_state_vars = bool(re.search(r'(uint|address|mapping|struct)\s+\w+', source_code))
        
        if has_delegatecall and has_state_vars:
            # Look for functions that use both delegatecall and state variables
            mixed_usage = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*delegatecall[^}]*\w+\s*=.*}', source_code)
            
            if mixed_usage:
                return {
                    'functions': mixed_usage,
                    'points': ['delegatecall_with_state_variables']
                }
        
        return None


class SelfdestructMisuseDetector(BaseVulnerabilityDetector):
    """Detects selfdestruct misuse vulnerabilities."""
    
    async def screen(self, target_contract: str) -> List[Any]:
        findings = []
        
        try:
            contract_info = await self.provider.get_contract_info(target_contract)
            
            if not contract_info or not contract_info.source_code:
                return findings
            
            source_code = contract_info.source_code.lower()
            
            # Check for selfdestruct misuse vulnerabilities
            selfdestruct_vulns = await self._detect_selfdestruct_misuse_vulnerabilities(source_code)
            
            for vuln in selfdestruct_vulns:
                finding = type('Finding', (), {
                    'vulnerability_type': VulnerabilityType.SELFDESTRUCT_MISUSE,
                    'severity': vuln['severity'],
                    'title': f"Selfdestruct Misuse Vulnerability: {vuln['type']}",
                    'description': vuln['description'],
                    'affected_functions': vuln['functions'],
                    'confidence': vuln['confidence'],
                    'exploitability_score': 0.8,
                    'impact_score': self._calculate_impact(VulnerabilityType.SELFDESTRUCT_MISUSE),
                    'evidence': vuln['evidence'],
                    'remediation': "Restrict selfdestruct to owner-only functions or remove entirely if not needed",
                    'references': ["https://consensys.github.io/smart-contract-best-practices/security-guidelines/self-destruct/"]
                })()
                findings.append(finding)
                
        except Exception as e:
            pass
        
        return findings
    
    async def _detect_selfdestruct_misuse_vulnerabilities(self, source_code: str) -> List[Dict]:
        vulnerabilities = []
        
        # Check for public selfdestruct
        public_selfdestruct = self._check_public_selfdestruct(source_code)
        if public_selfdestruct:
            vulnerabilities.append({
                'type': 'Public Selfdestruct',
                'severity': SeverityLevel.CRITICAL,
                'description': 'selfdestruct function is publicly accessible',
                'functions': public_selfdestruct['functions'],
                'confidence': 0.9,
                'evidence': {
                    'pattern': 'public_selfdestruct',
                    'selfdestruct_locations': public_selfdestruct['locations']
                }
            })
        
        # Check for selfdestruct without proper validation
        unvalidated_selfdestruct = self._check_unvalidated_selfdestruct(source_code)
        if unvalidated_selfdestruct:
            vulnerabilities.append({
                'type': 'Unvalidated Selfdestruct',
                'severity': SeverityLevel.HIGH,
                'description': 'selfdestruct called without proper access validation',
                'functions': unvalidated_selfdestruct['functions'],
                'confidence': 0.8,
                'evidence': {
                    'pattern': 'unvalidated_selfdestruct',
                    'validation_issues': unvalidated_selfdestruct['issues']
                }
            })
        
        # Check for selfdestruct with funds remaining
        selfdestruct_with_funds = self._check_selfdestruct_with_funds(source_code)
        if selfdestruct_with_funds:
            vulnerabilities.append({
                'type': 'Selfdestruct with Remaining Funds',
                'severity': SeverityLevel.MEDIUM,
                'description': 'selfdestruct called while contract still holds funds',
                'functions': selfdestruct_with_funds['functions'],
                'confidence': 0.7,
                'evidence': {
                    'pattern': 'selfdestruct_with_funds',
                    'fund_states': selfdestruct_with_funds['states']
                }
            })
        
        return vulnerabilities
    
    def _check_public_selfdestruct(self, source_code: str) -> Optional[Dict]:
        """Check for publicly accessible selfdestruct functions."""
        public_selfdestruct_pattern = r'function\s+\w+\s*[^{]*public\s*\{[^}]*selfdestruct\s*\('
        public_matches = re.findall(public_selfdestruct_pattern, source_code)
        
        if public_matches:
            return {
                'functions': ['public_selfdestruct_functions'],
                'locations': public_matches
            }
        
        return None
    
    def _check_unvalidated_selfdestruct(self, source_code: str) -> Optional[Dict]:
        """Check for selfdestruct without proper validation."""
        selfdestruct_pattern = r'selfdestruct\s*\('
        selfdestruct_matches = re.findall(selfdestruct_pattern, source_code)
        
        vulnerable_functions = []
        issues = []
        
        if selfdestruct_matches:
            # Check if there's proper access control
            for match in selfdestruct_matches:
                has_owner_check = bool(re.search(r'(require.*owner|onlyowner|msg\.sender.*==.*owner)', source_code))
                
                if not has_owner_check:
                    issues.append(f"Unvalidated selfdestruct: {match}")
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + re.escape(match), source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'issues': issues
            }
        
        return None
    
    def _check_selfdestruct_with_funds(self, source_code: str) -> Optional[Dict]:
        """Check for selfdestruct called while contract may still hold funds."""
        # Look for selfdestruct without balance transfer
        selfdestruct_pattern = r'selfdestruct\s*\('
        selfdestruct_matches = re.findall(selfdestruct_pattern, source_code)
        
        vulnerable_functions = []
        states = []
        
        if selfdestruct_matches:
            # Check if balance is transferred before selfdestruct
            for match in selfdestruct_matches:
                # Simple check for balance transfer patterns
                has_balance_transfer = bool(re.search(r'(transfer|send).*before.*' + re.escape(match), source_code))
                
                if not has_balance_transfer:
                    states.append(f"Potential funds remaining: {match}")
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + re.escape(match), source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'states': states
            }
        
        return None