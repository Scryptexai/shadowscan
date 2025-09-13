"""
Specialized EVM Vulnerability Detectors

This module contains specialized detectors for advanced and niche vulnerability types.
"""

import asyncio
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

from shadowscan.adapters.evm.provider import EVMProvider
from shadowscan.models.findings import Finding, SeverityLevel
from shadowscan.detectors.evm.vulnerability_detectors import BaseVulnerabilityDetector, VulnerabilityType


class ProxyMisuseDetector(BaseVulnerabilityDetector):
    """Detects proxy-related vulnerabilities."""
    
    async def screen(self, target_contract: str) -> List[Any]:
        findings = []
        
        try:
            contract_info = await self.provider.get_contract_info(target_contract)
            
            if not contract_info or not contract_info.source_code:
                return findings
            
            source_code = contract_info.source_code.lower()
            
            # Check for proxy misuse vulnerabilities
            proxy_vulns = await self._detect_proxy_misuse_vulnerabilities(source_code)
            
            for vuln in proxy_vulns:
                finding = type('Finding', (), {
                    'vulnerability_type': VulnerabilityType.PROXY_MISUSE,
                    'severity': vuln['severity'],
                    'title': f"Proxy Misuse Vulnerability: {vuln['type']}",
                    'description': vuln['description'],
                    'affected_functions': vuln['functions'],
                    'confidence': vuln['confidence'],
                    'exploitability_score': 0.7,
                    'impact_score': self._calculate_impact(VulnerabilityType.PROXY_MISUSE),
                    'evidence': vuln['evidence'],
                    'remediation': "Follow EIP-1822 proxy standards and implement proper upgrade mechanisms",
                    'references': ["https://eips.ethereum.org/EIPS/eip-1822"]
                })()
                findings.append(finding)
                
        except Exception as e:
            pass
        
        return findings
    
    async def _detect_proxy_misuse_vulnerabilities(self, source_code: str) -> List[Dict]:
        vulnerabilities = []
        
        # Check for uninitialized proxy
        uninitialized_proxy = self._check_uninitialized_proxy(source_code)
        if uninitialized_proxy:
            vulnerabilities.append({
                'type': 'Uninitialized Proxy',
                'severity': SeverityLevel.CRITICAL,
                'description': 'Proxy contract not properly initialized',
                'functions': uninitialized_proxy['functions'],
                'confidence': 0.9,
                'evidence': {
                    'pattern': 'uninitialized_proxy',
                    'initialization_issues': uninitialized_proxy['issues']
                }
            })
        
        # Check for storage layout conflict
        storage_conflict = self._check_proxy_storage_conflict(source_code)
        if storage_conflict:
            vulnerabilities.append({
                'type': 'Storage Layout Conflict',
                'severity': SeverityLevel.HIGH,
                'description': 'Proxy and implementation have conflicting storage layouts',
                'functions': storage_conflict['functions'],
                'confidence': 0.8,
                'evidence': {
                    'pattern': 'storage_layout_conflict',
                    'conflict_points': storage_conflict['points']
                }
            })
        
        # Check for transparent proxy bypass
        transparent_bypass = self._check_transparent_proxy_bypass(source_code)
        if transparent_bypass:
            vulnerabilities.append({
                'type': 'Transparent Proxy Bypass',
                'severity': SeverityLevel.HIGH,
                'description': 'Transparent proxy can be bypassed to call admin functions',
                'functions': transparent_bypass['functions'],
                'confidence': 0.8,
                'evidence': {
                    'pattern': 'transparent_proxy_bypass',
                    'bypass_methods': transparent_bypass['methods']
                }
            })
        
        return vulnerabilities
    
    def _check_uninitialized_proxy(self, source_code: str) -> Optional[Dict]:
        """Check for uninitialized proxy contract."""
        # Look for proxy patterns without proper initialization
        proxy_patterns = [
            r'delegatecall\s*\(\s*_implementation\s*\)',
            r'fallback\s*\(\)\s*external.*payable.*\{.*delegatecall'
        ]
        
        vulnerable_functions = []
        issues = []
        
        for pattern in proxy_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                # Check if initialization is present
                has_initialization = bool(re.search(r'(initialize|constructor|__init__)', source_code))
                
                if not has_initialization:
                    issues.append(f"Uninitialized proxy pattern: {pattern}")
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'issues': issues
            }
        
        return None
    
    def _check_proxy_storage_conflict(self, source_code: str) -> Optional[Dict]:
        """Check for storage layout conflicts between proxy and implementation."""
        # Look for both proxy and implementation storage variables
        has_proxy_storage = bool(re.search(r'(implementation|logic)\s*address', source_code))
        has_impl_storage = bool(re.search(r'(uint|mapping|struct)\s+\w+', source_code))
        
        if has_proxy_storage and has_impl_storage:
            # Check if storage slots are properly managed
            proper_slots = bool(re.search(r'storage.*slot|__gap|reserved', source_code))
            
            if not proper_slots:
                return {
                    'functions': ['constructor', 'fallback'],
                    'points': ['unmanaged_storage_slots']
                }
        
        return None
    
    def _check_transparent_proxy_bypass(self, source_code: str) -> Optional[Dict]:
        """Check for transparent proxy bypass vulnerabilities."""
        # Look for admin functions that might be bypassable
        admin_patterns = [
            r'function.*admin.*only',
            r'function.*owner.*only',
            r'modifier.*onlyadmin'
        ]
        
        vulnerable_functions = []
        methods = []
        
        for pattern in admin_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                # Check if proxy properly protects admin functions
                has_proxy_protection = bool(re.search(r'(proxy|transparent).*should.*not.*call', source_code))
                
                if not has_proxy_protection:
                    methods.extend(matches)
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'methods': methods
            }
        
        return None


class UpgradeMechanismDetector(BaseVulnerabilityDetector):
    """Detects upgrade mechanism vulnerabilities."""
    
    async def screen(self, target_contract: str) -> List[Any]:
        findings = []
        
        try:
            contract_info = await self.provider.get_contract_info(target_contract)
            
            if not contract_info or not contract_info.source_code:
                return findings
            
            source_code = contract_info.source_code.lower()
            
            # Check for upgrade mechanism vulnerabilities
            upgrade_vulns = await self._detect_upgrade_vulnerabilities(source_code)
            
            for vuln in upgrade_vulns:
                finding = type('Finding', (), {
                    'vulnerability_type': VulnerabilityType.UPGRADE_MISUSE,
                    'severity': vuln['severity'],
                    'title': f"Upgrade Mechanism Vulnerability: {vuln['type']}",
                    'description': vuln['description'],
                    'affected_functions': vuln['functions'],
                    'confidence': vuln['confidence'],
                    'exploitability_score': 0.6,
                    'impact_score': self._calculate_impact(VulnerabilityType.UPGRADE_MISUSE),
                    'evidence': vuln['evidence'],
                    'remediation': "Implement timelocks, multi-sig controls, and proper upgrade governance",
                    'references': ["https://docs.openzeppelin.com/contracts/upgradeable"]
                })()
                findings.append(finding)
                
        except Exception as e:
            pass
        
        return findings
    
    async def _detect_upgrade_vulnerabilities(self, source_code: str) -> List[Dict]:
        vulnerabilities = []
        
        # Check for unlimited upgrade authority
        unlimited_upgrade = self._check_unlimited_upgrade_authority(source_code)
        if unlimited_upgrade:
            vulnerabilities.append({
                'type': 'Unlimited Upgrade Authority',
                'severity': SeverityLevel.HIGH,
                'description': 'Single entity has unlimited upgrade authority without controls',
                'functions': unlimited_upgrade['functions'],
                'confidence': 0.8,
                'evidence': {
                    'pattern': 'unlimited_upgrade_authority',
                    'upgrade_points': unlimited_upgrade['points']
                }
            })
        
        # Check for missing upgrade delays
        missing_delay = self._check_missing_upgrade_delay(source_code)
        if missing_delay:
            vulnerabilities.append({
                'type': 'Missing Upgrade Delay',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Upgrades can be executed immediately without timelock',
                'functions': missing_delay['functions'],
                'confidence': 0.7,
                'evidence': {
                    'pattern': 'missing_upgrade_delay',
                    'upgrade_operations': missing_delay['operations']
                }
            })
        
        # Check for upgrade without validation
        unvalidated_upgrade = self._check_unvalidated_upgrade(source_code)
        if unvalidated_upgrade:
            vulnerabilities.append({
                'type': 'Unvalidated Upgrade',
                'severity': SeverityLevel.HIGH,
                'description': 'Implementation address not validated before upgrade',
                'functions': unvalidated_upgrade['functions'],
                'confidence': 0.8,
                'evidence': {
                    'pattern': 'unvalidated_upgrade',
                    'validation_issues': unvalidated_upgrade['issues']
                }
            })
        
        return vulnerabilities
    
    def _check_unlimited_upgrade_authority(self, source_code: str) -> Optional[Dict]:
        """Check for unlimited upgrade authority."""
        upgrade_patterns = [
            r'function.*upgrade.*onlyowner',
            r'function.*setimplementation.*public'
        ]
        
        vulnerable_functions = []
        points = []
        
        for pattern in upgrade_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                # Check if there are additional controls (multi-sig, timelock)
                has_additional_controls = bool(re.search(r'(multisig|timelock|delay|governance)', source_code))
                
                if not has_additional_controls:
                    points.extend(matches)
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'points': points
            }
        
        return None
    
    def _check_missing_upgrade_delay(self, source_code: str) -> Optional[Dict]:
        """Check for missing upgrade delays."""
        upgrade_pattern = r'upgrade.*implementation'
        upgrade_matches = re.findall(upgrade_pattern, source_code)
        
        vulnerable_functions = []
        operations = []
        
        if upgrade_matches:
            # Check if there's a timelock mechanism
            has_timelock = bool(re.search(r'(timelock|delay.*blocks|minimum.*wait)', source_code))
            
            if not has_timelock:
                operations.extend(upgrade_matches)
                func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + upgrade_pattern, source_code)
                vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'operations': operations
            }
        
        return None
    
    def _check_unvalidated_upgrade(self, source_code: str) -> Optional[Dict]:
        """Check for unvalidated implementation upgrades."""
        upgrade_pattern = r'_implementation\s*=\s*\w+'
        upgrade_matches = re.findall(upgrade_pattern, source_code)
        
        vulnerable_functions = []
        issues = []
        
        if upgrade_matches:
            # Check if implementation address is validated
            has_validation = bool(re.search(r'(require.*implementation|validate.*address)', source_code))
            
            if not has_validation:
                issues.extend([f"Unvalidated upgrade: {match}" for match in upgrade_matches])
                func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + upgrade_pattern, source_code)
                vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'issues': issues
            }
        
        return None


class MulticallExploitDetector(BaseVulnerabilityDetector):
    """Detects multicall-related vulnerabilities."""
    
    async def screen(self, target_contract: str) -> List[Any]:
        findings = []
        
        try:
            contract_info = await self.provider.get_contract_info(target_contract)
            
            if not contract_info or not contract_info.source_code:
                return findings
            
            source_code = contract_info.source_code.lower()
            
            # Check for multicall exploit vulnerabilities
            multicall_vulns = await self._detect_multicall_vulnerabilities(source_code)
            
            for vuln in multicall_vulns:
                finding = type('Finding', (), {
                    'vulnerability_type': VulnerabilityType.MULTICALL_EXPLOIT,
                    'severity': vuln['severity'],
                    'title': f"Multicall Exploit Vulnerability: {vuln['type']}",
                    'description': vuln['description'],
                    'affected_functions': vuln['functions'],
                    'confidence': vuln['confidence'],
                    'exploitability_score': 0.7,
                    'impact_score': self._calculate_impact(VulnerabilityType.MULTICALL_EXPLOIT),
                    'evidence': vuln['evidence'],
                    'remediation': "Implement proper state validation between calls in multicall operations",
                    'references': ["https://github.com/ConsenSys/awesome-blockchain-security#multicall"]
                })()
                findings.append(finding)
                
        except Exception as e:
            pass
        
        return findings
    
    async def _detect_multicall_vulnerabilities(self, source_code: str) -> List[Dict]:
        vulnerabilities = []
        
        # Check for state manipulation in multicall
        state_manipulation = self._check_multicall_state_manipulation(source_code)
        if state_manipulation:
            vulnerabilities.append({
                'type': 'State Manipulation in Multicall',
                'severity': SeverityLevel.HIGH,
                'description': 'State can be manipulated across multiple calls in multicall',
                'functions': state_manipulation['functions'],
                'confidence': 0.8,
                'evidence': {
                    'pattern': 'multicall_state_manipulation',
                    'manipulation_points': state_manipulation['points']
                }
            })
        
        # Check for reentrancy in multicall
        reentrancy_multicall = self._check_multicall_reentrancy(source_code)
        if reentrancy_multicall:
            vulnerabilities.append({
                'type': 'Reentrancy in Multicall',
                'severity': SeverityLevel.HIGH,
                'description': 'Reentrancy vulnerability within multicall operations',
                'functions': reentrancy_multicall['functions'],
                'confidence': 0.8,
                'evidence': {
                    'pattern': 'multicall_reentrancy',
                    'reentrancy_points': reentrancy_multicall['points']
                }
            })
        
        # Check for unchecked multicall results
        unchecked_multicall = self._check_unchecked_multicall(source_code)
        if unchecked_multicall:
            vulnerabilities.append({
                'type': 'Unchecked Multicall Results',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Multicall results not properly validated',
                'functions': unchecked_multicall['functions'],
                'confidence': 0.7,
                'evidence': {
                    'pattern': 'unchecked_multicall',
                    'validation_issues': unchecked_multicall['issues']
                }
            })
        
        return vulnerabilities
    
    def _check_multicall_state_manipulation(self, source_code: str) -> Optional[Dict]:
        """Check for state manipulation vulnerabilities in multicall."""
        multicall_pattern = r'multicall|batch.*call'
        multicall_matches = re.findall(multicall_pattern, source_code)
        
        vulnerable_functions = []
        points = []
        
        if multicall_matches:
            # Check if state changes occur between calls
            state_change_patterns = [
                r'balances\[',
                r'mapping\[',
                r'uint.*=',
                r'state.*='
            ]
            
            for pattern in state_change_patterns:
                state_changes = re.findall(pattern, source_code)
                if state_changes:
                    points.extend([f"State change in multicall: {change}" for change in state_changes])
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + multicall_pattern, source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'points': points
            }
        
        return None
    
    def _check_multicall_reentrancy(self, source_code: str) -> Optional[Dict]:
        """Check for reentrancy within multicall operations."""
        multicall_pattern = r'multicall'
        external_call_pattern = r'\.(call|transfer|send)\('
        
        # Look for multicall functions that also make external calls
        multicall_functions = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + multicall_pattern + '[^}]*\}', source_code)
        
        vulnerable_functions = []
        points = []
        
        for func in multicall_functions:
            if re.search(external_call_pattern, func):
                vulnerable_functions.append(func)
                points.append(f"External call in multicall function: {func}")
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'points': points
            }
        
        return None
    
    def _check_unchecked_multicall(self, source_code: str) -> Optional[Dict]:
        """Check for unchecked multicall results."""
        multicall_pattern = r'multicall\s*\([^)]*\)'
        multicall_matches = re.findall(multicall_pattern, source_code)
        
        vulnerable_functions = []
        issues = []
        
        if multicall_matches:
            # Check if results are validated
            for match in multicall_matches:
                has_validation = bool(re.search(r'(require.*result|assert.*multicall)', source_code))
                
                if not has_validation:
                    issues.append(f"Unchecked multicall: {match}")
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + re.escape(match), source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'issues': issues
            }
        
        return None


class SignatureReplayDetector(BaseVulnerabilityDetector):
    """Detects signature replay vulnerabilities."""
    
    async def screen(self, target_contract: str) -> List[Any]:
        findings = []
        
        try:
            contract_info = await self.provider.get_contract_info(target_contract)
            
            if not contract_info or not contract_info.source_code:
                return findings
            
            source_code = contract_info.source_code.lower()
            
            # Check for signature replay vulnerabilities
            replay_vulns = await self._detect_signature_replay_vulnerabilities(source_code)
            
            for vuln in replay_vulns:
                finding = type('Finding', (), {
                    'vulnerability_type': VulnerabilityType.SIGNATURE_REPLAY,
                    'severity': vuln['severity'],
                    'title': f"Signature Replay Vulnerability: {vuln['type']}",
                    'description': vuln['description'],
                    'affected_functions': vuln['functions'],
                    'confidence': vuln['confidence'],
                    'exploitability_score': 0.8,
                    'impact_score': self._calculate_impact(VulnerabilityType.SIGNATURE_REPLAY),
                    'evidence': vuln['evidence'],
                    'remediation': "Implement proper nonce management and domain separation for signatures",
                    'references': ["https://eips.ethereum.org/EIPS/eip-712"]
                })()
                findings.append(finding)
                
        except Exception as e:
            pass
        
        return findings
    
    async def _detect_signature_replay_vulnerabilities(self, source_code: str) -> List[Dict]:
        vulnerabilities = []
        
        # Check for missing nonce management
        missing_nonce = self._check_missing_nonce_management(source_code)
        if missing_nonce:
            vulnerabilities.append({
                'type': 'Missing Nonce Management',
                'severity': SeverityLevel.HIGH,
                'description': 'Signatures used without proper nonce management',
                'functions': missing_nonce['functions'],
                'confidence': 0.9,
                'evidence': {
                    'pattern': 'missing_nonce_management',
                    'signature_operations': missing_nonce['operations']
                }
            })
        
        # Check for domain separation issues
        domain_separation = self._check_domain_separation_issues(source_code)
        if domain_separation:
            vulnerabilities.append({
                'type': 'Domain Separation Issues',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Signatures lack proper domain separation',
                'functions': domain_separation['functions'],
                'confidence': 0.7,
                'evidence': {
                    'pattern': 'domain_separation_issues',
                    'separation_issues': domain_separation['issues']
                }
            })
        
        # Check for signature replay across chains
        chain_replay = self._check_chain_replay_vulnerability(source_code)
        if chain_replay:
            vulnerabilities.append({
                'type': 'Chain Replay Vulnerability',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Signatures can be replayed across different chains',
                'functions': chain_replay['functions'],
                'confidence': 0.6,
                'evidence': {
                    'pattern': 'chain_replay_vulnerability',
                    'chain_dependencies': chain_replay['dependencies']
                }
            })
        
        return vulnerabilities
    
    def _check_missing_nonce_management(self, source_code: str) -> Optional[Dict]:
        """Check for missing nonce management in signature verification."""
        signature_patterns = [
            r'ecrecover\s*\(',
            r'verify\s*\(',
            r'signature.*verify'
        ]
        
        vulnerable_functions = []
        operations = []
        
        for pattern in signature_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                # Check if nonce is used
                has_nonce = bool(re.search(r'(nonce|counter|sequence)', source_code))
                
                if not has_nonce:
                    operations.extend(matches)
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'operations': operations
            }
        
        return None
    
    def _check_domain_separation_issues(self, source_code: str) -> Optional[Dict]:
        """Check for domain separation issues in signatures."""
        signature_patterns = [
            r'ecrecover\s*\(',
            r'signature.*verify'
        ]
        
        vulnerable_functions = []
        issues = []
        
        for pattern in signature_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                # Check if domain separator is used (EIP-712)
                has_domain_separator = bool(re.search(r'(domain|separator|eip712)', source_code))
                
                if not has_domain_separator:
                    issues.extend([f"No domain separation: {match}" for match in matches])
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'issues': issues
            }
        
        return None
    
    def _check_chain_replay_vulnerability(self, source_code: str) -> Optional[Dict]:
        """Check for chain replay vulnerabilities."""
        signature_patterns = [
            r'ecrecover\s*\(',
            r'verify.*signature'
        ]
        
        vulnerable_functions = []
        dependencies = []
        
        for pattern in signature_patterns:
            matches = re.findall(pattern, source_code)
            if matches:
                # Check if chain ID is included in signature
                has_chain_id = bool(re.search(r'(chainid|chain.*id)', source_code))
                
                if not has_chain_id:
                    dependencies.extend([f"Chain ID missing: {match}" for match in matches])
                    func_matches = re.findall(r'function\s+(\w+)\s*[^{]*\{[^}]*' + pattern, source_code)
                    vulnerable_functions.extend(func_matches)
        
        if vulnerable_functions:
            return {
                'functions': list(set(vulnerable_functions)),
                'dependencies': dependencies
            }
        
        return None


class StorageCollisionDetector(BaseVulnerabilityDetector):
    """Detects storage collision vulnerabilities."""
    
    async def screen(self, target_contract: str) -> List[Any]:
        findings = []
        
        try:
            contract_info = await self.provider.get_contract_info(target_contract)
            
            if not contract_info or not contract_info.source_code:
                return findings
            
            source_code = contract_info.source_code.lower()
            
            # Check for storage collision vulnerabilities
            collision_vulns = await self._detect_storage_collision_vulnerabilities(source_code)
            
            for vuln in collision_vulns:
                finding = type('Finding', (), {
                    'vulnerability_type': VulnerabilityType.STORAGE_COLLISION,
                    'severity': vuln['severity'],
                    'title': f"Storage Collision Vulnerability: {vuln['type']}",
                    'description': vuln['description'],
                    'affected_functions': vuln['functions'],
                    'confidence': vuln['confidence'],
                    'exploitability_score': 0.7,
                    'impact_score': self._calculate_impact(VulnerabilityType.STORAGE_COLLISION),
                    'evidence': vuln['evidence'],
                    'remediation': 'Use explicit storage slots or implement proper storage layout management',
                    'references': ['https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html']
                })()
                findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error in storage collision detector: {e}")
        
        return findings
