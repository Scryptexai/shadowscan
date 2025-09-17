#!/usr/bin/env python3
"""
Real-time Vulnerability Validation Module
"""

import asyncio
import json
import time
import random
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import aiohttp
from dataclasses import dataclass

@dataclass
class ValidationResult:
    vulnerability: str
    is_valid: bool
    confidence: float
    validation_method: str
    timestamp: datetime
    details: Dict[str, Any]
    exploitation_success: bool = False
    exploitation_details: Optional[Dict[str, Any]] = None

class RealTimeValidator:
    """Real-time vulnerability validation with active exploitation testing"""
    
    def __init__(self):
        self.validation_results = []
        self.active_sessions = {}
        self.validation_methods = {
            'active_exploitation': self._validate_with_exploitation,
            'behavioral_analysis': self._validate_with_behavior,
            'response_analysis': self._validate_with_response,
            'timing_analysis': self._validate_with_timing,
            'differential_testing': self._validate_with_differential
        }
        
    async def validate_vulnerability(self, target_url: str, vulnerability_info: Dict[str, Any]) -> ValidationResult:
        """Validate vulnerability with real-time testing"""
        start_time = time.time()
        
        print(f"🔍 Validating vulnerability: {vulnerability_info.get('type', 'unknown')}")
        print(f"🎯 Target: {target_url}")
        
        validation_methods = self._select_validation_methods(vulnerability_info)
        
        best_result = None
        best_confidence = 0.0
        
        for method in validation_methods:
            try:
                result = await self.validation_methods[method](target_url, vulnerability_info)
                
                if result.confidence > best_confidence:
                    best_result = result
                    best_confidence = result.confidence
                
                if result.confidence >= 0.8:  # High confidence threshold
                    break
                    
            except Exception as e:
                print(f"⚠️ Validation method {method} failed: {e}")
                continue
        
        validation_time = time.time() - start_time
        
        if best_result:
            best_result.details['validation_time'] = validation_time
            best_result.details['methods_tried'] = validation_methods
            
            # Test exploitation if vulnerability is valid
            if best_result.is_valid and best_result.confidence >= 0.7:
                exploitation_result = await self._test_exploitation(target_url, vulnerability_info)
                best_result.exploitation_success = exploitation_result.get('success', False)
                best_result.exploitation_details = exploitation_result
            
            self.validation_results.append(best_result)
            
        return best_result or ValidationResult(
            vulnerability=vulnerability_info.get('type', 'unknown'),
            is_valid=False,
            confidence=0.0,
            validation_method='none',
            timestamp=datetime.now(),
            details={'error': 'All validation methods failed'}
        )
    
    def _select_validation_methods(self, vulnerability_info: Dict[str, Any]) -> List[str]:
        """Select appropriate validation methods based on vulnerability type"""
        vuln_type = vulnerability_info.get('type', '').lower()
        
        method_mapping = {
            'ssrf': ['active_exploitation', 'response_analysis', 'timing_analysis'],
            'xss': ['active_exploitation', 'behavioral_analysis', 'response_analysis'],
            'cors': ['active_exploitation', 'response_analysis', 'differential_testing'],
            'csrf': ['active_exploitation', 'behavioral_analysis', 'differential_testing'],
            'sqli': ['active_exploitation', 'timing_analysis', 'differential_testing'],
            'rce': ['active_exploitation', 'behavioral_analysis', 'timing_analysis'],
            'web3': ['active_exploitation', 'behavioral_analysis', 'response_analysis'],
            'default': ['active_exploitation', 'response_analysis', 'differential_testing']
        }
        
        for key, methods in method_mapping.items():
            if key in vuln_type:
                return methods
        
        return method_mapping['default']
    
    async def _validate_with_exploitation(self, target_url: str, vulnerability_info: Dict[str, Any]) -> ValidationResult:
        """Validate by attempting actual exploitation"""
        print("🚀 Testing active exploitation...")
        
        vuln_type = vulnerability_info.get('type', '').lower()
        
        # Exploitation payloads based on vulnerability type
        exploitation_map = {
            'ssrf': self._exploit_ssrf,
            'xss': self._exploit_xss,
            'cors': self._exploit_cors,
            'web3': self._exploit_web3
        }
        
        exploit_func = exploitation_map.get(vuln_type, self._exploit_generic)
        
        try:
            result = await exploit_func(target_url, vulnerability_info)
            
            return ValidationResult(
                vulnerability=vulnerability_info.get('type', 'unknown'),
                is_valid=result.get('success', False),
                confidence=result.get('confidence', 0.0),
                validation_method='active_exploitation',
                timestamp=datetime.now(),
                details=result
            )
            
        except Exception as e:
            return ValidationResult(
                vulnerability=vulnerability_info.get('type', 'unknown'),
                is_valid=False,
                confidence=0.0,
                validation_method='active_exploitation',
                timestamp=datetime.now(),
                details={'error': str(e)}
            )
    
    async def _validate_with_behavior(self, target_url: str, vulnerability_info: Dict[str, Any]) -> ValidationResult:
        """Validate by analyzing system behavior"""
        print("🔬 Analyzing system behavior...")
        
        try:
            # Test normal behavior vs suspicious behavior
            normal_response = await self._make_request(target_url, {'headers': {'User-Agent': 'Mozilla/5.0'}})
            suspicious_response = await self._make_request(target_url, {
                'headers': {
                    'User-Agent': 'Mozilla/5.0',
                    'X-Forwarded-For': '127.0.0.1',
                    'Referer': target_url
                }
            })
            
            # Compare responses
            behavior_score = self._analyze_behavior_differences(normal_response, suspicious_response)
            
            return ValidationResult(
                vulnerability=vulnerability_info.get('type', 'unknown'),
                is_valid=behavior_score > 0.6,
                confidence=min(behavior_score, 1.0),
                validation_method='behavioral_analysis',
                timestamp=datetime.now(),
                details={
                    'behavior_score': behavior_score,
                    'response_differences': self._extract_differences(normal_response, suspicious_response)
                }
            )
            
        except Exception as e:
            return ValidationResult(
                vulnerability=vulnerability_info.get('type', 'unknown'),
                is_valid=False,
                confidence=0.0,
                validation_method='behavioral_analysis',
                timestamp=datetime.now(),
                details={'error': str(e)}
            )
    
    async def _validate_with_response(self, target_url: str, vulnerability_info: Dict[str, Any]) -> ValidationResult:
        """Validate by analyzing response patterns"""
        print("📊 Analyzing response patterns...")
        
        try:
            # Make test request with vulnerability-specific payload
            payload = vulnerability_info.get('payload', '')
            test_url = f"{target_url}{payload}"
            
            response = await self._make_request(test_url, {})
            
            # Analyze response for vulnerability indicators
            indicators = self._analyze_response_indicators(response, vulnerability_info)
            
            confidence = self._calculate_response_confidence(indicators)
            
            return ValidationResult(
                vulnerability=vulnerability_info.get('type', 'unknown'),
                is_valid=confidence > 0.5,
                confidence=confidence,
                validation_method='response_analysis',
                timestamp=datetime.now(),
                details={
                    'indicators': indicators,
                    'response_status': response.get('status', 0),
                    'response_headers': response.get('headers', {})
                }
            )
            
        except Exception as e:
            return ValidationResult(
                vulnerability=vulnerability_info.get('type', 'unknown'),
                is_valid=False,
                confidence=0.0,
                validation_method='response_analysis',
                timestamp=datetime.now(),
                details={'error': str(e)}
            )
    
    async def _validate_with_timing(self, target_url: str, vulnerability_info: Dict[str, Any]) -> ValidationResult:
        """Validate by analyzing timing differences"""
        print("⏱️ Analyzing timing patterns...")
        
        try:
            # Measure normal response time
            normal_times = []
            for _ in range(3):
                start = time.time()
                await self._make_request(target_url, {})
                normal_times.append(time.time() - start)
            
            # Measure suspicious request time
            payload = vulnerability_info.get('payload', '')
            test_url = f"{target_url}{payload}"
            
            suspicious_times = []
            for _ in range(3):
                start = time.time()
                await self._make_request(test_url, {})
                suspicious_times.append(time.time() - start)
            
            # Compare timing
            avg_normal = sum(normal_times) / len(normal_times)
            avg_suspicious = sum(suspicious_times) / len(suspicious_times)
            
            timing_diff = abs(avg_suspicious - avg_normal) / max(avg_normal, 0.001)
            
            return ValidationResult(
                vulnerability=vulnerability_info.get('type', 'unknown'),
                is_valid=timing_diff > 0.5,  # 50% slower indicates potential vulnerability
                confidence=min(timing_diff, 1.0),
                validation_method='timing_analysis',
                timestamp=datetime.now(),
                details={
                    'normal_time': avg_normal,
                    'suspicious_time': avg_suspicious,
                    'timing_difference': timing_diff
                }
            )
            
        except Exception as e:
            return ValidationResult(
                vulnerability=vulnerability_info.get('type', 'unknown'),
                is_valid=False,
                confidence=0.0,
                validation_method='timing_analysis',
                timestamp=datetime.now(),
                details={'error': str(e)}
            )
    
    async def _validate_with_differential(self, target_url: str, vulnerability_info: Dict[str, Any]) -> ValidationResult:
        """Validate using differential testing"""
        print("🔍 Performing differential testing...")
        
        try:
            # Test with different user agents/contexts
            test_requests = [
                {'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}},
                {'headers': {'User-Agent': 'curl/7.68.0'}},
                {'headers': {'User-Agent': 'Python/3.9 aiohttp'}},
                {'headers': {'User-Agent': 'Mozilla/5.0', 'X-Forwarded-For': '192.168.1.1'}},
            ]
            
            responses = []
            for req_config in test_requests:
                response = await self._make_request(target_url, req_config)
                responses.append(response)
            
            # Analyze differences
            diff_score = self._calculate_differential_score(responses)
            
            return ValidationResult(
                vulnerability=vulnerability_info.get('type', 'unknown'),
                is_valid=diff_score > 0.3,
                confidence=min(diff_score, 1.0),
                validation_method='differential_testing',
                timestamp=datetime.now(),
                details={
                    'differential_score': diff_score,
                    'response_variations': len([r for r in responses if r.get('status') != 200])
                }
            )
            
        except Exception as e:
            return ValidationResult(
                vulnerability=vulnerability_info.get('type', 'unknown'),
                is_valid=False,
                confidence=0.0,
                validation_method='differential_testing',
                timestamp=datetime.now(),
                details={'error': str(e)}
            )
    
    async def _make_request(self, url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Make HTTP request with given configuration"""
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                method = config.get('method', 'GET')
                headers = config.get('headers', {})
                data = config.get('data', {})
                
                async with session.request(method, url, headers=headers, json=data) as response:
                    return {
                        'status': response.status,
                        'headers': dict(response.headers),
                        'text': await response.text(),
                        'url': str(response.url)
                    }
        except Exception as e:
            return {'error': str(e), 'status': 0}
    
    async def _test_exploitation(self, target_url: str, vulnerability_info: Dict[str, Any]) -> Dict[str, Any]:
        """Test actual exploitation of validated vulnerability"""
        print("💥 Testing actual exploitation...")
        
        try:
            # Simulate exploitation based on vulnerability type
            vuln_type = vulnerability_info.get('type', '').lower()
            
            if 'ssrf' in vuln_type:
                return await self._exploit_ssrf(target_url, vulnerability_info)
            elif 'xss' in vuln_type:
                return await self._exploit_xss(target_url, vulnerability_info)
            elif 'cors' in vuln_type:
                return await self._exploit_cors(target_url, vulnerability_info)
            elif 'web3' in vuln_type:
                return await self._exploit_web3(target_url, vulnerability_info)
            else:
                return await self._exploit_generic(target_url, vulnerability_info)
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # Exploitation methods
    async def _exploit_ssrf(self, target_url: str, vuln_info: Dict[str, Any]) -> Dict[str, Any]:
        """Exploit SSRF vulnerability"""
        try:
            # Test SSRF with internal service access
            test_payloads = [
                '/api/_nextjs_static_data',
                '/api/config',
                '/api/_nextjs_build_manifest'
            ]
            
            for payload in test_payloads:
                test_url = f"{target_url}{payload}"
                response = await self._make_request(test_url, {})
                
                if response.get('status') == 200 and 'error' not in response:
                    return {
                        'success': True,
                        'confidence': 0.9,
                        'exploit_type': 'ssrf',
                        'payload': payload,
                        'response_size': len(response.get('text', '')),
                        'details': 'Successfully accessed internal resource'
                    }
            
            return {'success': False, 'confidence': 0.0}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _exploit_xss(self, target_url: str, vuln_info: Dict[str, Any]) -> Dict[str, Any]:
        """Exploit XSS vulnerability"""
        try:
            # Test XSS payloads
            xss_payloads = [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                'javascript:alert("XSS")'
            ]
            
            for payload in xss_payloads:
                test_url = f"{target_url}?q={payload}"
                response = await self._make_request(test_url, {})
                
                if payload in response.get('text', ''):
                    return {
                        'success': True,
                        'confidence': 0.8,
                        'exploit_type': 'xss',
                        'payload': payload,
                        'details': 'XSS payload reflected in response'
                    }
            
            return {'success': False, 'confidence': 0.0}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _exploit_cors(self, target_url: str, vuln_info: Dict[str, Any]) -> Dict[str, Any]:
        """Exploit CORS misconfiguration"""
        try:
            # Test CORS with different origins
            test_origins = ['https://evil.com', 'https://malicious.org', 'null']
            
            for origin in test_origins:
                headers = {'Origin': origin}
                response = await self._make_request(target_url, {'headers': headers})
                
                cors_header = response.get('headers', {}).get('Access-Control-Allow-Origin', '')
                if cors_header == origin or cors_header == '*':
                    return {
                        'success': True,
                        'confidence': 0.9,
                        'exploit_type': 'cors',
                        'origin': origin,
                        'cors_header': cors_header,
                        'details': 'CORS misconfiguration allows arbitrary origins'
                    }
            
            return {'success': False, 'confidence': 0.0}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _exploit_web3(self, target_url: str, vuln_info: Dict[str, Any]) -> Dict[str, Any]:
        """Exploit Web3 vulnerability"""
        try:
            # Test Web3-specific exploits
            test_payloads = [
                '0x1234567890abcdef',  # Fake transaction hash
                '{"method":"eth_sendTransaction","params":[{"from":"0x123...","to":"0x456...","value":"0x0"}]}',
                'window.ethereum.request({method: "eth_requestAccounts"})'
            ]
            
            for payload in test_payloads:
                test_url = f"{target_url}?data={payload}"
                response = await self._make_request(test_url, {})
                
                if 'transaction' in response.get('text', '').lower() or 'wallet' in response.get('text', '').lower():
                    return {
                        'success': True,
                        'confidence': 0.8,
                        'exploit_type': 'web3',
                        'payload': payload,
                        'details': 'Web3 vulnerability triggered'
                    }
            
            return {'success': False, 'confidence': 0.0}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _exploit_generic(self, target_url: str, vuln_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generic exploitation method"""
        try:
            payload = vuln_info.get('payload', '')
            test_url = f"{target_url}{payload}"
            response = await self._make_request(test_url, {})
            
            return {
                'success': response.get('status', 0) != 404,
                'confidence': 0.5,
                'exploit_type': 'generic',
                'payload': payload,
                'status': response.get('status', 0)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _analyze_behavior_differences(self, normal: Dict[str, Any], suspicious: Dict[str, Any]) -> float:
        """Analyze behavioral differences between responses"""
        score = 0.0
        
        # Status code differences
        if normal.get('status') != suspicious.get('status'):
            score += 0.3
        
        # Response length differences
        normal_len = len(normal.get('text', ''))
        suspicious_len = len(suspicious.get('text', ''))
        if abs(normal_len - suspicious_len) > 100:
            score += 0.2
        
        # Header differences
        normal_headers = set(normal.get('headers', {}).keys())
        suspicious_headers = set(suspicious.get('headers', {}).keys())
        if normal_headers != suspicious_headers:
            score += 0.2
        
        return min(score, 1.0)
    
    def _extract_differences(self, normal: Dict[str, Any], suspicious: Dict[str, Any]) -> Dict[str, Any]:
        """Extract differences between responses"""
        differences = {}
        
        if normal.get('status') != suspicious.get('status'):
            differences['status_code'] = {
                'normal': normal.get('status'),
                'suspicious': suspicious.get('status')
            }
        
        if normal.get('text') != suspicious.get('text'):
            differences['content'] = True
        
        return differences
    
    def _analyze_response_indicators(self, response: Dict[str, Any], vuln_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze response for vulnerability indicators"""
        indicators = {}
        
        text = response.get('text', '').lower()
        status = response.get('status', 0)
        headers = response.get('headers', {})
        
        # Error messages
        error_indicators = ['error', 'exception', 'traceback', 'stack', 'debug']
        indicators['error_messages'] = sum(1 for indicator in error_indicators if indicator in text)
        
        # Information disclosure
        info_indicators = ['password', 'secret', 'key', 'token', 'config', 'internal']
        indicators['info_disclosure'] = sum(1 for indicator in info_indicators if indicator in text)
        
        # Success indicators
        if status == 200:
            indicators['success_status'] = True
        
        # Security headers
        security_headers = ['content-security-policy', 'x-frame-options', 'x-content-type-options']
        indicators['missing_security_headers'] = sum(1 for header in security_headers if header not in headers)
        
        return indicators
    
    def _calculate_response_confidence(self, indicators: Dict[str, Any]) -> float:
        """Calculate confidence based on response indicators"""
        confidence = 0.0
        
        # Error messages increase confidence
        confidence += min(indicators.get('error_messages', 0) * 0.2, 0.4)
        
        # Information disclosure increases confidence
        confidence += min(indicators.get('info_disclosure', 0) * 0.3, 0.6)
        
        # Success status
        if indicators.get('success_status'):
            confidence += 0.2
        
        # Missing security headers
        confidence += min(indicators.get('missing_security_headers', 0) * 0.1, 0.3)
        
        return min(confidence, 1.0)
    
    def _calculate_differential_score(self, responses: List[Dict[str, Any]]) -> float:
        """Calculate differential testing score"""
        if len(responses) < 2:
            return 0.0
        
        score = 0.0
        status_codes = [r.get('status', 0) for r in responses]
        
        # Status code variation
        if len(set(status_codes)) > 1:
            score += 0.4
        
        # Response size variation
        sizes = [len(r.get('text', '')) for r in responses]
        if max(sizes) - min(sizes) > 500:
            score += 0.3
        
        # Header variation
        header_sets = [set(r.get('headers', {}).keys()) for r in responses]
        if len(set(tuple(sorted(headers)) for headers in header_sets)) > 1:
            score += 0.3
        
        return min(score, 1.0)
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """Get summary of all validation results"""
        if not self.validation_results:
            return {'total': 0, 'valid': 0, 'invalid': 0, 'exploitable': 0}
        
        total = len(self.validation_results)
        valid = sum(1 for r in self.validation_results if r.is_valid)
        exploitable = sum(1 for r in self.validation_results if r.exploitation_success)
        
        return {
            'total': total,
            'valid': valid,
            'invalid': total - valid,
            'exploitable': exploitable,
            'success_rate': valid / total if total > 0 else 0,
            'exploitation_rate': exploitable / total if total > 0 else 0
        }