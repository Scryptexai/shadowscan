#!/usr/bin/env python3
"""
Web Application Layer Testing Module
Comprehensive web application security testing for claim websites and DEX platforms
"""

import asyncio
import aiohttp
import re
import json
import base64
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from dataclasses import dataclass
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class WebVulnerability:
    vulnerability_type: str
    severity: str
    description: str
    endpoint: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    request_data: Optional[Dict[str, Any]] = None
    response_data: Optional[Dict[str, Any]] = None

@dataclass
class FormAnalysis:
    form_id: Optional[str]
    action: str
    method: str
    inputs: List[Dict[str, Any]]
    is_claim_form: bool
    potential_vulnerabilities: List[WebVulnerability]

@dataclass
class WebAnalysisResult:
    target_url: str
    technology_stack: Dict[str, Any]
    forms: List[FormAnalysis]
    api_endpoints: List[str]
    vulnerabilities: List[WebVulnerability]
    security_headers: Dict[str, str]
    session_info: Dict[str, Any]
    javascript_analysis: Dict[str, Any]
    cookies: List[Dict[str, Any]]

class WebApplicationTester:
    def __init__(self):
        self.session = None
        self.vulnerabilities = []
        self.technology_signatures = {
            'react': r'react|jsx|__NEXT_DATA__',
            'vue': r'vue|vuex|__vue__',
            'angular': r'angular|ng-app|__zone_symbol__',
            'blockchain': r'web3|ethers|ethereum|tron|bsc|polygon',
            'wallet': r'metamask|trustwallet|walletconnect',
            'claim': r'claim|airdrop|faucet|reward',
            'defi': r'defi|dex|swap|liquidity|farming',
            'web3': r'web3\.js|ethers\.js|tronweb'
        }
        
        self.security_headers_required = {
            'Content-Security-Policy': 'Missing Content Security Policy',
            'X-Frame-Options': 'Missing X-Frame-Options',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options',
            'X-XSS-Protection': 'Missing XSS Protection',
            'Strict-Transport-Security': 'Missing HSTS',
            'Referrer-Policy': 'Missing Referrer Policy'
        }
        
        self.sql_injection_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR SLEEP(5)--"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>"
        ]
        
        self.file_inclusion_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "/etc/passwd%00",
            "file:///etc/passwd"
        ]

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            },
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def analyze_web_application(self, target_url: str) -> WebAnalysisResult:
        logger.info(f"🌐 Starting comprehensive web analysis for: {target_url}")
        
        # Layer 1: Basic Analysis
        basic_info = await self._analyze_basic_info(target_url)
        
        # Layer 2: Technology Detection
        technology_stack = await self._detect_technology(target_url, basic_info['content'])
        
        # Layer 3: Form Analysis
        forms = await self._analyze_forms(target_url, basic_info['soup'])
        
        # Layer 4: API Endpoint Discovery
        api_endpoints = await self._discover_api_endpoints(target_url, basic_info['content'])
        
        # Layer 5: Security Headers Analysis
        security_headers = await self._analyze_security_headers(basic_info['headers'])
        
        # Layer 6: JavaScript Analysis
        js_analysis = await self._analyze_javascript(target_url, basic_info['content'])
        
        # Layer 7: Vulnerability Testing
        vulnerabilities = await self._test_vulnerabilities(target_url, forms, api_endpoints)
        
        return WebAnalysisResult(
            target_url=target_url,
            technology_stack=technology_stack,
            forms=forms,
            api_endpoints=api_endpoints,
            vulnerabilities=vulnerabilities,
            security_headers=security_headers,
            session_info=basic_info['session_info'],
            javascript_analysis=js_analysis,
            cookies=basic_info['cookies']
        )

    async def _analyze_basic_info(self, url: str) -> Dict[str, Any]:
        try:
            async with self.session.get(url) as response:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                return {
                    'status_code': response.status,
                    'headers': dict(response.headers),
                    'content': content,
                    'soup': soup,
                    'cookies': [
                        {'name': cookie.key, 'value': cookie.value, 'domain': cookie['domain']}
                        for cookie in response.cookies.values()
                    ],
                    'session_info': {
                        'is_https': url.startswith('https'),
                        'content_type': response.headers.get('content-type', ''),
                        'content_length': len(content),
                        'encoding': response.encoding or 'utf-8'
                    }
                }
        except Exception as e:
            logger.error(f"Error analyzing basic info: {e}")
            return {
                'status_code': 0,
                'headers': {},
                'content': '',
                'soup': None,
                'cookies': [],
                'session_info': {
                    'is_https': url.startswith('https'),
                    'content_type': '',
                    'content_length': 0,
                    'encoding': 'utf-8'
                }
            }

    async def _detect_technology(self, url: str, content: str) -> Dict[str, Any]:
        detected = {
            'frameworks': [],
            'libraries': [],
            'blockchain_related': False,
            'claim_related': False,
            'defi_related': False,
            'web3_integration': False,
            'wallet_integration': False
        }
        
        # Analyze content for technology signatures
        for tech, pattern in self.technology_signatures.items():
            if re.search(pattern, content, re.IGNORECASE):
                if tech in ['react', 'vue', 'angular']:
                    detected['frameworks'].append(tech)
                elif tech in ['blockchain', 'web3']:
                    detected[tech + '_related'] = True
                elif tech == 'wallet':
                    detected['wallet_integration'] = True
                elif tech == 'claim':
                    detected['claim_related'] = True
                elif tech == 'defi':
                    detected['defi_related'] = True
        
        # Check for blockchain-related patterns
        blockchain_patterns = [
            r'0x[a-fA-F0-9]{40}',  # Ethereum address
            r'bscscan|etherscan|polygonscan',  # Block explorers
            r'web3\.provider|ethers\.provider',  # Web3 providers
            r'connect|disconnect|wallet',  # Wallet functions
        ]
        
        for pattern in blockchain_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                detected['blockchain_related'] = True
                detected['web3_integration'] = True
                break
        
        return detected

    async def _analyze_forms(self, url: str, soup: BeautifulSoup) -> List[FormAnalysis]:
        forms = []
        if not soup:
            return forms
            
        for form in soup.find_all('form'):
            try:
                form_analysis = await self._analyze_single_form(url, form)
                forms.append(form_analysis)
            except Exception as e:
                logger.error(f"Error analyzing form: {e}")
        
        return forms

    async def _analyze_single_form(self, base_url: str, form) -> FormAnalysis:
        action = form.get('action', '')
        if not action.startswith(('http://', 'https://')):
            action = urljoin(base_url, action)
        
        method = form.get('method', 'get').upper()
        form_id = form.get('id')
        
        inputs = []
        for input_field in form.find_all(['input', 'select', 'textarea']):
            input_info = {
                'name': input_field.get('name', ''),
                'type': input_field.get('type', 'text'),
                'value': input_field.get('value', ''),
                'required': input_field.has_attr('required'),
                'placeholder': input_field.get('placeholder', ''),
                'pattern': input_field.get('pattern', '')
            }
            inputs.append(input_info)
        
        # Check if this is a claim form
        claim_indicators = ['claim', 'airdrop', 'faucet', 'reward', 'mint', 'withdraw']
        is_claim_form = any(
            indicator in action.lower() or 
            indicator in form_id.lower() if form_id else False or
            any(indicator in inp.get('name', '').lower() for inp in inputs)
            for indicator in claim_indicators
        )
        
        # Analyze form for vulnerabilities
        vulnerabilities = await self._analyze_form_vulnerabilities(action, method, inputs)
        
        return FormAnalysis(
            form_id=form_id,
            action=action,
            method=method,
            inputs=inputs,
            is_claim_form=is_claim_form,
            potential_vulnerabilities=vulnerabilities
        )

    async def _analyze_form_vulnerabilities(self, action: str, method: str, inputs: List[Dict[str, Any]]) -> List[WebVulnerability]:
        vulnerabilities = []
        
        # Check for CSRF protection
        has_csrf_token = any(
            input_field['name'].lower() in ['csrf_token', 'csrfmiddlewaretoken', '_token', 'authenticity_token']
            for input_field in inputs
        )
        
        if not has_csrf_token and method in ['POST', 'PUT', 'DELETE']:
            vulnerabilities.append(WebVulnerability(
                vulnerability_type='CSRF',
                severity='MEDIUM',
                description='Form missing CSRF protection',
                endpoint=action,
                parameter='CSRF Token'
            ))
        
        # Check for sensitive data transmission
        sensitive_fields = ['password', 'private_key', 'mnemonic', 'seed', 'wallet']
        has_sensitive_data = any(
            sensitive_field in input_field['name'].lower()
            for input_field in inputs
            for sensitive_field in sensitive_fields
        )
        
        if has_sensitive_data and not action.startswith('https://'):
            vulnerabilities.append(WebVulnerability(
                vulnerability_type='Insecure Data Transmission',
                severity='HIGH',
                description='Sensitive data transmitted over unencrypted connection',
                endpoint=action,
                parameter='HTTPS'
            ))
        
        return vulnerabilities

    async def _discover_api_endpoints(self, base_url: str, content: str) -> List[str]:
        endpoints = []
        
        # Extract API endpoints from JavaScript
        js_patterns = [
            r'fetch\([\'"]([^\'"]+)[\'"]',
            r'\.get\([\'"]([^\'"]+)[\'"]',
            r'\.post\([\'"]([^\'"]+)[\'"]',
            r'axios\.[a-z]+\([\'"]([^\'"]+)[\'"]',
            r'api/[a-zA-Z0-9_/-]+',
            r'/v[0-9]+/[a-zA-Z0-9_/-]+',
            r'rpc/[a-zA-Z0-9_/-]+',
            r'contract/[a-zA-Z0-9_/-]+',
            r'web3/[a-zA-Z0-9_/-]+'
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match.startswith(('http://', 'https://')):
                    endpoints.append(match)
                else:
                    endpoints.append(urljoin(base_url, match))
        
        # Common API endpoints for claim/DEX websites
        common_endpoints = [
            '/api/user',
            '/api/claim',
            '/api/balance',
            '/api/transaction',
            '/api/contract',
            '/api/wallet',
            '/api/airdrop',
            '/api/reward',
            '/web3/contract',
            '/web3/transaction'
        ]
        
        for endpoint in common_endpoints:
            full_endpoint = urljoin(base_url, endpoint)
            endpoints.append(full_endpoint)
        
        return list(set(endpoints))  # Remove duplicates

    async def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        security_headers = {}
        
        for header, description in self.security_headers_required.items():
            if header not in headers:
                security_headers[header] = f"MISSING - {description}"
            else:
                security_headers[header] = f"PRESENT - {headers[header]}"
        
        return security_headers

    async def _analyze_javascript(self, url: str, content: str) -> Dict[str, Any]:
        analysis = {
            'external_scripts': [],
            'inline_scripts': 0,
            'web3_detected': False,
            'sensitive_functions': [],
            'potential_backdoors': []
        }
        
        # Find external scripts
        soup = BeautifulSoup(content, 'html.parser')
        for script in soup.find_all('script'):
            if script.get('src'):
                analysis['external_scripts'].append(script.get('src'))
            else:
                analysis['inline_scripts'] += 1
                
                # Analyze inline scripts for sensitive content
                script_content = script.string or ''
                if re.search(r'web3|ethers|ethereum|tron|bsc', script_content, re.IGNORECASE):
                    analysis['web3_detected'] = True
                
                # Look for potential backdoors
                backdoor_patterns = [
                    r'eval\s*\(',
                    r'document\.write\s*\(',
                    r'innerHTML\s*=',
                    r'atob\s*\(',
                    r'localStorage\s*\.'
                ]
                
                for pattern in backdoor_patterns:
                    if re.search(pattern, script_content, re.IGNORECASE):
                        analysis['potential_backdoors'].append(pattern)
        
        return analysis

    async def _test_vulnerabilities(self, base_url: str, forms: List[FormAnalysis], api_endpoints: List[str]) -> List[WebVulnerability]:
        vulnerabilities = []
        
        # Test forms for vulnerabilities
        for form in forms:
            if form.is_claim_form:
                form_vulns = await self._test_form_vulnerabilities(form)
                vulnerabilities.extend(form_vulns)
        
        # Test API endpoints for vulnerabilities
        for endpoint in api_endpoints[:10]:  # Limit to avoid excessive requests
            try:
                api_vulns = await self._test_api_vulnerabilities(endpoint)
                vulnerabilities.extend(api_vulns)
            except Exception as e:
                logger.error(f"Error testing API endpoint {endpoint}: {e}")
        
        return vulnerabilities

    async def _test_form_vulnerabilities(self, form: FormAnalysis) -> List[WebVulnerability]:
        vulnerabilities = []
        
        # Test SQL Injection
        if form.method == 'POST':
            for payload in self.sql_injection_payloads[:3]:  # Limit payloads
                try:
                    test_data = {}
                    for input_field in form.inputs:
                        if input_field['type'] not in ['submit', 'button']:
                            test_data[input_field['name']] = payload
                    
                    async with self.session.post(form.action, data=test_data) as response:
                        content = await response.text()
                        if any(error in content.lower() for error in ['sql', 'mysql', 'postgresql', 'syntax error']):
                            vulnerabilities.append(WebVulnerability(
                                vulnerability_type='SQL Injection',
                                severity='HIGH',
                                description='Potential SQL injection vulnerability detected',
                                endpoint=form.action,
                                payload=payload
                            ))
                            break
                except Exception as e:
                    logger.debug(f"SQL injection test failed: {e}")
        
        # Test XSS
        if form.method == 'POST':
            for payload in self.xss_payloads[:2]:  # Limit payloads
                try:
                    test_data = {}
                    for input_field in form.inputs:
                        if input_field['type'] not in ['submit', 'button']:
                            test_data[input_field['name']] = payload
                    
                    async with self.session.post(form.action, data=test_data) as response:
                        content = await response.text()
                        if payload.lower() in content.lower():
                            vulnerabilities.append(WebVulnerability(
                                vulnerability_type='XSS',
                                severity='HIGH',
                                description='Cross-site scripting vulnerability detected',
                                endpoint=form.action,
                                payload=payload
                            ))
                            break
                except Exception as e:
                    logger.debug(f"XSS test failed: {e}")
        
        return vulnerabilities

    async def _test_api_vulnerabilities(self, endpoint: str) -> List[WebVulnerability]:
        vulnerabilities = []
        
        # Test for information disclosure
        try:
            async with self.session.get(endpoint) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Check for sensitive information exposure
                    sensitive_patterns = [
                        r'private_key|mnemonic|seed|password',
                        r'api_key|secret|token',
                        r'0x[a-fA-F0-9]{40}',  # Ethereum addresses
                        r'[a-fA-F0-9]{32}'  # Potential hashes/keys
                    ]
                    
                    for pattern in sensitive_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            vulnerabilities.append(WebVulnerability(
                                vulnerability_type='Information Disclosure',
                                severity='MEDIUM',
                                description='Potential sensitive information exposure',
                                endpoint=endpoint
                            ))
                            break
        except Exception as e:
            logger.debug(f"API endpoint test failed: {e}")
        
        return vulnerabilities

    async def generate_report(self, analysis_result: WebAnalysisResult) -> Dict[str, Any]:
        report = {
            'analysis_summary': {
                'target_url': analysis_result.target_url,
                'total_vulnerabilities': len(analysis_result.vulnerabilities),
                'high_severity': len([v for v in analysis_result.vulnerabilities if v.severity == 'HIGH']),
                'medium_severity': len([v for v in analysis_result.vulnerabilities if v.severity == 'MEDIUM']),
                'low_severity': len([v for v in analysis_result.vulnerabilities if v.severity == 'LOW']),
                'is_claim_related': analysis_result.technology_stack['claim_related'],
                'has_blockchain_integration': analysis_result.technology_stack['blockchain_related']
            },
            'technology_stack': analysis_result.technology_stack,
            'forms_analysis': [
                {
                    'form_id': form.form_id,
                    'action': form.action,
                    'method': form.method,
                    'is_claim_form': form.is_claim_form,
                    'input_count': len(form.inputs),
                    'vulnerabilities': len(form.potential_vulnerabilities)
                }
                for form in analysis_result.forms
            ],
            'api_endpoints': analysis_result.api_endpoints[:20],  # Limit for readability
            'security_headers': analysis_result.security_headers,
            'vulnerabilities': [
                {
                    'type': vuln.vulnerability_type,
                    'severity': vuln.severity,
                    'description': vuln.description,
                    'endpoint': vuln.endpoint,
                    'parameter': vuln.parameter,
                    'payload': vuln.payload
                }
                for vuln in analysis_result.vulnerabilities
            ],
            'javascript_analysis': analysis_result.javascript_analysis,
            'recommendations': self._generate_recommendations(analysis_result)
        }
        
        return report

    def _generate_recommendations(self, analysis_result: WebAnalysisResult) -> List[str]:
        recommendations = []
        
        # Security headers recommendations
        missing_headers = [
            header for header, status in analysis_result.security_headers.items()
            if status.startswith('MISSING')
        ]
        
        if missing_headers:
            recommendations.append(f"Implement missing security headers: {', '.join(missing_headers)}")
        
        # Vulnerability-specific recommendations
        high_vulns = [v for v in analysis_result.vulnerabilities if v.severity == 'HIGH']
        if high_vulns:
            recommendations.append(f"Address {len(high_vulns)} high-severity vulnerabilities immediately")
        
        # Blockchain-specific recommendations
        if analysis_result.technology_stack['blockchain_related']:
            recommendations.append("Implement additional security measures for blockchain integration")
            recommendations.append("Validate all smart contract interactions")
        
        # Claim form recommendations
        claim_forms = [f for f in analysis_result.forms if f.is_claim_form]
        if claim_forms:
            recommendations.append("Implement rate limiting for claim forms")
            recommendations.append("Add CAPTCHA to prevent automated abuse")
        
        return recommendations

async def test_web_application(target_url: str) -> Dict[str, Any]:
    async with WebApplicationTester() as tester:
        analysis_result = await tester.analyze_web_application(target_url)
        report = await tester.generate_report(analysis_result)
        return report

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        
        async def run_test():
            result = await test_web_application(target_url)
            print(json.dumps(result, indent=2))
        
        asyncio.run(run_test())
    else:
        print("Usage: python web_application_tester.py <target_url>")