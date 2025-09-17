#!/usr/bin/env python3
"""
API Endpoint Discovery and Testing Module
Comprehensive API security testing for claim websites and DEX platforms
"""

import asyncio
import aiohttp
import json
import re
import base64
import hashlib
import hmac
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass
import logging
from pathlib import Path
import time
import random

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class APIEndpoint:
    url: str
    method: str
    parameters: List[Dict[str, Any]]
    headers: Dict[str, str]
    content_type: str
    authentication_required: bool
    rate_limiting: bool
    description: str

@dataclass
class APIVulnerability:
    vulnerability_type: str
    severity: str
    description: str
    endpoint: str
    method: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    request_data: Optional[Dict[str, Any]] = None
    response_data: Optional[Dict[str, Any]] = None

@dataclass
class APIAnalysisResult:
    target_url: str
    endpoints_discovered: List[APIEndpoint]
    vulnerabilities: List[APIVulnerability]
    authentication_flaws: List[APIVulnerability]
    rate_limiting_info: Dict[str, Any]
    cors_policy: Dict[str, Any]
    api_security_headers: Dict[str, str]
    business_logic_flaws: List[APIVulnerability]

class APIEndpointTester:
    def __init__(self):
        self.session = None
        self.vulnerabilities = []
        self.discovered_endpoints = []
        
        # Common API endpoints for claim/DEX websites
        self.common_endpoints = [
            '/api/user',
            '/api/claim',
            '/api/balance',
            '/api/transaction',
            '/api/contract',
            '/api/wallet',
            '/api/airdrop',
            '/api/reward',
            '/api/withdraw',
            '/api/deposit',
            '/api/stake',
            '/api/unstake',
            '/api/approve',
            '/api/allowance',
            '/api/pool',
            '/api/liquidity',
            '/api/swap',
            '/api/price',
            '/api/quote',
            '/api/route',
            '/api/nft',
            '/api/collection',
            '/api/metadata',
            '/api/chain',
            '/api/block',
            '/api/gas',
            '/api/estimate',
            '/api/signature',
            '/api/verify',
            '/api/nonce',
            '/api/auth',
            '/api/login',
            '/api/logout',
            '/api/register',
            '/api/refresh',
            '/web3/contract',
            '/web3/transaction',
            '/web3/account',
            '/web3/sign',
            '/web3/verify',
            '/rpc/eth_call',
            '/rpc/eth_sendTransaction',
            '/rpc/eth_estimateGas',
            '/rpc/personal_sign',
            '/rpc/eth_chainId'
        ]
        
        # Authentication test payloads
        self.auth_test_payloads = {
            'broken_auth': [
                {'username': 'admin', 'password': 'admin'},
                {'username': 'user', 'password': 'password'},
                {'username': 'test', 'password': 'test123'},
                {'email': 'admin@test.com', 'password': 'admin'},
                {'email': 'user@test.com', 'password': 'password'}
            ],
            'jwt_test': [
                'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
                'Bearer invalid.token.here',
                'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature',
                'Bearer '
            ],
            'api_key_test': [
                'API_KEY_123456789',
                'sk-test-123456789',
                'pk-test-123456789',
                'key_123456789',
                'token_123456789'
            ]
        }
        
        # Business logic test payloads
        self.business_logic_payloads = {
            'claim_amount': [
                {'amount': 999999999999999999999999999},
                {'amount': -1},
                {'amount': 0},
                {'amount': '0x' + 'f' * 64},  # Very large hex number
                {'amount': 'INFINITY'},
                {'amount': 'NaN'}
            ],
            'claim_frequency': [
                {'timestamp': 0},
                {'timestamp': -1},
                {'timestamp': 9999999999999},
                {'timestamp': '2020-01-01'},
                {'timestamp': 'future'}
            ],
            'address_manipulation': [
                {'address': '0x' + '0' * 40},  # Zero address
                {'address': '0x' + 'f' * 40},  # Max address
                {'address': '0xdeadbeef'},  # Invalid address
                {'address': '0x1234567890abcdef1234567890abcdef12345678'},  # Invalid length
                {'address': 'burn_address'},  # Invalid format
            ]
        }
        
        # Rate limiting test parameters
        self.rate_limiting_threshold = 10
        self.rate_limiting_interval = 1.0  # seconds

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

    async def analyze_api_endpoints(self, target_url: str, web_info: Dict[str, Any]) -> APIAnalysisResult:
        logger.info(f"🔗 Starting comprehensive API analysis for: {target_url}")
        
        # Layer 1: Endpoint Discovery
        endpoints = await self._discover_endpoints(target_url, web_info)
        
        # Layer 2: Endpoint Classification
        classified_endpoints = await self._classify_endpoints(endpoints)
        
        # Layer 3: Authentication Testing
        auth_flaws = await self._test_authentication(classified_endpoints)
        
        # Layer 4: Rate Limiting Analysis
        rate_limiting_info = await self._analyze_rate_limiting(classified_endpoints)
        
        # Layer 5: CORS Policy Analysis
        cors_policy = await self._analyze_cors_policy(target_url)
        
        # Layer 6: Security Headers Analysis
        security_headers = await self._analyze_api_security_headers(target_url)
        
        # Layer 7: Business Logic Testing
        business_logic_flaws = await self._test_business_logic(classified_endpoints)
        
        # Layer 8: Input Validation Testing
        input_validation_flaws = await self._test_input_validation(classified_endpoints)
        
        # Combine all vulnerabilities
        all_vulnerabilities = auth_flaws + business_logic_flaws + input_validation_flaws
        
        return APIAnalysisResult(
            target_url=target_url,
            endpoints_discovered=classified_endpoints,
            vulnerabilities=all_vulnerabilities,
            authentication_flaws=auth_flaws,
            rate_limiting_info=rate_limiting_info,
            cors_policy=cors_policy,
            api_security_headers=security_headers,
            business_logic_flaws=business_logic_flaws
        )

    async def _discover_endpoints(self, base_url: str, web_info: Dict[str, Any]) -> List[str]:
        endpoints = set()
        
        # Add common endpoints
        for endpoint in self.common_endpoints:
            endpoints.add(urljoin(base_url, endpoint))
        
        # Extract from web content
        content = web_info.get('content', '')
        
        # Extract from JavaScript
        js_patterns = [
            r'fetch\([\'"]([^\'"]+)[\'"]',
            r'axios\.[a-z]+\([\'"]([^\'"]+)[\'"]',
            r'\$\.([a-z]+)\([\'"]([^\'"]+)[\'"]',
            r'\.get\([\'"]([^\'"]+)[\'"]',
            r'\.post\([\'"]([^\'"]+)[\'"]',
            r'\.put\([\'"]([^\'"]+)[\'"]',
            r'\.delete\([\'"]([^\'"]+)[\'"]',
            r'url:\s*[\'"]([^\'"]+)[\'"]',
            r'endpoint:\s*[\'"]([^\'"]+)[\'"]',
            r'baseURL:\s*[\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[1] if len(match) > 1 else match[0]
                
                if match.startswith(('http://', 'https://')):
                    endpoints.add(match)
                else:
                    endpoints.add(urljoin(base_url, match))
        
        # Extract from HTML links
        soup = web_info.get('soup')
        if soup:
            for link in soup.find_all(['a', 'link']):
                href = link.get('href', '')
                if href and (href.startswith('/api/') or href.startswith('/web3/') or href.startswith('/rpc/')):
                    endpoints.add(urljoin(base_url, href))
        
        # Extract from forms
        if soup:
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action and (action.startswith('/api/') or action.startswith('/web3/') or action.startswith('/rpc/')):
                    endpoints.add(urljoin(base_url, action))
        
        # Try to discover additional endpoints through directory enumeration
        discovery_endpoints = await self._discover_additional_endpoints(base_url)
        endpoints.update(discovery_endpoints)
        
        return list(endpoints)

    async def _discover_additional_endpoints(self, base_url: str) -> List[str]:
        endpoints = []
        
        # Common API paths to test
        api_paths = [
            '/api', '/v1', '/v2', '/v3', '/web3', '/rpc', '/graphql', '/rest',
            '/api/v1', '/api/v2', '/api/v3', '/web3/v1', '/rpc/v1'
        ]
        
        for path in api_paths:
            full_url = urljoin(base_url, path)
            try:
                async with self.session.get(full_url) as response:
                    if response.status in [200, 401, 403]:
                        endpoints.append(full_url)
                        
                        # If we get a successful response, try to find more endpoints
                        if response.status == 200:
                            content = await response.text()
                            # Extract JSON responses that might contain endpoint information
                            try:
                                json_data = json.loads(content)
                                if isinstance(json_data, dict):
                                    self._extract_endpoints_from_json(json_data, base_url, endpoints)
                            except:
                                pass
            except:
                continue
        
        return endpoints

    def _extract_endpoints_from_json(self, json_data: Any, base_url: str, endpoints: List[str]):
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                if isinstance(value, str) and (value.startswith('/api/') or value.startswith('/web3/') or value.startswith('/rpc/')):
                    endpoints.append(urljoin(base_url, value))
                elif isinstance(value, (dict, list)):
                    self._extract_endpoints_from_json(value, base_url, endpoints)
        elif isinstance(json_data, list):
            for item in json_data:
                if isinstance(item, (dict, list)):
                    self._extract_endpoints_from_json(item, base_url, endpoints)

    async def _classify_endpoints(self, endpoints: List[str]) -> List[APIEndpoint]:
        classified_endpoints = []
        
        for endpoint in endpoints[:50]:  # Limit to avoid excessive requests
            try:
                api_endpoint = await self._analyze_single_endpoint(endpoint)
                if api_endpoint:
                    classified_endpoints.append(api_endpoint)
            except Exception as e:
                logger.error(f"Error analyzing endpoint {endpoint}: {e}")
        
        return classified_endpoints

    async def _analyze_single_endpoint(self, url: str) -> Optional[APIEndpoint]:
        try:
            # Test different HTTP methods
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
            working_method = None
            
            for method in methods:
                try:
                    async with self.session.request(method, url) as response:
                        working_method = method
                        break
                except:
                    continue
            
            if not working_method:
                return None
            
            # Get detailed information
            async with self.session.request(working_method, url) as response:
                headers = dict(response.headers)
                content_type = headers.get('content-type', '')
                
                # Determine if authentication is required
                auth_required = response.status in [401, 403]
                
                # Analyze parameters based on content type
                parameters = []
                if 'application/json' in content_type:
                    try:
                        content = await response.text()
                        json_data = json.loads(content)
                        if isinstance(json_data, dict):
                            for key, value in json_data.items():
                                parameters.append({
                                    'name': key,
                                    'type': type(value).__name__,
                                    'required': True,
                                    'sample_value': value
                                })
                    except:
                        pass
                
                return APIEndpoint(
                    url=url,
                    method=working_method,
                    parameters=parameters,
                    headers=headers,
                    content_type=content_type,
                    authentication_required=auth_required,
                    rate_limiting=False,  # Will be tested separately
                    description=f"{working_method} endpoint for {urlparse(url).path}"
                )
        except Exception as e:
            logger.debug(f"Error analyzing endpoint {url}: {e}")
            return None

    async def _test_authentication(self, endpoints: List[APIEndpoint]) -> List[APIVulnerability]:
        vulnerabilities = []
        
        for endpoint in endpoints[:20]:  # Limit to avoid excessive requests
            if not endpoint.authentication_required:
                continue
                
            # Test broken authentication
            for payload in self.auth_test_payloads['broken_auth']:
                try:
                    async with self.session.post(endpoint.url, json=payload) as response:
                        if response.status in [200, 201]:
                            vulnerabilities.append(APIVulnerability(
                                vulnerability_type='Broken Authentication',
                                severity='CRITICAL',
                                description='Default credentials work or authentication is bypassed',
                                endpoint=endpoint.url,
                                method='POST',
                                payload=str(payload),
                                request_data=payload
                            ))
                            break
                except:
                    continue
            
            # Test JWT vulnerabilities
            if 'authorization' in endpoint.headers:
                for jwt_token in self.auth_test_payloads['jwt_test']:
                    try:
                        headers = {'Authorization': jwt_token}
                        async with self.session.get(endpoint.url, headers=headers) as response:
                            if response.status in [200, 201]:
                                vulnerabilities.append(APIVulnerability(
                                    vulnerability_type='JWT Vulnerability',
                                    severity='HIGH',
                                    description='JWT token validation is weak or bypassed',
                                    endpoint=endpoint.url,
                                    method='GET',
                                    payload=jwt_token
                                ))
                                break
                    except:
                        continue
            
            # Test API key vulnerabilities
            for api_key in self.auth_test_payloads['api_key_test']:
                try:
                    headers = {'X-API-Key': api_key}
                    async with self.session.get(endpoint.url, headers=headers) as response:
                        if response.status in [200, 201]:
                            vulnerabilities.append(APIVulnerability(
                                vulnerability_type='API Key Vulnerability',
                                severity='HIGH',
                                description='API key validation is weak or bypassed',
                                endpoint=endpoint.url,
                                method='GET',
                                payload=api_key
                            ))
                            break
                except:
                    continue
        
        return vulnerabilities

    async def _analyze_rate_limiting(self, endpoints: List[APIEndpoint]) -> Dict[str, Any]:
        rate_limiting_info = {
            'rate_limiting_enabled': False,
            'threshold': None,
            'interval': None,
            'tested_endpoints': [],
            'rate_limiting_headers': {}
        }
        
        # Test a few endpoints for rate limiting
        test_endpoints = endpoints[:5]
        
        for endpoint in test_endpoints:
            endpoint_info = {
                'url': endpoint.url,
                'method': endpoint.method,
                'rate_limited': False,
                'threshold': None,
                'headers_found': {}
            }
            
            try:
                # Send multiple requests quickly
                responses = []
                for i in range(self.rate_limiting_threshold + 5):
                    async with self.session.request(endpoint.method, endpoint.url) as response:
                        responses.append({
                            'status': response.status,
                            'headers': dict(response.headers)
                        })
                        
                        # Check for rate limiting headers
                        if 'x-ratelimit-limit' in response.headers:
                            endpoint_info['headers_found']['x-ratelimit-limit'] = response.headers['x-ratelimit-limit']
                        if 'x-ratelimit-remaining' in response.headers:
                            endpoint_info['headers_found']['x-ratelimit-remaining'] = response.headers['x-ratelimit-remaining']
                        if 'retry-after' in response.headers:
                            endpoint_info['headers_found']['retry-after'] = response.headers['retry-after']
                    
                    await asyncio.sleep(0.1)  # Small delay between requests
                
                # Analyze responses for rate limiting
                status_codes = [r['status'] for r in responses]
                if 429 in status_codes or 503 in status_codes:
                    endpoint_info['rate_limited'] = True
                    rate_limiting_info['rate_limiting_enabled'] = True
                    
                    # Find the threshold
                    for i, status in enumerate(status_codes):
                        if status in [429, 503]:
                            endpoint_info['threshold'] = i + 1
                            break
                
                endpoint_info['headers_found'].update(rate_limiting_info['rate_limiting_headers'])
                
            except Exception as e:
                logger.error(f"Error testing rate limiting for {endpoint.url}: {e}")
            
            rate_limiting_info['tested_endpoints'].append(endpoint_info)
        
        return rate_limiting_info

    async def _analyze_cors_policy(self, target_url: str) -> Dict[str, Any]:
        cors_policy = {
            'cors_enabled': False,
            'cors_headers': {},
            'vulnerabilities': []
        }
        
        try:
            async with self.session.options(target_url) as response:
                headers = dict(response.headers)
                
                if 'access-control-allow-origin' in headers:
                    cors_policy['cors_enabled'] = True
                    cors_policy['cors_headers'] = {
                        key: value for key, value in headers.items()
                        if key.lower().startswith('access-control-')
                    }
                    
                    # Check for CORS vulnerabilities
                    acao = headers.get('access-control-allow-origin', '')
                    if acao == '*':
                        cors_policy['vulnerabilities'].append({
                            'type': 'Permissive CORS',
                            'severity': 'MEDIUM',
                            'description': 'CORS policy allows any origin'
                        })
                    
                    acac = headers.get('access-control-allow-credentials', '')
                    if acac.lower() == 'true' and acao == '*':
                        cors_policy['vulnerabilities'].append({
                            'type': 'Insecure CORS',
                            'severity': 'HIGH',
                            'description': 'CORS allows credentials with wildcard origin'
                        })
        except Exception as e:
            logger.error(f"Error analyzing CORS policy: {e}")
        
        return cors_policy

    async def _analyze_api_security_headers(self, target_url: str) -> Dict[str, str]:
        security_headers = {}
        
        required_headers = {
            'Content-Security-Policy': 'Missing Content Security Policy',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options',
            'X-Frame-Options': 'Missing X-Frame-Options',
            'X-XSS-Protection': 'Missing XSS Protection',
            'Strict-Transport-Security': 'Missing HSTS'
        }
        
        try:
            async with self.session.get(target_url) as response:
                headers = dict(response.headers)
                
                for header, description in required_headers.items():
                    if header not in headers:
                        security_headers[header] = f"MISSING - {description}"
                    else:
                        security_headers[header] = f"PRESENT - {headers[header]}"
        except Exception as e:
            logger.error(f"Error analyzing security headers: {e}")
        
        return security_headers

    async def _test_business_logic(self, endpoints: List[APIEndpoint]) -> List[APIVulnerability]:
        vulnerabilities = []
        
        for endpoint in endpoints[:15]:  # Limit to avoid excessive requests
            endpoint_path = urlparse(endpoint.url).path.lower()
            
            # Test claim-related endpoints
            if 'claim' in endpoint_path:
                vulnerabilities.extend(await self._test_claim_logic(endpoint))
            
            # Test transaction-related endpoints
            if 'transaction' in endpoint_path or 'swap' in endpoint_path:
                vulnerabilities.extend(await self._test_transaction_logic(endpoint))
            
            # Test authentication-related endpoints
            if 'auth' in endpoint_path or 'login' in endpoint_path:
                vulnerabilities.extend(await self._test_auth_logic(endpoint))
        
        return vulnerabilities

    async def _test_claim_logic(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        vulnerabilities = []
        
        # Test amount manipulation
        for payload in self.business_logic_payloads['claim_amount']:
            try:
                async with self.session.post(endpoint.url, json=payload) as response:
                    if response.status in [200, 201]:
                        vulnerabilities.append(APIVulnerability(
                            vulnerability_type='Business Logic Flaw',
                            severity='HIGH',
                            description='Claim endpoint accepts invalid amounts',
                            endpoint=endpoint.url,
                            method='POST',
                            parameter='amount',
                            payload=str(payload)
                        ))
                        break
            except:
                continue
        
        # Test frequency bypass
        for payload in self.business_logic_payloads['claim_frequency']:
            try:
                async with self.session.post(endpoint.url, json=payload) as response:
                    if response.status in [200, 201]:
                        vulnerabilities.append(APIVulnerability(
                            vulnerability_type='Business Logic Flaw',
                            severity='HIGH',
                            description='Claim frequency validation can be bypassed',
                            endpoint=endpoint.url,
                            method='POST',
                            parameter='timestamp',
                            payload=str(payload)
                        ))
                        break
            except:
                continue
        
        return vulnerabilities

    async def _test_transaction_logic(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        vulnerabilities = []
        
        # Test address manipulation
        for payload in self.business_logic_payloads['address_manipulation']:
            try:
                test_payload = {'to': payload['address'], 'amount': 1}
                async with self.session.post(endpoint.url, json=test_payload) as response:
                    if response.status in [200, 201]:
                        vulnerabilities.append(APIVulnerability(
                            vulnerability_type='Business Logic Flaw',
                            severity='HIGH',
                            description='Transaction endpoint accepts invalid addresses',
                            endpoint=endpoint.url,
                            method='POST',
                            parameter='to',
                            payload=str(test_payload)
                        ))
                        break
            except:
                continue
        
        return vulnerabilities

    async def _test_auth_logic(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        vulnerabilities = []
        
        # Test authentication bypass
        test_payloads = [
            {'username': '', 'password': ''},
            {'email': '', 'password': ''},
            {'token': 'invalid_token'},
            {'signature': 'invalid_signature'}
        ]
        
        for payload in test_payloads:
            try:
                async with self.session.post(endpoint.url, json=payload) as response:
                    if response.status in [200, 201]:
                        vulnerabilities.append(APIVulnerability(
                            vulnerability_type='Authentication Bypass',
                            severity='CRITICAL',
                            description='Authentication can be bypassed with empty credentials',
                            endpoint=endpoint.url,
                            method='POST',
                            payload=str(payload)
                        ))
                        break
            except:
                continue
        
        return vulnerabilities

    async def _test_input_validation(self, endpoints: List[APIEndpoint]) -> List[APIVulnerability]:
        vulnerabilities = []
        
        # SQL Injection test
        sql_payloads = [
            {"query": "SELECT * FROM users"},
            {"id": "1' OR '1'='1"},
            {"search": "' UNION SELECT username, password FROM users--"},
            {"filter": "1; DROP TABLE users--"}
        ]
        
        for endpoint in endpoints[:10]:
            for payload in sql_payloads[:2]:  # Limit payloads
                try:
                    async with self.session.post(endpoint.url, json=payload) as response:
                        if response.status in [200, 201]:
                            content = await response.text()
                            if 'sql' in content.lower() or 'error' in content.lower():
                                vulnerabilities.append(APIVulnerability(
                                    vulnerability_type='SQL Injection',
                                    severity='HIGH',
                                    description='Potential SQL injection vulnerability',
                                    endpoint=endpoint.url,
                                    method='POST',
                                    payload=str(payload)
                                ))
                                break
                except:
                    continue
        
        return vulnerabilities

    async def generate_report(self, analysis_result: APIAnalysisResult) -> Dict[str, Any]:
        report = {
            'api_analysis_summary': {
                'target_url': analysis_result.target_url,
                'total_endpoints': len(analysis_result.endpoints_discovered),
                'vulnerable_endpoints': len(analysis_result.vulnerabilities),
                'auth_flaws': len(analysis_result.authentication_flaws),
                'business_logic_flaws': len(analysis_result.business_logic_flaws),
                'rate_limiting_enabled': analysis_result.rate_limiting_info['rate_limiting_enabled']
            },
            'endpoints_discovered': [
                {
                    'url': endpoint.url,
                    'method': endpoint.method,
                    'auth_required': endpoint.authentication_required,
                    'rate_limited': endpoint.rate_limiting,
                    'content_type': endpoint.content_type,
                    'parameters': endpoint.parameters[:5]  # Limit for readability
                }
                for endpoint in analysis_result.endpoints_discovered
            ],
            'vulnerabilities': [
                {
                    'type': vuln.vulnerability_type,
                    'severity': vuln.severity,
                    'description': vuln.description,
                    'endpoint': vuln.endpoint,
                    'method': vuln.method,
                    'parameter': vuln.parameter,
                    'payload': vuln.payload
                }
                for vuln in analysis_result.vulnerabilities
            ],
            'rate_limiting_analysis': analysis_result.rate_limiting_info,
            'cors_policy': analysis_result.cors_policy,
            'security_headers': analysis_result.api_security_headers,
            'recommendations': self._generate_api_recommendations(analysis_result)
        }
        
        return report

    def _generate_api_recommendations(self, analysis_result: APIAnalysisResult) -> List[str]:
        recommendations = []
        
        # Authentication recommendations
        if analysis_result.authentication_flaws:
            recommendations.append("Implement strong authentication mechanisms with proper session management")
        
        # Rate limiting recommendations
        if not analysis_result.rate_limiting_info['rate_limiting_enabled']:
            recommendations.append("Implement rate limiting to prevent abuse and DoS attacks")
        
        # CORS recommendations
        if analysis_result.cors_policy.get('vulnerabilities'):
            recommendations.append("Review and restrict CORS policy to prevent cross-origin attacks")
        
        # Security headers recommendations
        missing_headers = [
            header for header, status in analysis_result.api_security_headers.items()
            if status.startswith('MISSING')
        ]
        
        if missing_headers:
            recommendations.append(f"Implement missing security headers: {', '.join(missing_headers)}")
        
        # Business logic recommendations
        if analysis_result.business_logic_flaws:
            recommendations.append("Implement proper input validation and business logic checks")
            recommendations.append("Add rate limiting for claim and transaction endpoints")
        
        # Input validation recommendations
        input_validation_vulns = [v for v in analysis_result.vulnerabilities if v.vulnerability_type == 'SQL Injection']
        if input_validation_vulns:
            recommendations.append("Implement proper input validation and parameterized queries")
        
        return recommendations

async def test_api_endpoints(target_url: str, web_info: Dict[str, Any]) -> Dict[str, Any]:
    async with APIEndpointTester() as tester:
        analysis_result = await tester.analyze_api_endpoints(target_url, web_info)
        report = await tester.generate_report(analysis_result)
        return report

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        
        async def run_test():
            # Simple web info for testing
            web_info = {'content': '', 'soup': None}
            result = await test_api_endpoints(target_url, web_info)
            print(json.dumps(result, indent=2))
        
        asyncio.run(run_test())
    else:
        print("Usage: python api_endpoint_tester.py <target_url>")