#!/usr/bin/env python3
"""
ShadowScan Website Airdrop Scanner Module
Khusus untuk scanning website airdrop dan token claim vulnerabilities
"""

import asyncio
import aiohttp
import json
import re
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
import hashlib
import base64
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class WebsiteTech:
    """Technology stack detection"""
    framework: Optional[str] = None
    backend: Optional[str] = None
    web3_libs: List[str] = None
    analytics: List[str] = None
    cms: Optional[str] = None
    
    def __post_init__(self):
        if self.web3_libs is None:
            self.web3_libs = []
        if self.analytics is None:
            self.analytics = []

@dataclass
class EndpointInfo:
    """API endpoint information"""
    url: str
    method: str
    params: Dict[str, Any]
    headers: Dict[str, str]
    response_code: int
    response_time: float
    response_size: int

@dataclass
class VulnerabilityFinding:
    """Vulnerability finding"""
    type: str
    severity: str
    description: str
    endpoint: str
    proof: str
    impact: str
    remediation: str

class AirdropWebsiteScanner:
    """Scanner khusus untuk website airdrop"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.findings: List[VulnerabilityFinding] = []
        self.endpoints: List[EndpointInfo] = []
        self.tech_stack = WebsiteTech()
        self.max_requests = 50
        
    async def scan_comprehensive(self, max_requests: int = 50) -> Dict[str, Any]:
        """Scanning komprehensif website airdrop"""
        logger.info(f"🔍 Starting comprehensive scan of {self.target_url}")
        self.max_requests = max_requests
        
        results = {
            'target_url': self.target_url,
            'technology_stack': {},
            'endpoints': [],
            'vulnerabilities': [],
            'claim_mechanism': {},
            'recommendations': []
        }
        
        try:
            # Step 1: Teknologi Detection
            logger.info("📊 Detecting technology stack...")
            tech_results = await self._detect_technology()
            results['technology_stack'] = tech_results
            
            # Step 2: Endpoint Discovery
            logger.info("🔍 Discovering API endpoints...")
            endpoint_results = await self._discover_endpoints()
            results['endpoints'] = endpoint_results
            
            # Step 3: Claim Mechanism Analysis
            logger.info("🎯 Analyzing claim mechanism...")
            claim_results = await self._analyze_claim_mechanism()
            results['claim_mechanism'] = claim_results
            
            # Step 4: Vulnerability Scanning
            logger.info("🚨 Scanning for vulnerabilities...")
            vuln_results = await self._scan_vulnerabilities()
            results['vulnerabilities'] = vuln_results
            
            # Step 5: Generate Recommendations
            logger.info("💡 Generating recommendations...")
            results['recommendations'] = self._generate_recommendations()
            
            logger.info("✅ Comprehensive scan completed!")
            
        except Exception as e:
            logger.error(f"❌ Error during scanning: {e}")
            results['error'] = str(e)
            
        return results
    
    async def _detect_technology(self) -> Dict[str, Any]:
        """Deteksi teknologi yang digunakan website"""
        tech_info = {
            'framework': None,
            'backend': None,
            'web3_libraries': [],
            'cms': None,
            'analytics': [],
            'headers': {},
            'meta_tags': {},
            'scripts': []
        }
        
        try:
            # HTTP Request untuk headers
            response = self.session.get(self.target_url, timeout=10)
            tech_info['headers'] = dict(response.headers)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', '').lower()
                content = meta.get('content', '')
                if name and content:
                    tech_info['meta_tags'][name] = content
            
            # Script tags untuk deteksi libraries
            scripts = soup.find_all('script')
            for script in scripts:
                src = script.get('src', '')
                if src:
                    tech_info['scripts'].append(src)
                    
                    # Deteksi framework
                    if 'react' in src.lower():
                        tech_info['framework'] = 'React'
                    elif 'vue' in src.lower():
                        tech_info['framework'] = 'Vue'
                    elif 'angular' in src.lower():
                        tech_info['framework'] = 'Angular'
                    elif 'next' in src.lower():
                        tech_info['framework'] = 'Next.js'
                        
                    # Deteksi Web3 libraries
                    if any(lib in src.lower() for lib in ['web3', 'ethers', 'walletconnect', 'metamask']):
                        tech_info['web3_libraries'].append(src)
                        
                    # Deteksi analytics
                    if any(analytic in src.lower() for analytic in ['google-analytics', 'plausible', 'mixpanel']):
                        tech_info['analytics'].append(src)
            
            # Deteksi dari headers
            headers = response.headers
            if 'x-powered-by' in headers:
                tech_info['backend'] = headers['x-powered-by']
            if 'server' in headers:
                tech_info['server'] = headers['server']
                
        except Exception as e:
            logger.error(f"Error detecting technology: {e}")
            
        return tech_info
    
    async def _discover_endpoints(self) -> List[Dict[str, Any]]:
        """Discovery API endpoints"""
        endpoints = []
        
        try:
            # Get HTML content
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Cari API endpoints di JavaScript
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    # Cari URL patterns
                    api_pattern = r'https?://[^\s"\'<>]+/api/[^\s"\'<>]+'
                    matches = re.findall(api_pattern, script.string)
                    for match in matches:
                        endpoint_info = {
                            'url': match,
                            'source': 'javascript',
                            'method': 'GET',
                            'discovered_from': 'script_tag'
                        }
                        endpoints.append(endpoint_info)
            
            # Cari form actions
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action')
                if action:
                    endpoint_info = {
                        'url': urljoin(self.target_url, action),
                        'source': 'form',
                        'method': form.get('method', 'POST').upper(),
                        'discovered_from': 'form_action'
                    }
                    endpoints.append(endpoint_info)
            
            # Common airdrop endpoints
            common_endpoints = [
                '/api/claim',
                '/api/airdrop',
                '/api/mint',
                '/api/user',
                '/api/wallet',
                '/api/verify',
                '/api/signature'
            ]
            
            for endpoint in common_endpoints:
                full_url = urljoin(self.target_url, endpoint)
                endpoint_info = {
                    'url': full_url,
                    'source': 'common',
                    'method': 'POST',
                    'discovered_from': 'common_airdrop_patterns'
                }
                endpoints.append(endpoint_info)
                
        except Exception as e:
            logger.error(f"Error discovering endpoints: {e}")
            
        return endpoints
    
    async def _analyze_claim_mechanism(self) -> Dict[str, Any]:
        """Analisis mekanisme claim token"""
        claim_info = {
            'has_claim_form': False,
            'claim_endpoint': None,
            'wallet_required': False,
            'signature_required': False,
            'rate_limiting': False,
            'validation_methods': []
        }
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Cari claim form
            forms = soup.find_all('form')
            for form in forms:
                if any(keyword in form.get('action', '').lower() for keyword in ['claim', 'mint', 'airdrop']):
                    claim_info['has_claim_form'] = True
                    claim_info['claim_endpoint'] = urljoin(self.target_url, form.get('action', ''))
            
            # Cari wallet connection indicators
            wallet_indicators = ['connect', 'wallet', 'metamask', 'web3', 'sign']
            page_text = soup.get_text().lower()
            if any(indicator in page_text for indicator in wallet_indicators):
                claim_info['wallet_required'] = True
            
            # Cari signature requirement
            if any(keyword in page_text for keyword in ['signature', 'sign', 'verify']):
                claim_info['signature_required'] = True
            
            # Cari validation methods
            if any(keyword in page_text for keyword in ['captcha', 'recaptcha', 'human']):
                claim_info['validation_methods'].append('captcha')
            if any(keyword in page_text for keyword in ['rate', 'limit', 'throttle']):
                claim_info['rate_limiting'] = True
                
        except Exception as e:
            logger.error(f"Error analyzing claim mechanism: {e}")
            
        return claim_info
    
    async def _scan_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Scanning vulnerabilities khusus airdrop"""
        vulnerabilities = []
        
        # Test 1: Missing Rate Limiting
        rate_limit_vuln = await self._test_rate_limiting()
        if rate_limit_vuln:
            vulnerabilities.append(rate_limit_vuln)
        
        # Test 2: Signature Verification Bypass
        signature_vuln = await self._test_signature_verification()
        if signature_vuln:
            vulnerabilities.append(signature_vuln)
        
        # Test 3: Amount Manipulation
        amount_vuln = await self._test_amount_manipulation()
        if amount_vuln:
            vulnerabilities.append(amount_vuln)
        
        # Test 4: Replay Attack
        replay_vuln = await self._test_replay_attack()
        if replay_vuln:
            vulnerabilities.append(replay_vuln)
        
        # Test 5: Front-Running
        frontrunning_vuln = await self._test_frontrunning()
        if frontrunning_vuln:
            vulnerabilities.append(frontrunning_vuln)
        
        return vulnerabilities
    
    async def _test_rate_limiting(self) -> Optional[Dict[str, Any]]:
        """Test rate limiting vulnerability"""
        try:
            # Simulate multiple rapid requests
            test_endpoint = f"{self.target_url}/api/claim"
            
            times = []
            for i in range(10):
                start_time = time.time()
                try:
                    response = self.session.post(test_endpoint, json={'test': 'rate_limit'}, timeout=5)
                    times.append(time.time() - start_time)
                except:
                    pass
            
            # Check if all requests were processed quickly
            if times and all(t < 1.0 for t in times):
                return {
                    'type': 'Missing Rate Limiting',
                    'severity': 'High',
                    'description': 'No rate limiting detected on claim endpoint',
                    'endpoint': test_endpoint,
                    'proof': f'10 requests processed in {sum(times):.2f} seconds',
                    'impact': 'Attacker can spam claim requests',
                    'remediation': 'Implement rate limiting per wallet/address'
                }
        except Exception as e:
            logger.error(f"Error testing rate limiting: {e}")
        
        return None
    
    async def _test_signature_verification(self) -> Optional[Dict[str, Any]]:
        """Test signature verification bypass"""
        try:
            # Test with invalid signature
            test_endpoint = f"{self.target_url}/api/claim"
            
            # Try different invalid signature formats
            test_payloads = [
                {'signature': 'invalid_signature'},
                {'signature': ''},
                {'signature': None},
                {}  # No signature at all
            ]
            
            for payload in test_payloads:
                try:
                    response = self.session.post(test_endpoint, json=payload, timeout=5)
                    if response.status_code == 200:
                        return {
                            'type': 'Signature Verification Bypass',
                            'severity': 'Critical',
                            'description': 'Claim endpoint accepts invalid signatures',
                            'endpoint': test_endpoint,
                            'proof': f'Request with invalid signature returned 200: {payload}',
                            'impact': 'Attacker can claim tokens without valid signature',
                            'remediation': 'Implement proper signature verification'
                        }
                except:
                    pass
        except Exception as e:
            logger.error(f"Error testing signature verification: {e}")
        
        return None
    
    async def _test_amount_manipulation(self) -> Optional[Dict[str, Any]]:
        """Test amount manipulation vulnerability"""
        try:
            test_endpoint = f"{self.target_url}/api/claim"
            
            # Test with manipulated amounts
            test_amounts = [
                {'amount': 999999999},
                {'amount': -1},
                {'amount': 0},
                {'amount': '999999999'}
            ]
            
            for payload in test_amounts:
                try:
                    response = self.session.post(test_endpoint, json=payload, timeout=5)
                    if response.status_code == 200:
                        return {
                            'type': 'Amount Manipulation',
                            'severity': 'High',
                            'description': 'Claim endpoint accepts manipulated amounts',
                            'endpoint': test_endpoint,
                            'proof': f'Request with manipulated amount returned 200: {payload}',
                            'impact': 'Attacker can claim more tokens than allocated',
                            'remediation': 'Validate claim amounts on server-side'
                        }
                except:
                    pass
        except Exception as e:
            logger.error(f"Error testing amount manipulation: {e}")
        
        return None
    
    async def _test_replay_attack(self) -> Optional[Dict[str, Any]]:
        """Test replay attack vulnerability"""
        try:
            test_endpoint = f"{self.target_url}/api/claim"
            
            # Generate test payload
            test_payload = {'test': 'replay', 'nonce': int(time.time())}
            
            # Send same request multiple times
            responses = []
            for i in range(3):
                try:
                    response = self.session.post(test_endpoint, json=test_payload, timeout=5)
                    responses.append(response.status_code)
                except:
                    responses.append(500)
            
            # Check if all requests were accepted
            if all(code == 200 for code in responses):
                return {
                    'type': 'Replay Attack Vulnerability',
                    'severity': 'High',
                    'description': 'Duplicate claim requests are accepted',
                    'endpoint': test_endpoint,
                    'proof': f'Same payload accepted {len([c for c in responses if c == 200])} times',
                    'impact': 'Attacker can replay claim requests multiple times',
                    'remediation': 'Implement nonce checking and request deduplication'
                }
        except Exception as e:
            logger.error(f"Error testing replay attack: {e}")
        
        return None
    
    async def _test_frontrunning(self) -> Optional[Dict[str, Any]]:
        """Test front-running vulnerability"""
        try:
            # This is a simplified test - real front-running detection requires mempool monitoring
            test_endpoint = f"{self.target_url}/api/claim"
            
            # Check if timestamp is used properly
            test_payload = {'timestamp': int(time.time())}
            
            try:
                response = self.session.post(test_endpoint, json=test_payload, timeout=5)
                if response.status_code == 200:
                    # Check response for timestamp validation
                    response_text = response.text.lower()
                    if 'timestamp' not in response_text and 'time' not in response_text:
                        return {
                            'type': 'Potential Front-Running',
                            'severity': 'Medium',
                            'description': 'Claim endpoint may not validate timestamps properly',
                            'endpoint': test_endpoint,
                            'proof': 'No timestamp validation detected in response',
                            'impact': 'Attacker may be able to front-run claim transactions',
                            'remediation': 'Implement proper timestamp validation and use commit-reveal schemes'
                        }
            except:
                pass
        except Exception as e:
            logger.error(f"Error testing front-running: {e}")
        
        return None
    
    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate security recommendations"""
        recommendations = [
            {
                'category': 'Rate Limiting',
                'priority': 'High',
                'recommendation': 'Implement rate limiting per wallet address',
                'description': 'Prevent spam claims by limiting requests per address'
            },
            {
                'category': 'Signature Verification',
                'priority': 'Critical',
                'recommendation': 'Implement proper cryptographic signature verification',
                'description': 'Ensure only valid signed transactions can claim tokens'
            },
            {
                'category': 'Amount Validation',
                'priority': 'High',
                'recommendation': 'Validate claim amounts on server-side',
                'description': 'Prevent manipulation of claim amounts'
            },
            {
                'category': 'Replay Protection',
                'priority': 'High',
                'recommendation': 'Implement nonce checking and request deduplication',
                'description': 'Prevent replay attacks using unique nonces'
            },
            {
                'category': 'Monitoring',
                'priority': 'Medium',
                'recommendation': 'Implement real-time monitoring of claim activities',
                'description': 'Detect and respond to suspicious claim patterns'
            }
        ]
        
        return recommendations

async def main():
    """Main function for testing"""
    target_url = "https://airdrop.boundless.network/"
    max_requests = 30
    
    scanner = AirdropWebsiteScanner(target_url)
    results = await scanner.scan_comprehensive(max_requests=max_requests)
    
    # Print results
    print("\n" + "="*80)
    print("🔍 AIRDROP WEBSITE SECURITY SCAN RESULTS")
    print("="*80)
    
    print(f"\n📊 Target: {target_url}")
    print(f"🔍 Technology Stack:")
    for key, value in results.get('technology_stack', {}).items():
        if value:
            print(f"   {key}: {value}")
    
    print(f"\n🎯 Claim Mechanism:")
    claim_info = results.get('claim_mechanism', {})
    for key, value in claim_info.items():
        print(f"   {key}: {value}")
    
    print(f"\n🔍 Endpoints Discovered: {len(results.get('endpoints', []))}")
    for endpoint in results.get('endpoints', [])[:5]:  # Show first 5
        print(f"   {endpoint.get('method', 'GET')} {endpoint.get('url', 'N/A')}")
    
    print(f"\n🚨 Vulnerabilities Found: {len(results.get('vulnerabilities', []))}")
    for vuln in results.get('vulnerabilities', []):
        print(f"   [{vuln.get('severity', 'Info')}] {vuln.get('type', 'Unknown')}")
        print(f"   Description: {vuln.get('description', 'N/A')}")
        print(f"   Impact: {vuln.get('impact', 'N/A')}")
        print(f"   Remediation: {vuln.get('remediation', 'N/A')}")
        print()
    
    print(f"\n💡 Recommendations:")
    for rec in results.get('recommendations', []):
        print(f"   [{rec.get('priority', 'Medium')}] {rec.get('category', 'General')}")
        print(f"   {rec.get('recommendation', 'N/A')}")
        print(f"   {rec.get('description', 'N/A')}")
        print()
    
    # Save detailed report
    with open('airdrop_security_report.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n📄 Detailed report saved to: airdrop_security_report.json")

if __name__ == "__main__":
    asyncio.run(main())