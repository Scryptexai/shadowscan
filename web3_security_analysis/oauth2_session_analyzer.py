#!/usr/bin/env python3
"""
OAuth2 Session Analyzer untuk 0G Foundation Airdrop
Analisis keamanan OAuth2 dengan manipulasi session dan hijacking
"""

import asyncio
import json
import re
import time
import base64
import hashlib
import random
import string
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import aiohttp
import requests


class OAuth2SessionAnalyzer:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = None
        self.scan_results = {}
        self.start_time = time.time()

    async def run_oauth2_analysis(self):
        """Jalankan analisis OAuth2 komprehensif"""
        print("🔍 Memulai OAuth2 Session Analysis")
        print("=" * 60)
        print(f"🎯 Target: {self.target_url}")
        print("=" * 60)

        results = {}

        # OAuth2 Provider Detection
        print("\n🏢 OAuth2 Provider Detection")
        results["provider_detection"] = await self.oauth2_provider_detection()

        # OAuth2 Flow Analysis
        print("\n🔄 OAuth2 Flow Analysis")
        results["flow_analysis"] = await self.oauth2_flow_analysis()

        # Session Security Analysis
        print("\n🔐 Session Security Analysis")
        results["session_security"] = await self.session_security_analysis()

        # Token Security Analysis
        print("\n🎫 Token Security Analysis")
        results["token_security"] = await self.token_security_analysis()

        # Vulnerability Testing
        print("\n🚨 Vulnerability Testing")
        results["vulnerability_testing"] = await self.oauth2_vulnerability_testing()

        # Generate final report
        results["summary"] = self.generate_summary_report(results)
        results["scan_duration"] = time.time() - self.start_time

        return results

    async def oauth2_provider_detection(self):
        """Deteksi provider OAuth2"""
        try:
            async with aiohttp.ClientSession() as session:
                self.session = session

                # Get main page to detect OAuth patterns
                response = await self.session.get(self.target_url)
                content = response.text

                # Common OAuth2 providers
                providers = {
                    "twitter": {
                        "domains": ["twitter.com", "api.twitter.com"],
                        "patterns": [
                            r"twitter.*oauth",
                            r"api\.twitter\.com/oauth",
                            r"twitter\.com/i/oauth2",
                            r"client_id.*twitter"
                        ],
                        "endpoints": ["/auth/twitter", "/login/twitter", "/oauth/twitter"]
                    },
                    "discord": {
                        "domains": ["discord.com", "discord.gg"],
                        "patterns": [
                            r"discord.*oauth",
                            r"discord\.com/api/oauth2",
                            r"client_id.*discord",
                            r"guild_id.*discord"
                        ],
                        "endpoints": ["/auth/discord", "/login/discord", "/oauth/discord"]
                    },
                    "google": {
                        "domains": ["google.com", "accounts.google.com"],
                        "patterns": [
                            r"google.*oauth",
                            r"accounts\.google\.com",
                            r"gmail\.com",
                            r"client_id.*google"
                        ],
                        "endpoints": ["/auth/google", "/login/google", "/oauth/google"]
                    },
                    "github": {
                        "domains": ["github.com", "api.github.com"],
                        "patterns": [
                            r"github.*oauth",
                            r"api\.github\.com",
                            r"github\.com/login/oauth",
                            r"client_id.*github"
                        ],
                        "endpoints": ["/auth/github", "/login/github", "/oauth/github"]
                    },
                    "facebook": {
                        "domains": ["facebook.com", "graph.facebook.com"],
                        "patterns": [
                            r"facebook.*oauth",
                            r"graph\.facebook\.com",
                            r"fbsdk",
                            r"fbconnect"
                        ],
                        "endpoints": ["/auth/facebook", "/login/facebook", "/oauth/facebook"]
                    }
                }

                detected_providers = []
                provider_details = {}

                for provider_name, provider_config in providers.items():
                    provider_info = {
                        "name": provider_name.capitalize(),
                        "detected": False,
                        "domains_found": [],
                        "patterns_found": [],
                        "endpoints_found": [],
                        "security_score": 0
                    }

                    # Check for domain patterns
                    for domain in provider_config["domains"]:
                        if domain in content.lower():
                            provider_info["domains_found"].append(domain)
                            provider_info["detected"] = True

                    # Check for regex patterns
                    for pattern in provider_config["patterns"]:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            provider_info["patterns_found"].extend(matches[:5])  # Limit to 5 matches
                            provider_info["detected"] = True

                    # Test endpoints
                    for endpoint in provider_config["endpoints"]:
                        try:
                            test_response = await self.session.get(urljoin(self.target_url, endpoint))
                            if test_response.status < 500:
                                provider_info["endpoints_found"].append(endpoint)
                                provider_info["detected"] = True
                        except:
                            pass

                    if provider_info["detected"]:
                        detected_providers.append(provider_name)
                        # Calculate security score based on findings
                        score = 60 + len(provider_info["domains_found"]) * 10
                        score += len(provider_info["patterns_found"]) * 5
                        score += len(provider_info["endpoints_found"]) * 15
                        provider_info["security_score"] = min(score, 100)

                    provider_details[provider_name] = provider_info

                return {
                    "providers_tested": len(providers),
                    "providers_detected": len(detected_providers),
                    "detected_providers": detected_providers,
                    "provider_details": provider_details,
                    "score": self.calculate_provider_score(detected_providers, provider_details)
                }

        except Exception as e:
            return {"error": str(e), "score": 0}

    async def oauth2_flow_analysis(self):
        """Analisis OAuth2 flows"""
        try:
            # Detect different OAuth2 flows
            flows = {
                "authorization_code": {
                    "description": "Authorization Code Flow",
                    "indicators": [
                        r"authorization_code",
                        r"response_type.*code",
                        r"redirect_uri",
                        r"code_verifier",
                        r"pkce"
                    ]
                },
                "implicit": {
                    "description": "Implicit Flow",
                    "indicators": [
                        r"implicit",
                        r"response_type.*token",
                        r"access_token.*response"
                    ]
                },
                "client_credentials": {
                    "description": "Client Credentials Flow",
                    "indicators": [
                        r"client_credentials",
                        r"grant_type.*client_credentials",
                        r"client_secret"
                    ]
                },
                "password": {
                    "description": "Resource Owner Password Credentials Flow",
                    "indicators": [
                        r"password",
                        r"resource_owner_password_credentials",
                        r"grant_type.*password"
                    ]
                }
            }

            response = await self.session.get(self.target_url)
            content = response.text

            detected_flows = []
            flow_details = {}

            for flow_name, flow_config in flows.items():
                flow_info = {
                    "name": flow_config["description"],
                    "detected": False,
                    "indicators_found": [],
                    "security_concerns": [],
                    "security_score": 0
                }

                # Check for flow indicators
                for indicator in flow_config["indicators"]:
                    matches = re.findall(indicator, content, re.IGNORECASE)
                    if matches:
                        flow_info["indicators_found"].extend(matches[:3])
                        flow_info["detected"] = True

                # Assess security concerns based on flow type
                if flow_name == "implicit":
                    flow_info["security_concerns"].append("Access token exposed in URL")
                    flow_info["security_concerns"].append("No token refresh capability")
                elif flow_name == "password":
                    flow_info["security_concerns"].append("Username/password exposed")
                    flow_info["security_concerns"].append("Not recommended for third-party apps")

                if flow_info["detected"]:
                    detected_flows.append(flow_name)
                    # Calculate security score
                    base_score = 70 if flow_name == "authorization_code" else 40
                    score = base_score + len(flow_info["indicators_found"]) * 10
                    score -= len(flow_info["security_concerns"]) * 15
                    flow_info["security_score"] = max(0, min(score, 100))

                flow_details[flow_name] = flow_info

            return {
                "flows_tested": len(flows),
                "flows_detected": len(detected_flows),
                "detected_flows": detected_flows,
                "flow_details": flow_details,
                "score": self.calculate_flow_score(detected_flows, flow_details)
            }

        except Exception as e:
            return {"error": str(e), "score": 0}

    async def session_security_analysis(self):
        """Analisis keamanan session"""
        try:
            # Test session creation and management
            session_result = await self.test_session_management()

            # Test session fixation
            fixation_result = await self.test_session_fixation()

            # Test session timeout
            timeout_result = await self.test_session_timeout()

            # Test session hijacking
            hijacking_result = await self.test_session_hijacking()

            return {
                "session_management": session_result,
                "session_fixation": fixation_result,
                "session_timeout": timeout_result,
                "session_hijacking": hijacking_result,
                "score": self.calculate_session_score([
                    session_result, fixation_result, timeout_result, hijacking_result
                ])
            }

        except Exception as e:
            return {"error": str(e), "score": 0}

    async def test_session_management(self):
        """Test session management"""
        try:
            # Create session
            session1 = aiohttp.ClientSession()
            response1 = await session1.get(self.target_url)

            # Get session cookie
            cookies1 = session1.cookie_jar
            session_id1 = None

            for cookie in cookies1:
                if 'session' in cookie.key.lower() or 'ssid' in cookie.key.lower():
                    session_id1 = cookie.value
                    break

            # Create new session
            session2 = aiohttp.ClientSession()
            response2 = await session2.get(self.target_url)

            # Check if new session created
            cookies2 = session2.cookie_jar
            session_id2 = None

            for cookie in cookies2:
                if 'session' in cookie.key.lower() or 'ssid' in cookie.key.lower():
                    session_id2 = cookie.value
                    break

            # Test if sessions are different
            session_regeneration = session_id1 != session_id2 if session_id1 and session_id2 else True

            # Check for session security attributes
            secure_cookies = []
            httponly_cookies = []
            samesite_cookies = []

            for cookie in cookies1:
                if cookie.secure:
                    secure_cookies.append(cookie.key)
                if cookie.get('httponly'):
                    httponly_cookies.append(cookie.key)
                if cookie.get('samesite'):
                    samesite_cookies.append(cookie.key)

            # Calculate score
            score = 50  # Base score
            if session_regeneration:
                score += 20
            score += len(secure_cookies) * 15
            score += len(httponly_cookies) * 15
            score += len(samesite_cookies) * 10

            await session1.close()
            await session2.close()

            return {
                "sessions_tested": 2,
                "session_regeneration": session_regeneration,
                "secure_cookies": len(secure_cookies),
                "httponly_cookies": len(httponly_cookies),
                "samesite_cookies": len(samesite_cookies),
                "cookie_details": {
                    "secure": secure_cookies,
                    "httponly": httponly_cookies,
                    "samesite": samesite_cookies
                },
                "score": min(score, 100)
            }

        except Exception as e:
            return {"error": str(e), "score": 0}

    async def test_session_fixation(self):
        """Test session fixation vulnerability"""
        try:
            # Create session and get session ID
            session = aiohttp.ClientSession()
            response = await session.get(self.target_url)

            # Try to find session ID
            session_id = None
            for cookie in session.cookie_jar:
                if 'session' in cookie.key.lower() or 'ssid' in cookie.key.lower():
                    session_id = cookie.value
                    break

            if not session_id:
                return {"error": "No session found", "score": 100}

            # Check if session ID changes after authentication
            # This is a simplified test - real test would require authentication
            response2 = await session.get(self.target_url)

            # Check if session ID changed
            session_id2 = None
            for cookie in session.cookie_jar:
                if 'session' in cookie.key.lower() or 'ssid' in cookie.key.lower():
                    session_id2 = cookie.value
                    break

            session_fixation_vulnerable = session_id == session_id2 if session_id2 else False

            # Calculate score (lower is better for vulnerabilities)
            score = 0 if session_fixation_vulnerable else 80

            await session.close()

            return {
                "session_fixation_tested": True,
                "session_fixation_vulnerable": session_fixation_vulnerable,
                "initial_session_id": session_id[:10] + "..." if session_id else None,
                "score": score
            }

        except Exception as e:
            return {"error": str(e), "score": 60}

    async def test_session_timeout(self):
        """Test session timeout"""
        try:
            session = aiohttp.ClientSession()
            response = await session.get(self.target_url)

            # Check for session timeout mechanisms
            content = response.text

            timeout_patterns = [
                r"session.*timeout",
                r"session.*expires",
                r"session.*max-age",
                r"session.*lifetime",
                r"keep-alive"
            ]

            timeout_indicators = []
            for pattern in timeout_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    timeout_indicators.extend(matches[:3])

            # Calculate score based on timeout mechanisms
            score = 60  # Base score
            if timeout_indicators:
                score += 20
                # Check for reasonable timeout (1 hour or less)
                if any("1h" in indicator or "3600" in indicator for indicator in timeout_indicators):
                    score += 20

            return {
                "timeout_indicators_found": len(timeout_indicators),
                "timeout_indicators": timeout_indicators,
                "session_timeout_present": len(timeout_indicators) > 0,
                "score": min(score, 100)
            }

        except Exception as e:
            return {"error": str(e), "score": 40}

    async def test_session_hijacking(self):
        """Test session hijacking vulnerabilities"""
        try:
            # Test for session information leakage
            response = await self.session.get(self.target_url)
            content = response.text

            # Check for session information in URLs or headers
            session_leakage_indicators = [
                r"ssid=[^&\s]+",
                r"session_id=[^&\s]+",
                r"session_token=[^&\s]+",
                r"PHPSESSID=[^&\s]+",
                r"JSESSIONID=[^&\s]+"
            ]

            leakage_found = []
            for pattern in session_leakage_indicators:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    leakage_found.extend(matches[:3])

            # Check for predictable session IDs
            predictable_patterns = [
                r"session.*\d{4,}",
                r"session.*[a-f0-9]{8,}",
                r"session.*\b[a-f0-9]{8}\b[a-f0-9]{4}\b[a-f0-9]{4}\b[a-f0-9]{4}\b[a-f0-9]{12}\b"
            ]

            predictable_found = []
            for pattern in predictable_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    predictable_found.extend(matches[:3])

            # Calculate score (lower is better for vulnerabilities)
            vulnerability_score = len(leakage_found) * 10 + len(predictable_found) * 15
            score = max(0, 100 - vulnerability_score)

            return {
                "session_leakage_detected": len(leakage_found) > 0,
                "leakage_indicators": leakage_found,
                "predictable_sessions_detected": len(predictable_found) > 0,
                "predictable_indicators": predictable_found,
                "vulnerability_score": vulnerability_score,
                "score": score
            }

        except Exception as e:
            return {"error": str(e), "score": 70}

    async def token_security_analysis(self):
        """Analisis keamanan token"""
        try:
            # Test token generation
            generation_result = await self.test_token_generation()

            # Test token validation
            validation_result = await self.test_token_validation()

            # Test token exposure
            exposure_result = await self.test_token_exposure()

            # Test token refresh
            refresh_result = await self.test_token_refresh()

            return {
                "token_generation": generation_result,
                "token_validation": validation_result,
                "token_exposure": exposure_result,
                "token_refresh": refresh_result,
                "score": self.calculate_token_score([
                    generation_result, validation_result, exposure_result, refresh_result
                ])
            }

        except Exception as e:
            return {"error": str(e), "score": 0}

    async def test_token_generation(self):
        """Test token generation"""
        try:
            # Generate test tokens to analyze patterns
            tokens = []
            for i in range(5):
                # Generate different token types
                jwt_token = self.generate_jwt_token()
                bearer_token = self.generate_bearer_token()
                oauth_token = self.generate_oauth_token()

                tokens.extend([jwt_token, bearer_token, oauth_token])

            # Analyze token patterns
            token_patterns = {
                "jwt_tokens": len([t for t in tokens if t.startswith('eyJ')]),
                "bearer_tokens": len([t for t in tokens if t.startswith('Bearer ')]),
                "oauth_tokens": len([t for t in tokens if 'oauth' in t.lower()]),
                "random_tokens": len([t for t in tokens if len(t) > 32])
            }

            # Calculate token generation security score
            score = 70  # Base score
            score += token_patterns["random_tokens"] * 5
            score += token_patterns["jwt_tokens"] * 10  # JWT is generally secure

            return {
                "tokens_generated": len(tokens),
                "token_patterns": token_patterns,
                "secure_generation": token_patterns["random_tokens"] > 0,
                "score": min(score, 100)
            }

        except Exception as e:
            return {"error": str(e), "score": 0}

    async def test_token_validation(self):
        """Test token validation"""
        try:
            # Test with various token formats
            test_tokens = [
                self.generate_jwt_token(),
                "invalid_token",
                "",
                None,
                self.generate_jwt_token()[:-10]  # Truncated token
            ]

            validation_results = []
            for token in test_tokens:
                try:
                    # This is a simplified test - real validation would be more complex
                    is_valid = self.validate_token_format(token)
                    validation_results.append({
                        "token": token[:20] + "..." if token else "None",
                        "valid": is_valid,
                        "rejected": not is_valid
                    })
                except Exception as e:
                    validation_results.append({
                        "token": token[:20] + "..." if token else "None",
                        "valid": False,
                        "rejected": True,
                        "error": str(e)
                    })

            # Calculate validation security score
            proper_validation = sum(1 for r in validation_results if r["rejected"] and not r.get("error"))
            score = (proper_validation / len(test_tokens)) * 100

            return {
                "tokens_tested": len(test_tokens),
                "proper_validation": proper_validation,
                "validation_results": validation_results,
                "score": min(score, 100)
            }

        except Exception as e:
            return {"error": str(e), "score": 0}

    async def test_token_exposure(self):
        """Test token exposure"""
        try:
            # Check for tokens in various locations
            response = await self.session.get(self.target_url)
            content = response.text

            # Check for tokens in URLs
            url_tokens = re.findall(r'[?&]token=[^&\s]+', content)
            url_tokens.extend(re.findall(r'[?&]access_token=[^&\s]+', content))

            # Check for tokens in HTML comments
            comment_tokens = re.findall(r'<!--[^>]*token[^>]*-->', content, re.IGNORECASE)

            # Check for tokens in script tags
            script_tokens = re.findall(r'<script[^>]*>[^<]*token[^<]*</script>', content, re.IGNORECASE)

            # Calculate exposure score
            exposure_count = len(url_tokens) + len(comment_tokens) + len(script_tokens)
            score = max(0, 100 - exposure_count * 20)

            return {
                "url_tokens_found": len(url_tokens),
                "comment_tokens_found": len(comment_tokens),
                "script_tokens_found": len(script_tokens),
                "total_exposure": exposure_count,
                "exposure_detected": exposure_count > 0,
                "score": score
            }

        except Exception as e:
            return {"error": str(e), "score": 80}

    async def test_token_refresh(self):
        """Test token refresh mechanism"""
        try:
            # Check for refresh token patterns
            response = await self.session.get(self.target_url)
            content = response.text

            refresh_patterns = [
                r"refresh_token",
                r"token.*refresh",
                r"refresh.*token",
                r"token.*rotation",
                r"token.*rotate"
            ]

            refresh_indicators = []
            for pattern in refresh_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    refresh_indicators.extend(matches[:3])

            # Check for secure refresh mechanisms
            secure_refresh = len(refresh_indicators) > 0

            # Calculate refresh security score
            score = 60 if secure_refresh else 30
            if secure_refresh:
                score += 20  # Additional points for refresh mechanism

            return {
                "refresh_indicators_found": len(refresh_indicators),
                "refresh_indicators": refresh_indicators,
                "secure_refresh_mechanism": secure_refresh,
                "score": min(score, 100)
            }

        except Exception as e:
            return {"error": str(e), "score": 40}

    async def oauth2_vulnerability_testing(self):
        """Test kerentanan OAuth2"""
        try:
            # Open Redirect Testing
            redirect_result = await self.test_open_redirect()

            # CSRF Testing
            csrf_result = await self.test_oauth_csrf()

            # ClientID Leakage
            leakage_result = await self.test_client_id_leakage()

            # Authorization Code Interception
            interception_result = await self.test_code_interception()

            # PKCE Implementation
            pkce_result = await self.test_pkce_implementation()

            return {
                "open_redirect": redirect_result,
                "csrf_protection": csrf_result,
                "client_id_leakage": leakage_result,
                "code_interception": interception_result,
                "pkce_implementation": pkce_result,
                "score": self.calculate_vulnerability_score([
                    redirect_result, csrf_result, leakage_result, interception_result, pkce_result
                ])
            }

        except Exception as e:
            return {"error": str(e), "score": 0}

    async def test_open_redirect(self):
        """Test open redirect vulnerability"""
        try:
            # Test with various redirect URLs
            redirect_urls = [
                "https://evil.com",
                "javascript:alert('xss')",
                "data:text/html,<script>alert('xss')</script>",
                "//evil.com",
                "/evil.com"
            ]

            vulnerable_endpoints = []
            tested_endpoints = []

            for redirect_url in redirect_urls:
                try:
                    # Test in redirect_uri parameter
                    data = {"redirect_uri": redirect_url}
                    response = await self.session.post(self.target_url, data=data)

                    # Check if redirect is allowed
                    if response.status in [302, 301, 307, 308]:
                        location = response.headers.get('location', '')
                        if redirect_url in location or 'evil.com' in location:
                            vulnerable_endpoints.append(f"redirect_uri: {redirect_url}")

                except:
                    pass

            # Calculate score (lower is better for vulnerabilities)
            vulnerability_count = len(vulnerable_endpoints)
            score = max(0, 100 - vulnerability_count * 25)

            return {
                "redirect_urls_tested": len(redirect_urls),
                "vulnerable_redirects": vulnerability_count,
                "vulnerable_details": vulnerable_endpoints,
                "score": score
            }

        except Exception as e:
            return {"error": str(e), "score": 80}

    async def test_oauth_csrf(self):
        """Test OAuth2 CSRF protection"""
        try:
            response = await self.session.get(self.target_url)
            content = response.text

            # Check for state parameter usage
            state_patterns = [
                r'state=[^&\s]+',
                r'state_param',
                r'state_token',
                r'csrf_state',
                r'anti_csrf'
            ]

            state_indicators = []
            for pattern in state_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    state_indicators.extend(matches[:3])

            # Check for PKCE implementation
            pkce_patterns = [
                r'code_verifier',
                r'code_challenge',
                r'pkce',
                r'SHA256',
                r's256'
            ]

            pkce_indicators = []
            for pattern in pkce_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    pkce_indicators.extend(matches[:3])

            # Calculate CSRF protection score
            score = 50  # Base score
            if state_indicators:
                score += 30
            if pkce_indicators:
                score += 20

            return {
                "state_protection_detected": len(state_indicators) > 0,
                "state_indicators": state_indicators,
                "pkce_detected": len(pkce_indicators) > 0,
                "pkce_indicators": pkce_indicators,
                "csrf_protection_score": min(score, 100),
                "score": min(score, 100)
            }

        except Exception as e:
            return {"error": str(e), "score": 40}

    async def test_client_id_leakage(self):
        """Test client ID leakage"""
        try:
            response = await self.session.get(self.target_url)
            content = response.text

            # Look for client_id patterns
            client_id_patterns = [
                r'client_id=([^&\s]+)',
                r'client.*id.*["\']([^"\']+)["\']',
                r'clientId=([^&\s]+)',
                r'CLIENT_ID[^=]*=([^&\s]+)'
            ]

            leaked_client_ids = []
            for pattern in client_id_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    leaked_client_ids.extend(matches[:3])

            # Calculate score (lower is better for leakage)
            leakage_count = len(leaked_client_ids)
            score = max(0, 100 - leakage_count * 30)

            return {
                "client_id_patterns_tested": len(client_id_patterns),
                "leaked_client_ids": leakage_count,
                "leaked_details": leaked_client_ids,
                "client_id_leakage_detected": leakage_count > 0,
                "score": score
            }

        except Exception as e:
            return {"error": str(e), "score": 90}

    async def test_code_interception(self):
        """Test authorization code interception"""
        try:
            # Test for insecure code storage
            response = await self.session.get(self.target_url)
            content = response.text

            # Check for code storage patterns
            code_storage_patterns = [
                r'code.*storage',
                r'code.*cache',
                r'code.*session',
                r'code.*database',
                r'code.*file'
            ]

            storage_indicators = []
            for pattern in code_storage_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    storage_indicators.extend(matches[:3])

            # Check for short-lived codes
            short_code_indicators = [
                r'code.*expir',
                r'code.*timeout',
                r'code.*short',
                r'code.*1m',
                r'code.*5m'
            ]

            timeout_indicators = []
            for pattern in short_code_indicators:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    timeout_indicators.extend(matches[:3])

            # Calculate interception security score
            score = 70  # Base score
            if storage_indicators:
                score += 10
            if timeout_indicators:
                score += 20

            return {
                "storage_indicators_found": len(storage_indicators),
                "timeout_indicators_found": len(timeout_indicators),
                "secure_storage_detected": len(storage_indicators) > 0,
                "secure_timeout_detected": len(timeout_indicators) > 0,
                "score": min(score, 100)
            }

        except Exception as e:
            return {"error": str(e), "score": 60}

    async def test_pkce_implementation(self):
        """Test PKCE implementation"""
        try:
            response = await self.session.get(self.target_url)
            content = response.text

            # Check for PKCE components
            pkce_components = {
                "code_verifier": r'code_verifier=[^&\s]+',
                "code_challenge": r'code_challenge=[^&\s]+',
                "code_challenge_method": r'code_challenge_method=[^&\s]+',
                "pkce_header": r'PKCE',
                "s256_method": r'SHA256|S256'
            }

            found_components = {}
            for component, pattern in pkce_components.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                found_components[component] = len(matches) > 0

            # Calculate PKCE implementation score
            implemented_components = sum(1 for found in found_components.values() if found)
            score = (implemented_components / len(pkce_components)) * 100

            return {
                "pkce_components_tested": len(pkce_components),
                "components_implemented": implemented_components,
                "components_found": found_components,
                "pkce_properly_implemented": implemented_components >= 3,  # Most components needed
                "score": min(score, 100)
            }

        except Exception as e:
            return {"error": str(e), "score": 0}

    # Helper methods
    def generate_jwt_token(self):
        """Generate JWT token for testing"""
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip('=')
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "1234567890", "name": "Test User", "iat": int(time.time())}).encode()).decode().rstrip('=')
        signature = hashlib.sha256(f"{header}.{payload}".encode()).hexdigest()
        return f"eyJ{header}.{payload}.{signature}"

    def generate_bearer_token(self):
        """Generate Bearer token for testing"""
        return f"Bearer {''.join(random.choices(string.ascii_letters + string.digits, k=32))}"

    def generate_oauth_token(self):
        """Generate OAuth token for testing"""
        return f"oauth_token_{''.join(random.choices(string.ascii_letters + string.digits, k=16))}"

    def validate_token_format(self, token):
        """Validate token format"""
        if not token:
            return False
        if len(token) < 10:
            return False
        # Basic format validation
        return any(char.isalnum() for char in token)

    def calculate_provider_score(self, detected_providers, provider_details):
        """Calculate provider detection score"""
        if not detected_providers:
            return 0

        total_score = 0
        for provider in detected_providers:
            total_score += provider_details.get(provider, {}).get('security_score', 0)

        return total_score / len(detected_providers)

    def calculate_flow_score(self, detected_flows, flow_details):
        """Calculate flow detection score"""
        if not detected_flows:
            return 0

        total_score = 0
        for flow in detected_flows:
            total_score += flow_details.get(flow, {}).get('security_score', 0)

        return total_score / len(detected_flows)

    def calculate_session_score(self, results):
        """Calculate session security score"""
        scores = [r.get('score', 0) for r in results if isinstance(r, dict) and 'score' in r]
        return sum(scores) / len(scores) if scores else 0

    def calculate_token_score(self, results):
        """Calculate token security score"""
        scores = [r.get('score', 0) for r in results if isinstance(r, dict) and 'score' in r]
        return sum(scores) / len(scores) if scores else 0

    def calculate_vulnerability_score(self, results):
        """Calculate vulnerability test score"""
        scores = [r.get('score', 100) for r in results if isinstance(r, dict) and 'score' in r]
        return sum(scores) / len(scores) if scores else 100

    def generate_summary_report(self, results):
        """Generate summary report"""
        summary = {
            "analysis_completed": True,
            "overall_score": 0,
            "risk_level": "Unknown",
            "security_findings": {},
            "recommendations": [],
            "next_steps": []
        }

        # Calculate overall score
        all_scores = []
        for category_name, category_data in results.items():
            if isinstance(category_data, dict) and 'score' in category_data:
                all_scores.append(category_data['score'])

        if all_scores:
            summary["overall_score"] = sum(all_scores) / len(all_scores)

        # Determine risk level
        if summary["overall_score"] >= 80:
            summary["risk_level"] = "Low"
        elif summary["overall_score"] >= 60:
            summary["risk_level"] = "Medium"
        elif summary["overall_score"] >= 40:
            summary["risk_level"] = "High"
        else:
            summary["risk_level"] = "Critical"

        # Generate recommendations based on findings
        recommendations = []

        # Provider detection recommendations
        providers = results.get("provider_detection", {}).get("detected_providers", [])
        if providers:
            recommendations.append(f"Detected OAuth2 providers: {', '.join(providers)}")

        # Security recommendations
        if summary["overall_score"] < 60:
            recommendations.append("Implement OAuth2 security improvements")

        # Specific recommendations
        if "authorization_code" in results.get("flow_analysis", {}).get("detected_flows", []):
            recommendations.append("Ensure PKCE implementation for authorization code flow")

        if not results.get("vulnerability_testing", {}).get("csrf_protection", {}).get("score", 0) > 60:
            recommendations.append("Implement proper CSRF protection with state parameter")

        summary["recommendations"] = recommendations
        summary["next_steps"] = recommendations  # Same as recommendations for now

        return summary

    async def save_report(self, results):
        """Save report to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"oauth2_session_analysis_{timestamp}.json"

        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"📊 Report saved to: {filename}")
        return filename


async def main():
    """Main execution function"""
    target_url = "https://airdrop.0gfoundation.ai"

    print("🔍 OAuth2 Session Analyzer")
    print("=" * 60)
    print(f"🎯 Target: {target_url}")
    print("=" * 60)

    analyzer = OAuth2SessionAnalyzer(target_url)
    results = await analyzer.run_oauth2_analysis()

    if results:
        # Save report
        await analyzer.save_report(results)

        print(f"\n✅ OAuth2 Session Analysis completed!")
        print(f"📊 Overall Score: {results['summary']['overall_score']:.1f}/100")
        print(f"🎯 Risk Level: {results['summary']['risk_level']}")
        print(f"⏱️ Scan Duration: {results['scan_duration']:.2f} seconds")

        # Show detected providers
        providers = results.get("provider_detection", {}).get("detected_providers", [])
        if providers:
            print(f"🏢 Detected Providers: {', '.join(providers)}")

        # Show recommendations
        if results['summary']['recommendations']:
            print(f"💡 Recommendations:")
            for rec in results['summary']['recommendations']:
                print(f"   • {rec}")

        return results
    else:
        print("❌ Analysis failed!")
        return None


if __name__ == "__main__":
    asyncio.run(main())