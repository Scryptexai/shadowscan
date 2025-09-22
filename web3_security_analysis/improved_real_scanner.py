#!/usr/bin/env python3
"""
IMPROVED REAL SECURITY SCANNER
Scanner real-time yang lebih akurat dengan deteksi vulnerability yang realistis
System modular untuk testing berbagai target dengan false positive reduction
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
import re

class ImprovedRealSecurityScanner:
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

        # Store baseline responses for comparison
        self.baseline_responses = {}

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

    def get_baseline_response(self, endpoint=""):
        """Get baseline response for comparison"""
        cache_key = f"baseline_{endpoint}"

        if cache_key not in self.baseline_responses:
            try:
                url = f"http://{self.target}{endpoint}"
                response = self.session.get(url, timeout=10)

                if response.status_code == 200 and len(response.text) > 100:
                    self.baseline_responses[cache_key] = {
                        'status_code': response.status_code,
                        'content_length': len(response.text),
                        'content_hash': self.get_content_hash(response.text),
                        'response_text': response.text
                    }
                else:
                    self.baseline_responses[cache_key] = None

            except Exception:
                self.baseline_responses[cache_key] = None

        return self.baseline_responses[cache_key]

    def get_content_hash(self, text):
        """Simple hash for content comparison"""
        return str(hash(text))

    def check_significant_change(self, response_text, baseline_data):
        """Check if response shows significant change (potential vulnerability)"""
        if not baseline_data:
            return False

        current_length = len(response_text)
        baseline_length = baseline_data['content_length']
        length_diff = abs(current_length - baseline_length)

        # Significant change threshold
        if length_diff < 500:  # Threshold to avoid false positives
            return False

        # Check for actual payload reflection (not just length difference)
        current_hash = self.get_content_hash(response_text)

        # Check if payload patterns exist in response
        payload_indicators = [
            r'<script[^>]*>.*?</script>',
            r'onerror\s*=',
            r'onclick\s*=',
            r'onload\s*=',
            r'javascript:',
            r'vbscript:',
            r'expression\(',
            r'alert\(',
            r'confirm\(',
            r'prompt\('
        ]

        payload_detected = any(re.search(pattern, response_text, re.IGNORECASE)
                             for pattern in payload_indicators)

        return payload_detected

    def real_xss_scanner(self):
        """Real XSS vulnerability scanner with improved detection"""
        baseline = self.get_baseline_response()
        if not baseline:
            return {"total_tests": 0, "successful_xss": 0, "blocked_xss": 0}

        xss_endpoints = ["", "?id=1", "?search=test", "?category=test", "?page=1"]
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<ScRiPt>alert('XSS')</sCrIpT>",
            "<div style=expression(alert('XSS'))>"
        ]

        xss_results = {"total_tests": 0, "successful_xss": 0, "blocked_xss": 0}

        def test_xss(endpoint, payload):
            xss_results["total_tests"] += 1

            try:
                url = f"http://{self.target}{endpoint}"
                if endpoint:
                    test_url = f"{url}{endpoint}?{payload}"
                else:
                    test_url = f"{url}?{payload}"

                response = self.session.get(test_url, timeout=10)

                if (response.status_code == 200 and
                    len(response.text) > 100 and
                    'html' in response.text.lower()):

                    # Check for significant changes and payload reflection
                    if self.check_significant_change(response.text, baseline):
                        xss_results["successful_xss"] += 1
                        self.log_result("XSS", endpoint, payload, "VULNERABLE", {
                            "payload_detected": True,
                            "response_length": len(response.text),
                            "baseline_length": baseline['content_length'],
                            "length_difference": len(response.text) - baseline['content_length']
                        })
                    else:
                        xss_results["blocked_xss"] += 1
                        self.log_result("XSS", endpoint, payload, "BLOCKED", {
                            "response_length": len(response.text),
                            "note": "No significant change detected"
                        })
                else:
                    xss_results["blocked_xss"] += 1
                    self.log_result("XSS", endpoint, payload, "NO_RESPONSE", {
                        "status_code": response.status_code
                    })

            except Exception as e:
                xss_results["blocked_xss"] += 1
                self.log_result("XSS", endpoint, payload, "ERROR", {"error": str(e)})

        # Test XSS with threading
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(test_xss, endpoint, payload)
                     for endpoint in xss_endpoints for payload in xss_payloads]
            for future in as_completed(futures):
                future.result()

        return xss_results

    def real_sql_injection_scanner(self):
        """Real SQL injection vulnerability scanner"""
        baseline = self.get_baseline_response()
        if not baseline:
            return {"total_tests": 0, "successful_sql": 0, "blocked_sql": 0}

        sql_endpoints = ["", "?id=1", "?search=test", "?user=admin", "?page=1"]
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'--",
            "'#",
            "'/*"
        ]

        sql_results = {"total_tests": 0, "successful_sql": 0, "blocked_sql": 0}

        def test_sql(endpoint, payload):
            sql_results["total_tests"] += 1

            try:
                url = f"http://{self.target}{endpoint}"
                if endpoint:
                    test_url = f"{url}{endpoint}?{payload}"
                else:
                    test_url = f"{url}?{payload}"

                response = self.session.get(test_url, timeout=10)

                if (response.status_code == 200 and
                    len(response.text) > 100 and
                    'html' in response.text.lower()):

                    # Check for SQL error patterns or significant changes
                    sql_error_patterns = [
                        r'sql\s+syntax\s+error',
                        r'mysql_fetch',
                        r'postgresql\s+error',
                        r'ora-[0-9]+',
                        r'microsoft\s+ole\s+db',
                        r'unclosed\s+quote',
                        r'unclosed\s+string'
                    ]

                    sql_detected = any(re.search(pattern, response.text, re.IGNORECASE)
                                    for pattern in sql_error_patterns)

                    length_diff = abs(len(response.text) - baseline['content_length'])

                    if sql_detected or length_diff > 1000:
                        sql_results["successful_sql"] += 1
                        self.log_result("SQL Injection", endpoint, payload, "VULNERABLE", {
                            "sql_error_detected": sql_detected,
                            "response_length": len(response.text),
                            "length_difference": length_diff
                        })
                    else:
                        sql_results["blocked_sql"] += 1
                        self.log_result("SQL Injection", endpoint, payload, "BLOCKED", {
                            "response_length": len(response.text)
                        })
                else:
                    sql_results["blocked_sql"] += 1
                    self.log_result("SQL Injection", endpoint, payload, "NO_RESPONSE", {
                        "status_code": response.status_code
                    })

            except Exception as e:
                sql_results["blocked_sql"] += 1
                self.log_result("SQL Injection", endpoint, payload, "ERROR", {"error": str(e)})

        # Test SQL with threading
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(test_sql, endpoint, payload)
                     for endpoint in sql_endpoints for payload in sql_payloads]
            for future in as_completed(futures):
                future.result()

        return sql_results

    def run_full_scan(self):
        """Run complete security assessment"""
        print(f"🚀 Starting IMPROVED security scan for: {self.target}")
        print("=" * 80)

        # Get baseline responses first
        print("\n🔍 Establishing baseline responses...")
        self.get_baseline_response()

        # Run vulnerability scanners
        scan_results = {}

        print("\n🎯 Phase 1: XSS Vulnerability Assessment")
        scan_results['xss'] = self.real_xss_scanner()

        print("\n🎯 Phase 2: SQL Injection Assessment")
        scan_results['sql'] = self.real_sql_injection_scanner()

        # Generate report
        report = self.generate_comprehensive_report()

        return report

    def generate_comprehensive_report(self):
        """Generate comprehensive security report for target"""
        print(f"\n📊 GENERATING IMPROVED SECURITY REPORT FOR {self.target.upper()}")
        print("=" * 80)

        # Count results
        total_tests = len([r for r in self.results if r['test_type'] in ['XSS', 'SQL Injection']])
        successful_tests = len([r for r in self.results if r['result'] == 'VULNERABLE'])
        blocked_tests = len([r for r in self.results if r['result'] == 'BLOCKED'])
        error_tests = len([r for r in self.results if r['result'] == 'ERROR'])

        # Risk assessment
        if successful_tests > 5:
            risk_level = "CRITICAL"
        elif successful_tests > 2:
            risk_level = "HIGH"
        elif successful_tests > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Generate report
        report = {
            f"{self.target}_security_report": {
                "target": self.target,
                "scan_date": datetime.now().isoformat(),
                "scan_type": "Improved Real Security Assessment",
                "assessment_method": "Live Testing with Baseline Comparison",
                "baseline_used": True,
                "false_positive_reduction": True,
                "scan_metrics": {
                    "total_tests": total_tests,
                    "successful_tests": successful_tests,
                    "blocked_tests": blocked_tests,
                    "error_tests": error_tests,
                    "risk_level": risk_level,
                    "impact_assessment": "Medium risk of system compromise" if risk_level != "LOW" else "No significant vulnerabilities detected"
                },
                "detailed_findings": self.results,
                "recommendations": self.generate_recommendations(risk_level, successful_tests)
            }
        }

        # Save report
        filename = f"{self.target}_improved_security_report.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"✅ Improved security report saved: {filename}")

        # Summary
        print(f"\n🎯 IMPROVED SECURITY SUMMARY FOR {self.target.upper()}")
        print("=" * 80)
        print(f"📊 Risk Level: {risk_level}")
        print(f"🔍 Total Tests: {total_tests}")
        print(f"💉 Vulnerabilities Found: {successful_tests}")
        print(f"🚗 Blocked Attempts: {blocked_tests}")
        print(f"❌ Errors: {error_tests}")

        if successful_tests > 0:
            print(f"\n🔴 VULNERABILITIES DETECTED:")
            for finding in [f for f in self.results if f['result'] == 'VULNERABLE']:
                print(f"   • {finding['test_type']} - {finding['payload']}")
        else:
            print("\n🟢 NO CRITICAL VULNERABILITIES DETECTED")

        return report

    def generate_recommendations(self, risk_level, successful_tests):
        """Generate security recommendations"""
        if risk_level == "CRITICAL":
            return [
                {
                    "priority": "CRITICAL",
                    "recommendation": "Immediate security assessment required",
                    "action": "Deploy WAF, implement input validation, and conduct penetration testing"
                }
            ]
        elif risk_level == "HIGH":
            return [
                {
                    "priority": "HIGH",
                    "recommendation": "Security vulnerabilities detected",
                    "action": "Implement proper input filtering and parameterized queries"
                }
            ]
        else:
            return [
                {
                    "priority": "MEDIUM",
                    "recommendation": "Basic security measures in place",
                    "action": "Continue monitoring and regular security assessments"
                }
            ]

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 improved_real_scanner.py <target1> <target2> <target3>")
        sys.exit(1)

    targets = sys.argv[1:]

    for target in targets:
        print(f"\n🎯 SCANNING: {target}")
        print("-" * 40)

        scanner = ImprovedRealSecurityScanner(target)
        report = scanner.run_full_scan()
        print(f"✅ COMPLETED: {target}")
        print("-" * 40)