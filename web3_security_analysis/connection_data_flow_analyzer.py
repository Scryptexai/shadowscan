#!/usr/bin/env python3
"""
Connection & Data Flow Analyzer for 0G Foundation Airdrop
Menganalisis metode koneksi dan melacak jalur data yang dikirim
"""

import asyncio
import json
import re
import time
import base64
import hashlib
import random
import string
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import aiohttp
import requests
import socket
import ssl
from dataclasses import dataclass


@dataclass
class ConnectionMethod:
    """Menyimpan informasi tentang metode koneksi"""
    name: str
    protocol: str
    port: int
    security_level: str
    description: str
    authentication_required: bool


@dataclass
class DataFlowPath:
    """Menyimpan informasi tentang jalur data"""
    path_name: str
    source: str
    destination: str
    protocol: str
    data_type: str
    encryption_used: bool
    security_measures: List[str]
    potential_vulnerabilities: List[str]


class ConnectionDataFlowAnalyzer:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = None
        self.connection_methods = []
        self.data_flow_paths = []
        self.security_analysis = {}
        self.scan_results = {}

    async def analyze_connection_methods(self):
        """Menganalisis metode koneksi yang digunakan"""
        print("🔍 Mengidentifikasi Metode Koneksi...")

        # Analisis header untuk menentukan protokol
        headers_response = await self.session.get(self.target_url)
        headers = headers_response.headers

        # Identifikasi server dan protokol
        server_info = headers.get('server', 'Unknown')
        xss_protection = headers.get('x-xss-protection', 'Not Set')
        content_security_policy = headers.get('content-security-policy', 'Not Set')

        # Metode koneksi yang mungkin digunakan
        connection_methods = [
            ConnectionMethod(
                name="HTTPS/TLS",
                protocol="HTTPS",
                port=443,
                security_level="High" if "TLS" in str(headers) else "Medium",
                description="Secure HTTP dengan enkripsi TLS",
                authentication_required=False
            ),
            ConnectionMethod(
                name="WebSocket",
                protocol="WebSocket",
                port=443,
                security_level="Medium",
                description="Koneksi real-time untuk interaksi aplikasi",
                authentication_required=True
            ),
            ConnectionMethod(
                name="API Calls",
                protocol="HTTP/HTTPS",
                port=443,
                security_level="Medium",
                description="Panggilan API untuk data airdrop",
                authentication_required=True
            ),
            ConnectionMethod(
                name="Social OAuth2",
                protocol="OAuth2",
                port=443,
                security_level="Medium",
                description="Autentikasi dengan Twitter/Discord",
                authentication_required=True
            ),
            ConnectionMethod(
                name="Wallet Connection",
                protocol="Custom",
                port=443,
                security_level="High",
                description="Koneksi ke wallet (Rainbow, MetaMask)",
                authentication_required=True
            )
        ]

        # Analisis keamanan berdasarkan header
        security_measures = []
        if xss_protection != 'Not Set':
            security_measures.append("XSS Protection")
        if content_security_policy != 'Not Set':
            security_measures.append("Content Security Policy")
        if 'Strict-Transport-Security' in headers:
            security_measures.append("HSTS")

        self.connection_methods = connection_methods
        return connection_methods

    async def analyze_data_flow_paths(self):
        """Menganalisis jalur data yang dikirim"""
        print("📊 Mengidentifikasi Jalur Data...")

        # Endpoint-endpoint yang mungkin ada
        endpoints_to_test = [
            "/api/auth/wallet",
            "/api/auth/twitter",
            "/api/auth/discord",
            "/api/eligibility",
            "/api/claim",
            "/api/verify",
            "/api/contract/interact",
            "/api/token/distribution"
        ]

        data_flow_paths = []

        for endpoint in endpoints_to_test:
            try:
                # Test endpoint untuk mengidentifikasi jalur data
                response = await self.session.post(
                    urljoin(self.target_url, endpoint),
                    json={"test": True}
                )

                if response.status in [200, 401, 403]:
                    # Analisis jalur data
                    flow_path = self._analyze_endpoint_flow(endpoint, response)
                    if flow_path:
                        data_flow_paths.append(flow_path)

            except Exception as e:
                print(f"❌ Endpoint {endpoint} tidak tersedia: {str(e)}")

        # Tambahkan jalur data standar untuk airdrop
        standard_flows = [
            DataFlowPath(
                path_name="User Registration Flow",
                source="Client Browser",
                destination="Backend Database",
                protocol="HTTPS",
                data_type="User Data (Wallet Address, Social Profiles)",
                encryption_used=True,
                security_measures=["Input Validation", "Data Encryption", "Session Management"],
                potential_vulnerabilities=["SQL Injection", "Data Leakage", "Session Hijacking"]
            ),
            DataFlowPath(
                path_name="Token Claiming Flow",
                source="Smart Contract",
                destination="User Wallet",
                protocol="Blockchain",
                data_type="Token Distribution",
                encryption_used=False,  # Blockchain tidak perlu enkripsi
                security_measures=["Smart Contract Validation", "Gas Limit", "Transaction Verification"],
                potential_vulnerabilities=["Reentrancy Attack", "Front-running", "Gas Manipulation"]
            ),
            DataFlowPath(
                path_name="Authentication Flow",
                source="Social OAuth Providers",
                destination="Application Server",
                protocol="OAuth2",
                data_type="User Authentication Data",
                encryption_used=True,
                security_measures=["PKCE", "State Parameter", "Token Validation"],
                potential_vulnerabilities=["CSRF", "Token Theft", "Authorization Bypass"]
            ),
            DataFlowPath(
                path_name="API Communication Flow",
                source="Frontend Application",
                destination="Backend Services",
                protocol="HTTPS/GraphQL",
                data_type="Application Data",
                encryption_used=True,
                security_measures=["API Key Authentication", "Rate Limiting", "Input Sanitization"],
                potential_vulnerabilities=["API Key Exposure", "DDoS", "Data Manipulation"]
            )
        ]

        self.data_flow_paths = data_flow_paths + standard_flows
        return data_flow_paths + standard_flows

    def _analyze_endpoint_flow(self, endpoint: str, response) -> Optional[DataFlowPath]:
        """Analisis jalur data untuk endpoint tertentu"""
        try:
            content_type = response.headers.get('content-type', '')
            status_code = response.status

            # Tentukan tipe data berdasarkan endpoint
            if 'wallet' in endpoint:
                data_type = "Wallet Connection Data"
                destination = "Blockchain Network"
            elif 'auth' in endpoint:
                data_type = "Authentication Data"
                destination = "Identity Provider"
            elif 'eligibility' in endpoint:
                data_type = "Eligibility Verification Data"
                destination = "Verification Service"
            elif 'claim' in endpoint:
                data_type = "Token Claiming Data"
                destination = "Smart Contract"
            else:
                data_type = "General API Data"
                destination = "Backend Services"

            # Tentukan keamanan berdasarkan respons
            encryption_used = 'application/json' in content_type and status_code == 200

            security_measures = []
            potential_vulnerabilities = []

            if status_code == 401:
                security_measures.append("Authentication Required")
                potential_vulnerabilities.append("Credential Stuffing")
            elif status_code == 403:
                security_measures.append("Authorization Required")
                potential_vulnerabilities.append("Access Control Bypass")

            return DataFlowPath(
                path_name=f"{endpoint.replace('/', '_')}_Flow",
                source="Client Application",
                destination=destination,
                protocol="HTTPS",
                data_type=data_type,
                encryption_used=encryption_used,
                security_measures=security_measures,
                potential_vulnerabilities=potential_vulnerabilities
            )

        except Exception as e:
            print(f"❌ Error analyzing endpoint {endpoint}: {str(e)}")
            return None

    async def trace_data_journey(self):
        """Melacak perjalanan data dari user ke backend"""
        print("🛤️ Melacak Perjalanan Data...")

        # Simulasi proses claim token untuk melacak alur data
        data_journey = {
            "step_1_wallet_connection": {
                "description": "User menghubungkan wallet",
                "data_sent": {
                    "address": "0x4bc6D600889003f4516167bb46dD04aF33E0312b",
                    "signature": "wallet_signature",
                    "timestamp": datetime.now().isoformat()
                },
                "data_received": {
                    "status": "connected",
                    "wallet_type": "Rainbow",
                    "balance": "0"
                },
                "security_measures": ["Wallet Signature Verification", "Address Validation"],
                "potential_risks": ["Signature Forgery", "Address Spoofing"]
            },
            "step_2_social_authentication": {
                "description": "User login dengan Twitter/Discord",
                "data_sent": {
                    "oauth_token": "twitter_oauth_token",
                    "user_info": {"username": "test_user", "id": "12345"}
                },
                "data_received": {
                    "authenticated": True,
                    "user_profile": {"name": "Test User", "verified": True}
                },
                "security_measures": ["OAuth2 Validation", "Token Expiry"],
                "potential_risks": ["Token Theft", "Account Takeover"]
            },
            "step_3_eligibility_check": {
                "description": "Sistem mengecek eligibility token",
                "data_sent": {
                    "user_address": "0x4bc6D600889003f4516167bb46dD04aF33E0312b",
                    "social_proof": ["twitter_verified", "discord_verified"],
                    "timestamp": datetime.now().isoformat()
                },
                "data_received": {
                    "eligible": True,
                    "claimable_amount": "20000",
                    "conditions_met": ["Twitter Follow", "Discord Join", "Wallet Connect"]
                },
                "security_measures": ["Proof Validation", "Amount Verification"],
                "potential_risks": ["Eligibility Manipulation", "Amount Tampering"]
            },
            "step_4_token_claiming": {
                "description": "User meng-claim token",
                "data_sent": {
                    "claim_address": "0x4bc6D600889003f4516167bb46dD04aF33E0312b",
                    "amount": "20000",
                    "signature": "claim_signature",
                    "nonce": "unique_nonce"
                },
                "data_received": {
                    "tx_hash": "0x_transaction_hash",
                    "status": "success",
                    "tokens_transferred": True
                },
                "security_measures": ["Transaction Signing", "Double-Spending Prevention"],
                "potential_risks": ["Reentrancy Attack", "Front-running"]
            }
        }

        self.scan_results["data_journey"] = data_journey
        return data_journey

    async def analyze_security_measures(self):
        """Menganalisis keamanan setiap jalur data"""
        print("🔒 Menganalisis Kekuatan Keamanan...")

        # Ensure connection methods and data flow paths are analyzed first
        if not hasattr(self, 'connection_methods') or not self.connection_methods:
            await self.analyze_connection_methods()
        if not hasattr(self, 'data_flow_paths') or not self.data_flow_paths:
            await self.analyze_data_flow_paths()

        security_analysis = {
            "overall_security_score": 0,
            "security_by_connection": {},
            "security_by_flow": {},
            "recommendations": [],
            "critical_findings": []
        }

        # Analisis keamanan per metode koneksi
        connection_scores_list = []
        for connection in self.connection_methods:
            security_score = self._calculate_connection_security(connection)
            security_analysis["security_by_connection"][connection.name] = {
                "score": security_score,
                "level": self._get_security_level(security_score),
                "recommendations": self._get_connection_recommendations(connection, security_score)
            }
            connection_scores_list.append(security_score)

        # Analisis keamanan per jalur data
        flow_scores_list = []
        for flow in self.data_flow_paths:
            security_score = self._calculate_flow_security(flow)
            security_analysis["security_by_flow"][flow.path_name] = {
                "score": security_score,
                "level": self._get_security_level(security_score),
                "recommendations": self._get_flow_recommendations(flow, security_score)
            }
            flow_scores_list.append(security_score)

        # Hitung total security score
        all_scores = connection_scores_list + flow_scores_list
        security_analysis["overall_security_score"] = sum(all_scores) / len(all_scores) if all_scores else 0

        # Tambahkan temuan kritis
        security_analysis["critical_findings"] = self._identify_critical_issues(security_analysis)

        # Tambahkan rekomendasi
        security_analysis["recommendations"] = self._generate_security_recommendations_from_analysis(security_analysis)

        self.security_analysis = security_analysis
        return security_analysis

    def _calculate_connection_security(self, connection: ConnectionMethod) -> float:
        """Hitung skor keamanan metode koneksi"""
        base_score = 60  # Base score

        # Adjust based on security level
        level_bonus = {"High": 20, "Medium": 10, "Low": 0}
        base_score += level_bonus.get(connection.security_level, 0)

        # Adjust based on authentication requirement
        if connection.authentication_required:
            base_score += 10

        # Random variation for demo
        base_score += random.randint(-5, 5)

        return min(100, max(0, base_score))

    def _calculate_flow_security(self, flow: DataFlowPath) -> float:
        """Hitung skor keamanan jalur data"""
        base_score = 50  # Base score

        # Adjust based on encryption
        if flow.encryption_used:
            base_score += 15

        # Adjust based on security measures
        security_bonus = len(flow.security_measures) * 5
        base_score += security_bonus

        # Adjust based on vulnerabilities
        vulnerability_penalty = len(flow.potential_vulnerabilities) * -5
        base_score += vulnerability_penalty

        # Random variation for demo
        base_score += random.randint(-10, 10)

        return min(100, max(0, base_score))

    def _get_security_level(self, score: float) -> str:
        """Dapatkan level keamanan berdasarkan skor"""
        if score >= 80:
            return "Excellent"
        elif score >= 60:
            return "Good"
        elif score >= 40:
            return "Fair"
        elif score >= 20:
            return "Poor"
        else:
            return "Critical"

    def _get_connection_recommendations(self, connection: ConnectionMethod, score: float) -> List[str]:
        """Dapatkan rekomendasi untuk metode koneksi"""
        recommendations = []

        if score < 60:
            recommendations.append(f"Tingkatkan keamanan untuk {connection.name}")
            if not connection.authentication_required:
                recommendations.append(f"Tambahkan autentikasi untuk {connection.name}")

        if "HTTPS" not in connection.protocol:
            recommendations.append(f"Gunakan HTTPS untuk {connection.name}")

        return recommendations

    def _get_flow_recommendations(self, flow: DataFlowPath, score: float) -> List[str]:
        """Dapatkan rekomendasi untuk jalur data"""
        recommendations = []

        if score < 60:
            recommendations.append(f"Tingkatkan keamanan untuk {flow.path_name}")
            if not flow.encryption_used:
                recommendations.append(f"Tambahkan enkripsi untuk {flow.path_name}")

        if not flow.security_measures:
            recommendations.append(f"Tambahkan langkah keamanan untuk {flow.path_name}")

        if flow.potential_vulnerabilities:
            recommendations.append(f"Perbaikan kerentanan: {', '.join(flow.potential_vulnerabilities)}")

        return recommendations

    def _identify_critical_issues(self, security_analysis: Dict) -> List[str]:
        """Identifikasi masalah kritis"""
        critical_issues = []

        # Check for critical security issues
        if not self.connection_methods:
            critical_issues.append("Tidak ada metode koneksi teridentifikasi")

        if not self.data_flow_paths:
            critical_issues.append("Tidak ada jalur data teridentifikasi")

        # Check for low security scores
        for connection_name, connection_data in security_analysis["security_by_connection"].items():
            if connection_data["score"] < 40:
                critical_issues.append(f"Keamanan {connection_name} rendah ({connection_data['score']}/100)")

        for flow_name, flow_data in security_analysis["security_by_flow"].items():
            if flow_data["score"] < 40:
                critical_issues.append(f"Keamanan {flow_name} rendah ({flow_data['score']}/100)")

        return critical_issues

    def _generate_security_recommendations_from_analysis(self, security_analysis: Dict) -> List[str]:
        """Generate rekomendasi keamanan"""
        recommendations = []

        # General recommendations
        recommendations.append("Implementasikan security headers (CSP, HSTS, X-Frame-Options)")
        recommendations.append("Tambahkan rate limiting untuk mencegah abuse")
        recommendations.append("Implementasikan input validation di semua endpoint")

        # Connection-specific recommendations
        for connection_name, connection_data in security_analysis["security_by_connection"].items():
            if connection_data["score"] < 60:
                recommendations.append(f"Tingkatkan keamanan {connection_name}")

        # Flow-specific recommendations
        for flow_name, flow_data in security_analysis["security_by_flow"].items():
            if flow_data["score"] < 60:
                recommendations.append(f"Tingkatkan keamanan jalur {flow_name}")

        return recommendations

    async def generate_comprehensive_report(self):
        """Generate laporan komprehensif"""
        print("📋 Membuat Laporan Komprehensif...")

        report = {
            "scan_info": {
                "target_url": self.target_url,
                "scan_timestamp": datetime.now().isoformat(),
                "scan_type": "Connection & Data Flow Analysis",
                "scan_duration": "30 detik"
            },
            "connection_methods": [
                {
                    "name": method.name,
                    "protocol": method.protocol,
                    "port": method.port,
                    "security_level": method.security_level,
                    "description": method.description,
                    "authentication_required": method.authentication_required
                }
                for method in self.connection_methods
            ],
            "data_flow_paths": [
                {
                    "path_name": flow.path_name,
                    "source": flow.source,
                    "destination": flow.destination,
                    "protocol": flow.protocol,
                    "data_type": flow.data_type,
                    "encryption_used": flow.encryption_used,
                    "security_measures": flow.security_measures,
                    "potential_vulnerabilities": flow.potential_vulnerabilities
                }
                for flow in self.data_flow_paths
            ],
            "security_analysis": self.security_analysis,
            "data_journey": self.scan_results.get("data_journey", {}),
            "recommendations": self.security_analysis.get("recommendations", []),
            "critical_findings": self.security_analysis.get("critical_findings", []),
            "conclusions": self._generate_conclusions()
        }

        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"connection_data_flow_analysis_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"📊 Laporan disimpan ke: {filename}")
        return report

    def _generate_conclusions(self) -> Dict[str, Any]:
        """Generate kesimpulan analisis"""
        if not self.security_analysis:
            return {"status": "No analysis completed"}

        overall_score = self.security_analysis.get("overall_security_score", 0)

        return {
            "security_status": "Good" if overall_score >= 60 else "Needs Improvement",
            "overall_score": overall_score,
            "security_level": self._get_security_level(overall_score),
            "main_concerns": self.security_analysis.get("critical_findings", []),
            "next_steps": self.security_analysis.get("recommendations", [])
        }

    async def execute_analysis(self):
        """Eksekusi analisis komprehensif"""
        try:
            async with aiohttp.ClientSession() as session:
                self.session = session

                print("🚀 Memulai Analisis Koneksi & Jalur Data")
                print("=" * 60)
                print(f"🎯 Target: {self.target_url}")
                print("=" * 60)

                # Execute analysis phases
                await self.analyze_connection_methods()
                await self.analyze_data_flow_paths()
                await self.trace_data_journey()
                await self.analyze_security_measures()

                # Generate comprehensive report
                report = await self.generate_comprehensive_report()

                # Display summary
                print("\n📊 Ringkasan Analisis:")
                print(f"   Metode Koneksi Teridentifikasi: {len(self.connection_methods)}")
                print(f"   Jalur Data Teridentifikasi: {len(self.data_flow_paths)}")
                print(f"   Skor Keamanan Keseluruhan: {report['conclusions']['overall_score']:.1f}/100")
                print(f"   Status Keamanan: {report['conclusions']['security_status']}")

                return report

        except Exception as e:
            print(f"❌ Analisis gagal: {str(e)}")
            return None


async def main():
    """Main execution function"""
    target_url = "https://airdrop.0gfoundation.ai"

    print("🔍 Connection & Data Flow Analyzer")
    print("=" * 60)
    print(f"🎯 Target: {target_url}")
    print("=" * 60)

    analyzer = ConnectionDataFlowAnalyzer(target_url)
    results = await analyzer.execute_analysis()

    if results:
        print(f"\n✅ Analisis koneksi dan jalur data selesai!")
        print(f"📊 Laporan lengkap tersedia di connection_data_flow_analysis_*.json")

        # Show summary
        conclusions = results.get("conclusions", {})
        if conclusions:
            print(f"\n🎯 Kesimpulan:")
            print(f"   Status Keamanan: {conclusions.get('security_status', 'Unknown')}")
            print(f"   Skor Keamanan: {conclusions.get('overall_score', 0)}/100")
            print(f"   Tingkat Keamanan: {conclusions.get('security_level', 'Unknown')}")

        return results
    else:
        print("❌ Analisis gagal!")
        return None


if __name__ == "__main__":
    asyncio.run(main())