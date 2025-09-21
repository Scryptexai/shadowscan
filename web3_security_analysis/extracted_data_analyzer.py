#!/usr/bin/env python3
"""
Extracted Data Analyzer - Analyze user and token data from extraction results
Author: ShadowScan Security Team
Purpose: Parse and analyze the extracted data to get user lists, token amounts, and eligibility
"""

import json
import re
from datetime import datetime

class ExtractedDataAnalyzer:
    def __init__(self, extracted_file):
        self.extracted_file = extracted_file
        self.data = None

    def load_data(self):
        """Load the extracted data file"""
        try:
            with open(self.extracted_file, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
            print(f"✅ Data loaded successfully from {self.extracted_file}")
            return True
        except Exception as e:
            print(f"❌ Error loading data: {e}")
            return False

    def analyze_user_data(self):
        """Analyze user data and extract eligibility information"""
        print("📊 USER DATA ANALYSIS")
        print("=" * 50)

        user_endpoints = []
        total_users = 0
        all_users = []

        # Extract user data from endpoints
        for endpoint in self.data.get('user_data', []):
            endpoint_name = endpoint.get('endpoint', 'Unknown')
            users_data = endpoint.get('users', [])
            total_count = endpoint.get('total_users', 0)

            user_endpoints.append({
                'endpoint': endpoint_name,
                'total_users': total_count,
                'users': users_data
            })

            total_users += total_count
            all_users.extend(users_data)

            print(f"📋 Endpoint: {endpoint_name}")
            print(f"   Total Users: {total_count}")
            print(f"   Users: {users_data}")
            print()

        print(f"🎯 SUMMARY:")
        print(f"   Total Endpoints Found: {len(user_endpoints)}")
        print(f"   Total Users Across All Endpoints: {total_users}")
        print(f"   Unique Users: {len(all_users)} (individual user records)")

        return user_endpoints, total_users, all_users

    def analyze_token_data(self):
        """Analyze token distribution and amounts"""
        print("💰 TOKEN DATA ANALYSIS")
        print("=" * 50)

        token_endpoints = []
        total_tokens = 0
        all_tokens = []
        token_amounts = []

        # Extract token data from endpoints
        for endpoint in self.data.get('token_data', []):
            endpoint_name = endpoint.get('endpoint', 'Unknown')
            tokens_data = endpoint.get('tokens', [])
            total_count = endpoint.get('total_tokens', 0)

            token_endpoints.append({
                'endpoint': endpoint_name,
                'total_tokens': total_count,
                'tokens': tokens_data
            })

            total_tokens += total_count
            all_tokens.extend(tokens_data)

            # Extract token amounts if available
            if 'amounts' in endpoint:
                token_amounts.extend(endpoint.get('amounts', []))

            print(f"💵 Endpoint: {endpoint_name}")
            print(f"   Total Tokens: {total_count}")
            print(f"   Tokens: {tokens_data}")
            if 'amounts' in endpoint:
                print(f"   Amounts: {endpoint.get('amounts', [])}")
            print()

        print(f"💎 TOKEN SUMMARY:")
        print(f"   Total Endpoints Found: {len(token_endpoints)}")
        print(f"   Total Tokens Across All Endpoints: {total_tokens}")
        print(f"   Unique Tokens: {len(set(all_tokens))}")
        print(f"   Token Amounts Found: {len(token_amounts)}")

        return token_endpoints, total_tokens, all_tokens, token_amounts

    def analyze_eligibility_criteria(self):
        """Extract eligibility criteria and requirements"""
        print("🎯 ELIGIBILITY CRITERIA ANALYSIS")
        print("=" * 50)

        eligibility_info = []

        # Look for eligibility endpoints
        for endpoint in self.data.get('user_data', []):
            if 'eligibility' in endpoint.get('endpoint', '').lower():
                eligibility_info.append({
                    'endpoint': endpoint.get('endpoint'),
                    'total_eligible': endpoint.get('total_users', 0),
                    'eligible_users': endpoint.get('users', [])
                })
                print(f"✅ Eligibility Endpoint: {endpoint.get('endpoint')}")
                print(f"   Eligible Users: {endpoint.get('total_users', 0)}")
                print(f"   Users: {endpoint.get('users', [])}")
                print()

        # Extract eligibility criteria from admin configurations
        if 'system_config' in self.data:
            config = self.data['system_config']
            if 'eligibility_criteria' in config:
                criteria = config['eligibility_criteria']
                print(f"📋 System Eligibility Criteria:")
                for criterion, value in criteria.items():
                    print(f"   {criterion}: {value}")
                print()

        return eligibility_info

    def extract_address_eligibility_info(self):
        """Extract information about address eligibility and claiming processes"""
        print("🏠 ADDRESS ELIGIBILITY & CLAIMING INFO")
        print("=" * 50)

        address_info = []

        # Look for address-related endpoints
        for endpoint in self.data.get('user_data', []):
            if any(keyword in endpoint.get('endpoint', '').lower() for keyword in ['address', 'claim', 'wallet', 'eligibility']):
                address_info.append({
                    'endpoint': endpoint.get('endpoint'),
                    'data': endpoint
                })
                print(f"🏠 Address Endpoint: {endpoint.get('endpoint')}")
                print(f"   Users: {endpoint.get('users', [])}")
                print()

        return address_info

    def generate_analysis_report(self):
        """Generate comprehensive analysis report"""
        print("📋 COMPREHENSIVE ANALYSIS REPORT")
        print("=" * 60)
        print(f"📅 Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📁 Source File: {self.extracted_file}")
        print()

        # Analyze all data
        user_endpoints, total_users, all_users = self.analyze_user_data()
        token_endpoints, total_tokens, all_tokens, token_amounts = self.analyze_token_data()
        eligibility_info = self.analyze_eligibility_criteria()
        address_info = self.extract_address_eligibility_info()

        # Generate report
        report = {
            "analysis_timestamp": datetime.now().isoformat(),
            "source_file": self.extracted_file,
            "summary": {
                "total_user_endpoints": len(user_endpoints),
                "total_users": total_users,
                "total_token_endpoints": len(token_endpoints),
                "total_tokens": total_tokens,
                "total_eligibility_endpoints": len(eligibility_info),
                "total_address_endpoints": len(address_info)
            },
            "user_data": user_endpoints,
            "token_data": token_endpoints,
            "eligibility_info": eligibility_info,
            "address_info": address_info,
            "recommendations": self._generate_recommendations()
        }

        # Save report
        report_filename = f"extracted_data_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"📋 Analysis Report Saved: {report_filename}")
        print("=" * 60)
        print("🎯 ANALYSIS COMPLETE! 🎯")

        return report

    def _generate_recommendations(self):
        """Generate exploitation recommendations based on extracted data"""
        recommendations = []

        if self.data.get('user_data'):
            recommendations.append("🔓 System allows complete user enumeration - all endpoints expose user data")

        if self.data.get('token_data'):
            recommendations.append("💰 Token distribution data is accessible - can identify claim amounts")

        if self.data.get('summary', {}).get('system_access_achieved'):
            recommendations.append("🎯 Full system access achieved - can manipulate any user or token data")

        if self.data.get('admin_access'):
            recommendations.append("👑 Admin credentials confirmed working - can modify system configuration")

        if self.data.get('sensitive_data_found'):
            recommendations.append("⚠️ Sensitive data exposed including database credentials and system config")

        return recommendations

def main():
    # Analyze the extracted data
    extracted_file = "/root/myproject/shadowscan/web3_security_analysis/system_data_extracted_20250921_075618.json"

    analyzer = ExtractedDataAnalyzer(extracted_file)

    if analyzer.load_data():
        # Perform comprehensive analysis
        report = analyzer.generate_analysis_report()

        # Print key findings
        print("\n🔍 KEY FINDINGS:")
        print("=" * 40)
        print(f"👥 User Endpoints: {report['summary']['total_user_endpoints']}")
        print(f"💰 Token Endpoints: {report['summary']['total_token_endpoints']}")
        print(f"🎯 Eligibility Endpoints: {report['summary']['total_eligibility_endpoints']}")
        print(f"🏠 Address Endpoints: {report['summary']['total_address_endpoints']}")

        if report['recommendations']:
            print("\n⚠️ EXPLOITATION RECOMMENDATIONS:")
            for rec in report['recommendations']:
                print(f"   {rec}")
    else:
        print("❌ Failed to load extracted data")

if __name__ == "__main__":
    main()