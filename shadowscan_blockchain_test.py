#!/usr/bin/env python3
"""
SHADOWSCAN - Real Blockchain Exploitation Test
Test framework with actual blockchain interactions
"""

import asyncio
import json
import sys
import os
import time
from datetime import datetime
from typing import Dict, Any, List
from dataclasses import asdict

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        elif hasattr(obj, 'asdict'):
            return obj.asdict()
        else:
            return super().default(obj)

# Add framework ke path
sys.path.append('/home/nurkahfi/MyProject/shadowscan/modules/web_claim_dex_framework')

from real_blockchain_integration import RealBlockchainIntegration
from real_exploit_framework import RealExploitFramework
from real_time_validator import RealTimeValidator

async def test_real_blockchain_integration():
    """Test real blockchain integration capabilities"""
    print("🚀 SHADOWSCAN REAL BLOCKCHAIN INTEGRATION TEST")
    print("=" * 80)
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("🔗 Testing real blockchain interactions")
    print("=" * 80)
    
    # Initialize real blockchain integration
    blockchain = RealBlockchainIntegration()
    
    results = {
        'test_info': {
            'start_time': datetime.now().isoformat(),
            'framework': 'Shadowscan Real Blockchain Integration',
            'version': '2.0.0'
        },
        'results': {}
    }
    
    start_time = time.time()
    
    try:
        # Step 1: Test Network Connections
        print("🔗 Step 1: Testing Network Connections")
        network_status = {}
        
        networks = ['ethereum', 'polygon', 'bsc', 'arbitrum']
        
        for network in networks:
            print(f"   Testing {network}...")
            status = await blockchain.get_network_status(network)
            network_status[network] = status
            
            if 'error' not in status:
                print(f"   ✅ {network}: Connected (Block {status['block_number']})")
            else:
                print(f"   ❌ {network}: {status['error']}")
        
        results['results']['network_connections'] = network_status
        
        # Step 2: Test Contract Analysis
        print("\n📊 Step 2: Testing Smart Contract Analysis")
        
        # Test contracts on different networks
        test_contracts = {
            'ethereum': '0x30a25CC9c9EADe4D4d9e9349BE6e68c3411367D3',  # Sample contract
            'polygon': '0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619',  # WMATIC
            'bsc': '0x2170Ed0880ac9A755fd29B2688956BD959F933F8',  # WBNB
        }
        
        contract_analyses = {}
        
        for network, contract_address in test_contracts.items():
            print(f"   Analyzing {contract_address} on {network}...")
            
            try:
                analysis = await blockchain.analyze_contract(contract_address, network)
                contract_analyses[f"{network}_{contract_address}"] = {
                    'address': analysis.address,
                    'name': analysis.name,
                    'is_verified': analysis.is_verified,
                    'balance': analysis.balance,
                    'functions': len(analysis.functions),
                    'events': len(analysis.events),
                    'verification_source': analysis.verification_source
                }
                
                print(f"   ✅ {analysis.name} - Verified: {analysis.is_verified}, Balance: {analysis.balance:.6f} ETH")
                
            except Exception as e:
                print(f"   ❌ Error: {e}")
                contract_analyses[f"{network}_{contract_address}"] = {'error': str(e)}
        
        results['results']['contract_analyses'] = contract_analyses
        
        # Step 3: Test Transaction Execution
        print("\n💸 Step 3: Testing Transaction Execution")
        
        # Test small transaction on network with lowest gas
        test_network = None
        for network, status in network_status.items():
            if 'error' not in status and status['gas_price'] < 100:  # Find network with reasonable gas
                test_network = network
                break
        
        if test_network:
            print(f"   Testing transaction on {test_network}...")
            
            # Test transaction to self (small amount)
            tx_result = await blockchain.execute_transaction(
                to_address=blockchain.config.attacker_address,
                value=0.0001,  # Small test amount
                network=test_network
            )
            
            results['results']['transaction_test'] = {
                'network': test_network,
                'success': tx_result.success,
                'tx_hash': tx_result.tx_hash,
                'gas_used': tx_result.gas_used,
                'gas_price': tx_result.gas_price,
                'value': tx_result.value,
                'error': tx_result.error_message
            }
            
            if tx_result.success:
                print(f"   ✅ Transaction successful!")
                print(f"      Hash: {tx_result.tx_hash}")
                print(f"      Gas Used: {tx_result.gas_used}")
                print(f"      Cost: {tx_result.gas_price * tx_result.gas_used / 1e9:.6f} ETH")
            else:
                print(f"   ❌ Transaction failed: {tx_result.error_message}")
        else:
            print("   ⚠️ No suitable network found for transaction testing")
            results['results']['transaction_test'] = {'error': 'No suitable network'}
        
        # Step 4: Test Vulnerability Detection
        print("\n🔍 Step 4: Testing Vulnerability Detection")
        
        vulnerability_tests = {}
        
        for network, contract_address in test_contracts.items():
            if network in blockchain.web3_providers:
                print(f"   Testing vulnerabilities for {contract_address} on {network}...")
                
                try:
                    vuln_result = await blockchain.test_exploit_vulnerabilities(contract_address, network)
                    vulnerability_tests[f"{network}_{contract_address}"] = vuln_result
                    
                    vulnerabilities = vuln_result.get('vulnerabilities', [])
                    risk_level = vuln_result.get('risk_level', 'Unknown')
                    
                    print(f"   ✅ {len(vulnerabilities)} vulnerabilities found (Risk: {risk_level})")
                    
                    if vulnerabilities:
                        for vuln in vulnerabilities:
                            print(f"      • {vuln}")
                            
                except Exception as e:
                    print(f"   ❌ Error: {e}")
                    vulnerability_tests[f"{network}_{contract_address}"] = {'error': str(e)}
        
        results['results']['vulnerability_tests'] = vulnerability_tests
        
        # Step 5: Test Wallet Draining Capabilities
        print("\n💰 Step 5: Testing Wallet Draining Capabilities")
        
        wallet_tests = {}
        
        # Test with attacker address (self-test)
        for network in ['ethereum', 'polygon']:
            if network in blockchain.web3_providers:
                print(f"   Testing wallet draining on {network}...")
                
                try:
                    drain_result = await blockchain.test_wallet_draining(
                        blockchain.config.attacker_address,
                        network
                    )
                    wallet_tests[network] = drain_result
                    
                    if drain_result['vulnerable']:
                        print(f"   ✅ Wallet draining capability confirmed!")
                        print(f"      Target Balance: {drain_result['target_balance']:.6f} ETH")
                        print(f"      Test TX: {drain_result.get('test_transfer_tx', 'N/A')}")
                    else:
                        print(f"   ✅ No wallet draining vulnerability detected")
                        print(f"      Target Balance: {drain_result['target_balance']:.6f} ETH")
                        
                except Exception as e:
                    print(f"   ❌ Error: {e}")
                    wallet_tests[network] = {'error': str(e)}
        
        results['results']['wallet_tests'] = wallet_tests
        
        # Step 6: Test Balance Checks
        print("\n💳 Step 6: Testing Balance Checks")
        
        balance_tests = {}
        
        # Check attacker balance on all networks
        for network in networks:
            if network in blockchain.web3_providers:
                try:
                    balance = blockchain.get_wallet_balance(
                        blockchain.config.attacker_address,
                        network
                    )
                    balance_tests[network] = balance
                    print(f"   ✅ {network}: {balance:.6f} ETH")
                    
                except Exception as e:
                    print(f"   ❌ {network}: Error - {e}")
                    balance_tests[network] = {'error': str(e)}
        
        results['results']['balance_tests'] = balance_tests
        
        # Calculate execution time
        execution_time = time.time() - start_time
        results['test_info']['execution_time'] = execution_time
        results['test_info']['end_time'] = datetime.now().isoformat()
        
        # Summary
        print(f"\n📊 REAL BLOCKCHAIN INTEGRATION SUMMARY")
        print("=" * 50)
        print(f"⏱️ Execution time: {execution_time:.2f}s")
        print(f"🔗 Networks tested: {len([n for n in network_status.values() if 'error' not in n])}/{len(networks)}")
        print(f"📊 Contracts analyzed: {len([c for c in contract_analyses.values() if 'error' not in c])}")
        print(f"💸 Transaction test: {'✅ Success' if results['results'].get('transaction_test', {}).get('success') else '❌ Failed'}")
        print(f"🔍 Vulnerability tests: {len([v for v in vulnerability_tests.values() if 'error' not in v])}")
        print(f"💰 Wallet tests: {len([w for w in wallet_tests.values() if 'error' not in w])}")
        
        # Check if we have real interactions
        real_interactions = 0
        if results['results'].get('transaction_test', {}).get('success'):
            real_interactions += 1
        
        if any(v.get('vulnerable') for v in vulnerability_tests.values() if isinstance(v, dict)):
            real_interactions += 1
            
        if any(w.get('vulnerable') for w in wallet_tests.values() if isinstance(w, dict)):
            real_interactions += 1
        
        print(f"🚀 Real interactions confirmed: {real_interactions}")
        
        if real_interactions > 0:
            print("✅ FRAMEWORK USING REAL BLOCKCHAIN INTERACTIONS!")
        else:
            print("⚠️ Framework may still be using mock data")
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"shadowscan_blockchain_test_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, cls=CustomJSONEncoder)
        
        print(f"\n💾 Results saved to: {filename}")
        
        return results
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    results = asyncio.run(test_real_blockchain_integration())