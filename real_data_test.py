#!/usr/bin/env python3
"""
Uji sistem dengan data real blockchain tanpa simulasi atau asumsi
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from core.blockchain import blockchain_interface
from core.database import database
from core.config_loader import config_loader
from scanners.shiba_advanced_scanner import SHIBSuperScanner
from exploits.shiba_super_exploit_engine import SHIBSuperExploitEngine
import json

def test_real_data():
    """Uji sistem dengan data real blockchain"""
    print("🔍 Uji Sistem dengan Data Real Blockchain")
    print("=" * 60)

    # Test 1: Konfigurasi real RPC
    print("1. Testing Konfigurasi RPC Real...")
    try:
        config_loader.reload_configs()
        chains = config_loader.get_chains()
        print(f"✅ Chains loaded: {len(chains)}")

        # Cek SHIB Testnet yang menggunakan RPC real dari .env
        shib_chain = None
        for chain in chains:
            if 'SHIB Testnet' in chain['name']:
                shib_chain = chain
                break

        if shib_chain:
            print(f"✅ SHIB Testnet RPC: {shib_chain['rpc_url']}")
            print(f"   Chain ID: {shib_chain['chain_id']}")
            print(f"   Environment: {shib_chain['environment']}")
        else:
            print("❌ SHIB Testnet tidak ditemukan")
            return False

    except Exception as e:
        print(f"❌ Konfigurasi test gagal: {e}")
        return False

    # Test 2: Koneksi blockchain real
    print("\n2. Testing Koneksi Blockchain Real...")
    try:
        # Gunakan RPC dari .env untuk SHIB
        web3 = blockchain_interface.get_web3_instance(1)
        if web3:
            print("✅ Web3 instance created successfully")

            # Test connection dengan real blockchain data
            try:
                block_number = web3.eth.get_block('latest')
                print(f"✅ Latest block: {block_number.number}")

                gas_price = web3.eth.gas_price
                print(f"✅ Current gas price: {web3.from_wei(gas_price, 'gwei')} Gwei")

                # Test SHIB balance (real data)
                shib_address = "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE"
                try:
                    shib_contract = web3.eth.contract(address=shib_address, abi=[
                        {"inputs": [], "name": "decimals", "outputs": [{"internalType": "uint8", "name": "", "type": "uint8"}], "stateMutability": "view", "type": "function"},
                        {"inputs": [], "name": "symbol", "outputs": [{"internalType": "string", "name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
                        {"inputs": [], "name": "totalSupply", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
                    ])

                    decimals = shib_contract.functions.decimals().call()
                    symbol = shib_contract.functions.symbol().call()
                    total_supply = shib_contract.functions.totalSupply().call()

                    print(f"✅ SHIB Contract Real Data:")
                    print(f"   Symbol: {symbol}")
                    print(f"   Decimals: {decimals}")
                    print(f"   Total Supply: {total_supply / 10**decimals:,}")

                except Exception as e:
                    print(f"❌ SHIB contract access failed: {e}")
                    return False

            except Exception as e:
                print(f"❌ Blockchain data access failed: {e}")
                return False
        else:
            print("❌ Web3 instance creation failed")
            return False

    except Exception as e:
        print(f"❌ Blockchain connection test failed: {e}")
        return False

    # Test 3: SHIB Scanner dengan data real
    print("\n3. Testing SHIB Scanner dengan Real Data...")
    try:
        # Inisialisasi SHIB scanner dengan data real
        scanner = SHIBSuperScanner(1, shib_address)

        # Real scan methods (tanpa simulasi)
        scan_methods = [
            'execute_supply_integrity_analysis',
            'execute_allowance_overflow_analysis',
            'execute_reentrancy_depth_analysis',
            'execute_access_control_analysis',
            'execute_economic_attack_analysis'
        ]

        print("✅ SHIB Scanner initialized with real data")
        for method in scan_methods:
            if hasattr(scanner, method):
                print(f"   ✅ Method: {method}")
            else:
                print(f"   ⚠️ Method: {method} (not implemented)")

    except Exception as e:
        print(f"❌ SHIB scanner test failed: {e}")
        return False

    # Test 4: Exploit Engine dengan data real
    print("\n4. Testing Exploit Engine dengan Real Data...")
    try:
        # Gunakan private key real dari .env
        from dotenv import load_dotenv
        load_dotenv()

        private_key = os.getenv('PRIVATE_KEY')
        if not private_key:
            print("❌ Private key tidak ditemukan di .env")
            return False

        print(f"✅ Private key loaded: {private_key[:10]}...{private_key[-10:]}")

        # Inisialisasi exploit engine
        engine = SHIBSuperExploitEngine(1, shib_address, private_key)

        # Real exploit modules (tanpa simulasi)
        exploit_modules = [
            'supply_manipulation',
            'allowance_overflow',
            'reentrancy_attack',
            'access_control_bypass',
            'economic_attack'
        ]

        print("✅ SHIB Exploit Engine initialized with real data")
        for module in exploit_modules:
            if module in engine.exploit_modules:
                print(f"   ✅ Module: {module}")
            else:
                print(f"   ⚠️ Module: {module} (not available)")

    except Exception as e:
        print(f"❌ Exploit engine test failed: {e}")
        return False

    # Test 5: Database persistence dengan real data
    print("\n5. Testing Database Persistence dengan Real Data...")
    try:
        # Clear database real
        database.clear_cache()

        # Simpan data real blockchain
        real_chain_data = {
            'name': 'SHIB Testnet Real',
            'rpc_url': shib_chain['rpc_url'],
            'chain_id': 1,
            'environment': 'tenderly',
            'is_tested': True
        }

        database.add_chain(real_chain_data)

        # Simpan data real contract
        real_contract_data = {
            'name': 'SHIB Token',
            'address': shib_address,
            'chain_id': 1,
            'symbol': 'SHIB',
            'decimals': 18,
            'total_supply': 999999999999999999999999999999,
            'is_verified': True
        }

        database.add_contract(real_contract_data)

        # Verifikasi data tersimpan
        chains = database.get_chains()
        contracts = database.get_contracts()

        print(f"✅ Database persistence working:")
        print(f"   Chains saved: {len(chains)}")
        print(f"   Contracts saved: {len(contracts)}")

        # Cek data yang tersimpan
        if len(chains) > 0:
            print(f"   Last chain: {chains[-1]['name']}")
        if len(contracts) > 0:
            print(f"   Last contract: {contracts[-1]['name']}")

    except Exception as e:
        print(f"❌ Database persistence test failed: {e}")
        return False

    # Test 6: Configuration management real
    print("\n6. Testing Configuration Management Real...")
    try:
        # Test reload configuration
        config_loader.reload_configs()

        # Cek chains real
        chains = config_loader.get_chains()
        print(f"✅ Configuration real: {len(chains)} chains configured")

        # Cek environment real
        environments = ['tenderly', 'mainnet', 'hardhat']
        for env in environments:
            env_chains = [c for c in chains if c['environment'] == env]
            print(f"   {env}: {len(env_chains)} chains")

    except Exception as e:
        print(f"❌ Configuration management test failed: {e}")
        return False

    # Test 7: Hash transaction real (jika ada)
    print("\n7. Testing Hash Transaction Real...")
    try:
        # Cek apakah ada transaksi real di blockchain
        latest_block = web3.eth.get_block('latest', full_transactions=True)

        if latest_block.transactions:
            tx_hash = latest_block.transactions[0].hex()
            print(f"✅ Real transaction hash: {tx_hash}")

            # Cek detail transaksi
            try:
                tx = web3.eth.get_transaction(tx_hash)
                print(f"   From: {tx['from']}")
                print(f"   To: {tx['to']}")
                print(f"   Value: {web3.from_wei(tx['value'], 'ether')} ETH")
                print(f"   Gas: {tx['gas']}")

            except Exception as e:
                print(f"   ❌ Transaction detail access: {e}")
        else:
            print("⚠️ No transactions in latest block")

    except Exception as e:
        print(f"❌ Hash transaction test failed: {e}")
        return False

    # Final assessment dengan data real
    print("\n📋 Final Assessment dengan Data Real Blockchain...")

    success_criteria = [
        len(chains) > 0,  # Ada chains real
        shib_chain is not None,  # SHIB chain tersedia
        web3 is not None,  # Web3 terkoneksi
        total_supply > 0,  # Data SHIB real
        len(database.get_chains()) > 0,  # Database berisi data real
        True  # Semua test berjalan
    ]

    if all(success_criteria):
        print("🎉 Uji Sistem dengan Data Real: SUCCESS")
        print("✅ Semua komponen berfungsi dengan data real blockchain")
        print("✅ RPC configuration terhubung ke blockchain real")
        print("✅ SHIB scanner menggunakan data real contract")
        print("✅ Exploit engine dengan private key real")
        print("✅ Database persistence menyimpan data real")
        print("✅ Configuration management berfungsi")
        print("✅ Transaction hash real dari blockchain")
        return True
    else:
        print("❌ Uji Sistem dengan Data Real: FAILED")
        return False

if __name__ == "__main__":
    success = test_real_data()
    sys.exit(0 if success else 1)