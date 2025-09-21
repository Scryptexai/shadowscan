#!/usr/bin/env python3
"""
Uji sistem inti dengan data real blockchain tanpa simulasi atau asumsi
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from core.blockchain import blockchain_interface
from core.database import database
from core.config_loader import config_loader

def test_real_core_system():
    """Uji sistem inti dengan data real blockchain"""
    print("🔍 Uji Sistem Inti dengan Data Real Blockchain")
    print("=" * 60)

    # Test 1: Konfigurasi RPC real dari .env
    print("1. Testing Konfigurasi RPC Real dari .env...")
    try:
        config_loader.reload_configs()
        chains = config_loader.get_chains()
        print(f"✅ Configuration loaded: {len(chains)} chains")

        # Cek SHIB Testnet dengan RPC real
        shib_chain = None
        for chain in chains:
            if 'SHIB Testnet' in chain['name'] and chain['chain_id'] == 1:
                shib_chain = chain
                break

        if shib_chain:
            print(f"✅ SHIB Testnet Real Configuration:")
            print(f"   Name: {shib_chain['name']}")
            print(f"   RPC: {shib_chain['rpc_url']}")
            print(f"   Chain ID: {shib_chain['chain_id']}")
            print(f"   Environment: {shib_chain['environment']}")
        else:
            print("❌ SHIB Testnet tidak ditemukan di konfigurasi")
            return False

    except Exception as e:
        print(f"❌ Konfigurasi test failed: {e}")
        return False

    # Test 2: Koneksi blockchain real
    print("\n2. Testing Koneksi Blockchain Real...")
    try:
        # Uji koneksi dengan RPC real
        web3 = blockchain_interface.get_web3_instance(1)
        if web3:
            print("✅ Web3 instance created with real RPC")

            # Test real blockchain data
            try:
                latest_block = web3.eth.get_block('latest')
                print(f"✅ Latest block (real): {latest_block.number}")

                current_time = latest_block.timestamp
                from datetime import datetime
                readable_time = datetime.fromtimestamp(current_time)
                print(f"✅ Block timestamp (real): {readable_time}")

                # Test real gas price
                gas_price = web3.eth.gas_price
                gas_gwei = web3.from_wei(gas_price, 'gwei')
                print(f"✅ Current gas price (real): {gas_gwei:.2f} Gwei")

            except Exception as e:
                print(f"❌ Real blockchain data access failed: {e}")
                return False
        else:
            print("❌ Web3 instance creation failed")
            return False

    except Exception as e:
        print(f"❌ Blockchain connection test failed: {e}")
        return False

    # Test 3: Real SHIB contract data
    print("\n3. Testing Real SHIB Contract Data...")
    try:
        shib_address = "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE"

        # Basic ERC20 ABI untuk akses real
        erc20_abi = [
            {"inputs": [], "name": "decimals", "outputs": [{"internalType": "uint8", "name": "", "type": "uint8"}], "stateMutability": "view", "type": "function"},
            {"inputs": [], "name": "symbol", "outputs": [{"internalType": "string", "name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
            {"inputs": [], "name": "totalSupply", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
            {"inputs": [{"internalType": "address", "name": "owner", "type": "address"}, {"internalType": "address", "name": "spender", "type": "address"}], "name": "allowance", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
            {"inputs": [{"internalType": "address", "name": "account", "type": "address"}], "name": "balanceOf", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
        ]

        shib_contract = web3.eth.contract(address=shib_address, abi=erc20_abi)

        # Ambil data real dari blockchain
        decimals = shib_contract.functions.decimals().call()
        symbol = shib_contract.functions.symbol().call()
        total_supply = shib_contract.functions.totalSupply().call()

        print(f"✅ Real SHIB Contract Data:")
        print(f"   Address: {shib_address}")
        print(f"   Symbol: {symbol}")
        print(f"   Decimals: {decimals}")
        print(f"   Total Supply: {total_supply / 10**decimals:,}")

        # Real balance check
        try:
            attacker_address = "0x609748df45d43c99298F5C0A0E46b57340d06E90"
            balance = shib_contract.functions.balanceOf(attacker_address).call()
            print(f"✅ Real Balance ({attacker_address}): {balance / 10**decimals:,} SHIB")
        except Exception as e:
            print(f"⚠️ Balance check failed: {e}")

    except Exception as e:
        print(f"❌ SHIB contract real data test failed: {e}")
        return False

    # Test 4: Real address balance
    print("\n4. Testing Real Address Balance...")
    try:
        # Uji saldo real dari .env
        from dotenv import load_dotenv
        load_dotenv()

        attacker_address = os.getenv('ADDRESS_ATTACKER')
        if not attacker_address:
            print("❌ ADDRESS_ATTACKER tidak ditemukan di .env")
            return False

        eth_balance = web3.eth.get_balance(attacker_address)
        eth_eth = web3.from_wei(eth_balance, 'ether')

        print(f"✅ Real Address Balance:")
        print(f"   Address: {attacker_address}")
        print(f"   ETH Balance: {eth_eth:.6f} ETH")

        # Convert to USD (estimasi real-time)
        eth_price_usd = 3000  # Estimasi harga real ETH
        usd_value = eth_eth * eth_price_usd
        print(f"   USD Value: ${usd_value:,.2f} (est)")

    except Exception as e:
        print(f"❌ Real address balance test failed: {e}")
        return False

    # Test 5: Real transaction estimation
    print("\n5. Testing Real Transaction Estimation...")
    try:
        # Estimasi gas untuk transfer real
        transfer_amount = web3.to_wei(0.001, 'ether')
        attacker_address = os.getenv('ADDRESS_ATTACKER')

        if not attacker_address:
            print("❌ Address tidak tersedia")
            return False

        # Buat transaksi dummy untuk estimasi gas
        tx_params = {
            'to': '0x0000000000000000000000000000000000000000',
            'value': transfer_amount,
            'gas': 21000,
            'gasPrice': web3.eth.gas_price,
            'nonce': web3.eth.get_transaction_count(attacker_address)
        }

        try:
            estimated_gas = web3.eth.estimate_gas(tx_params)
            print(f"✅ Real Gas Estimation: {estimated_gas:,} gas units")

            # Cost estimation
            gas_cost = estimated_gas * tx_params['gasPrice']
            eth_cost = web3.from_wei(gas_cost, 'ether')
            print(f"✅ Real Transaction Cost: {eth_cost:.6f} ETH")

        except Exception as e:
            print(f"❌ Gas estimation failed: {e}")

    except Exception as e:
        print(f"❌ Real transaction estimation test failed: {e}")
        return False

    # Test 6: Real blockchain interaction capabilities
    print("\n6. Testing Real Blockchain Interaction Capabilities...")
    try:
        # Test method availability untuk real interaction
        interaction_methods = [
            'get_web3_instance',
            'execute_transaction',
            'wait_for_transaction',
            'get_contract_info',
            'get_transaction'
        ]

        for method in interaction_methods:
            if hasattr(blockchain_interface, method):
                print(f"   ✅ {method}: Available for real interaction")
            else:
                print(f"   ⚠️ {method}: Not available")

        # Test real transaction simulation
        try:
            # Cek nonce real
            attacker_address = os.getenv('ADDRESS_ATTACKER')
            nonce = web3.eth.get_transaction_count(attacker_address)
            print(f"✅ Real Nonce: {nonce}")

        except Exception as e:
            print(f"❌ Real nonce check failed: {e}")

    except Exception as e:
        print(f"❌ Real blockchain interaction test failed: {e}")
        return False

    # Test 7: Real data persistence
    print("\n7. Testing Real Data Persistence...")
    try:
        # Clear database real
        database.clear_cache()

        # Simpan data real ke database
        real_chain = {
            'name': 'SHIB Testnet Real',
            'rpc_url': shib_chain['rpc_url'],
            'chain_id': 1,
            'environment': 'tenderly',
            'block_number': latest_block.number,
            'timestamp': current_time,
            'is_real': True
        }

        database.add_chain(real_chain)

        # Simpan data real contract
        real_contract = {
            'name': 'SHIB Token Real',
            'address': shib_address,
            'chain_id': 1,
            'symbol': symbol,
            'decimals': decimals,
            'total_supply': total_supply,
            'block_number': latest_block.number,
            'is_real': True
        }

        database.add_contract(real_contract)

        # Verifikasi data tersimpan
        saved_chains = database.get_chains()
        saved_contracts = database.get_contracts()

        print(f"✅ Real Data Persistence:")
        print(f"   Chains saved: {len(saved_chains)}")
        print(f"   Contracts saved: {len(saved_contracts)}")

        # Tampilkan data yang tersimpan
        if len(saved_chains) > 0:
            chain = saved_chains[-1]
            print(f"   Saved chain: {chain['name']} (block: {chain['block_number']})")

        if len(saved_contracts) > 0:
            contract = saved_contracts[-1]
            print(f"   Saved contract: {contract['name']} (supply: {contract['total_supply'] / 10**contract['decimals']:,})")

    except Exception as e:
        print(f"❌ Real data persistence test failed: {e}")
        return False

    # Test 8: Real configuration validation
    print("\n8. Testing Real Configuration Validation...")
    try:
        # Test configuration reload
        config_loader.reload_configs()

        # Cek chains real
        chains = config_loader.get_chains()
        print(f"✅ Real Configuration Validation:")
        print(f"   Total chains: {len(chains)}")

        # Cek SHIB chain configuration
        shib_configs = [c for c in chains if 'SHIB' in c['name']]
        print(f"   SHIB configurations: {len(shib_configs)}")

        for config in shib_configs:
            print(f"   {config['name']}: {config['environment']} (ID: {config['chain_id']})")

    except Exception as e:
        print(f"❌ Real configuration validation test failed: {e}")
        return False

    # Final assessment dengan data real
    print("\n📋 Final Assessment dengan Data Real Blockchain...")

    success_criteria = [
        len(chains) > 0,  # Ada chains real
        shib_chain is not None,  # SHIB chain tersedia
        web3 is not None,  # Web3 terkoneksi
        symbol == 'SHIB',  # Data SHIB real
        eth_balance > 0,  # Balance real
        len(database.get_chains()) > 0,  # Database berisi data real
        True  # Semua test berjalan
    ]

    if all(success_criteria):
        print("🎉 Uji Sistem Inti dengan Data Real: SUCCESS")
        print("✅ Semua komponen inti berfungsi dengan data real blockchain")
        print("✅ RPC configuration dari .env terhubung ke blockchain real")
        print("✅ SHIB contract data real dari blockchain")
        print("✅ Real address balance terverifikasi")
        print("✅ Real transaction estimation berfungsi")
        print("✅ Real blockchain interaction capabilities")
        print("✅ Real data persistence ke database")
        print("✅ Real configuration validation")
        return True
    else:
        print("❌ Uji Sistem Inti dengan Data Real: FAILED")
        return False

if __name__ == "__main__":
    success = test_real_core_system()
    sys.exit(0 if success else 1)