#!/usr/bin/env python3
"""
Temporary test to check if we can import web3
"""

try:
    from web3 import Web3
    print("✅ Web3 import successful")
except Exception as e:
    print(f"❌ Web3 import failed: {e}")

try:
    from shadowscan.collectors.evm.tx_fetcher import TxFetcher
    print("✅ TxFetcher import successful")
except Exception as e:
    print(f"❌ TxFetcher import failed: {e}")