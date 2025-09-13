# shadowscan/utils/web3_helper.py
from web3 import Web3
from typing import Dict, Any, Optional

def get_function_selector(func: str) -> str:
    """Dapatkan selector fungsi dari nama fungsi"""
    return Web3.keccak(text=func).hex()[:8]

def function_exists(w3: Web3, contract: str, selector: str) -> bool:
    """Cek apakah fungsi ada di kontrak"""
    try:
        w3.eth.call({'to': contract, 'data': '0x' + selector})
        return True
    except:
        return False

def get_balance(w3: Web3, token: str, user: str, decimals: int = 18) -> float:
    """Dapatkan balance token pengguna"""
    try:
        data = Web3.keccak(text="balanceOf(address)").hex()[:8] + user[2:].rjust(64, '0')
        result = w3.eth.call({'to': token, 'data': data}).hex()
        return int(result, 16) / (10 ** decimals)
    except:
        return 0.0

def get_token_decimals(w3: Web3, token: str) -> int:
    """Dapatkan token decimals dengan aman"""
    try:
        # Coba panggil decimals()
        decimals_selector = Web3.keccak(text="decimals()").hex()[:8]
        result = w3.eth.call({'to': token, 'data': '0x' + decimals_selector})
        return int(result.hex(), 16)
    except:
        return 18  # Default untuk ERC20

def get_token_name(w3: Web3, token: str) -> str:
    """Dapatkan nama token dengan aman"""
    try:
        # Coba panggil name()
        name_selector = Web3.keccak(text="name()").hex()[:8]
        result = w3.eth.call({'to': token, 'data': '0x' + name_selector})
        # Decode string dari ABI encoding
        return Web3.to_text(bytes.fromhex(result[2:])).strip('\x00')
    except:
        return "Unknown Token"

def get_token_symbol(w3: Web3, token: str) -> str:
    """Dapatkan symbol token dengan aman"""
    try:
        # Coba panggil symbol()
        symbol_selector = Web3.keccak(text="symbol()").hex()[:8]
        result = w3.eth.call({'to': token, 'data': '0x' + symbol_selector})
        # Decode string dari ABI encoding
        return Web3.to_text(bytes.fromhex(result[2:])).strip('\x00')
    except:
        return "UNKNOWN"

def get_total_supply(w3: Web3, token: str, decimals: int = 18) -> float:
    """Dapatkan total supply token"""
    try:
        # Coba panggil totalSupply()
        supply_selector = Web3.keccak(text="totalSupply()").hex()[:8]
        result = w3.eth.call({'to': token, 'data': '0x' + supply_selector})
        return int(result.hex(), 16) / (10 ** decimals)
    except:
        return 0.0
