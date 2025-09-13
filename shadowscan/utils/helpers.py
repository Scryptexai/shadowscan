# shadowscan/utils/helpers.py
"""Shared helper functions."""

import hashlib
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
import re

def generate_session_id(target: str, chain: str) -> str:
    """Generate unique session ID."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_short = target[:8] if target.startswith('0x') else target[:6]
    return f"session_{target_short}_{timestamp}"

def generate_hypothesis_id(category: str, target: str) -> str:
    """Generate unique hypothesis ID."""
    hash_input = f"{category}_{target}_{time.time()}"
    hash_hex = hashlib.md5(hash_input.encode()).hexdigest()[:8]
    return f"HYP-{hash_hex.upper()}"

def format_wei(wei_value: str, decimals: int = 18) -> float:
    """Convert wei string to float with decimals."""
    try:
        wei_int = int(wei_value)
        return wei_int / (10 ** decimals)
    except (ValueError, TypeError):
        return 0.0

def format_address(address: str, short: bool = True) -> str:
    """Format address for display."""
    if not address or not address.startswith('0x'):
        return address
    return f"{address[:8]}...{address[-6:]}" if short else address

def extract_function_signature(input_data: str) -> Optional[str]:
    """Extract function selector from transaction input."""
    if not input_data or len(input_data) < 10:
        return None
    return input_data[:10]

def calculate_risk_score(factors: Dict[str, float], weights: Dict[str, float]) -> float:
    """Calculate weighted risk score."""
    total_score = 0.0
    total_weight = 0.0
    
    for factor, value in factors.items():
        weight = weights.get(factor, 1.0)
        total_score += value * weight
        total_weight += weight
    
    return min(1.0, total_score / total_weight if total_weight > 0 else 0.0)

def is_contract_address(web3, address: str) -> bool:
    """Check if address is a contract."""
    try:
        code = web3.eth.get_code(web3.to_checksum_address(address))
        return len(code) > 0
    except Exception:
        return False

def parse_token_transfer(event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Parse Transfer event data."""
    try:
        if not event_data.get('topics') or len(event_data['topics']) < 3:
            return None
            
        return {
            'from': '0x' + event_data['topics'][1][-40:],
            'to': '0x' + event_data['topics'][2][-40:],
            'value': int(event_data.get('data', '0x0'), 16)
        }
    except Exception:
        return None
