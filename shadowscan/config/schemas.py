# shadowscan/config/schemas.py
from typing import Dict, List, Any

def validate_config(config: Dict[str, Any]) -> List[str]:
    """Validasi konfigurasi dengan aturan ketat"""
    errors = []
    
    # Validasi target
    if config['TARGET_TYPE'] not in ['blockchain', 'web', 'network']:
        errors.append(f"TARGET_TYPE tidak valid: {config['TARGET_TYPE']}. Harus 'blockchain', 'web', atau 'network'")
    
    if config['TARGET_TYPE'] == 'blockchain' and not config.get('TARGET_CONTRACT'):
        errors.append("TARGET_CONTRACT harus diisi untuk target blockchain")
    
    if config['TARGET_TYPE'] == 'web' and not config.get('TARGET_URL'):
        errors.append("TARGET_URL harus diisi untuk target web")
    
    # Validasi blockchain
    if config['TARGET_TYPE'] == 'blockchain':
        if not config.get('TENDERLY_RPC'):
            errors.append("TENDERLY_RPC harus diisi untuk target blockchain")
        if not config.get('ETHERSCAN_API_KEY'):
            errors.append("ETHERSCAN_API_KEY harus diisi untuk target blockchain")
        if not config.get('ATTACKER_ADDRESS'):
            errors.append("ATTACKER_ADDRESS harus diisi untuk target blockchain")
    
    # Validasi engine
    if config['MAX_THREADS'] < 1 or config['MAX_THREADS'] > 50:
        errors.append(f"MAX_THREADS tidak valid: {config['MAX_THREADS']}. Harus antara 1-50")
    
    if config['RATE_LIMIT_DELAY'] < 0.5:
        errors.append(f"RATE_LIMIT_DELAY terlalu rendah: {config['RATE_LIMIT_DELAY']}. Minimal 0.5 detik")
    
    if config['TIMEOUT'] < 10:
        errors.append(f"TIMEOUT terlalu rendah: {config['TIMEOUT']}. Minimal 10 detik")
    
    # Validasi reporting
    if config['REPORT_FORMAT'] not in ['pdf', 'html', 'json']:
        errors.append(f"REPORT_FORMAT tidak valid: {config['REPORT_FORMAT']}. Harus 'pdf', 'html', atau 'json'")
    
    return errors
