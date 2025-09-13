"""
ShadowScan Configuration Module
"""

DEFAULT_CONFIG = {
    "networks": {
        "ethereum": {
            "name": "Ethereum Mainnet",
            "chain_id": 1,
            "rpc_url": "https://eth.llamarpc.com"
        },
        "polygon": {
            "name": "Polygon",
            "chain_id": 137,
            "rpc_url": "https://polygon.llamarpc.com"
        },
        "bsc": {
            "name": "BNB Smart Chain",
            "chain_id": 56,
            "rpc_url": "https://bsc.llamarpc.com"
        }
    }
}

class ConfigLoader:
    """Simple config loader for compatibility."""
    
    def __init__(self):
        self.config = DEFAULT_CONFIG.copy()
    
    def get(self, key, default=None):
        return self.config.get(key, default)

def get_config():
    return DEFAULT_CONFIG.copy()

def get_network_config(network: str):
    config = get_config()
    return config["networks"].get(network, {})

__all__ = ["DEFAULT_CONFIG", "ConfigLoader", "get_config", "get_network_config"]
