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

def get_config():
    return DEFAULT_CONFIG.copy()

def get_network_config(network: str):
    config = get_config()
    return config["networks"].get(network, {})

__all__ = ["DEFAULT_CONFIG", "get_config", "get_network_config"]
