# shadowscan/core/execution_mode.py
from enum import Enum
from typing import Optional
from dataclasses import dataclass

class ExecutionMode(Enum):
    SIMULATOR = "simulator"  # Default — aman, fork environment
    MAINNET = "mainnet"      # Real — langsung ke mainnet RPC

@dataclass
class ExecutionContext:
    mode: ExecutionMode
    target_chain: str
    target_contract: str
    rpc_url: Optional[str] = None  # Untuk mode mainnet
    fork_block: Optional[int] = None  # Untuk mode simulator

    def is_safe(self) -> bool:
        """Apakah mode ini aman (tidak sentuh mainnet)?"""
        return self.mode == ExecutionMode.SIMULATOR

    def get_rpc_url(self) -> str:
        """Dapatkan RPC URL sesuai mode."""
        if self.mode == ExecutionMode.SIMULATOR:
            # Gunakan default RPC untuk fork
            default_rpcs = {
                "ethereum": "https://eth.llamarpc.com",
                "polygon": "https://polygon.llamarpc.com",
                "arbitrum": "https://arb1.arbitrum.io/rpc",
                "optimism": "https://mainnet.optimism.io",
                "bsc": "https://bsc-dataseed.binance.org"
            }
            return default_rpcs.get(self.target_chain, "https://eth.llamarpc.com")
        else:
            # Untuk mainnet, gunakan RPC dari .env atau input user
            if not self.rpc_url:
                raise ValueError("Mainnet mode requires RPC URL")
            return self.rpc_url
