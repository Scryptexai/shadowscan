# shadowscan/modules/blockchain/__init__.py
from .erc20_scanner import ERC20Scanner
from .miner_reward import MinerRewardDetector
from .reentrancy import ReentrancyDetector

__all__ = [
    'ERC20Scanner',
    'MinerRewardDetector',
    'ReentrancyDetector'
]
