# shadowscan/collectors/evm/__init__.py
"""EVM collectors package."""

from .abi_fetcher import ABIFetcher
from .proxy_resolver import ProxyResolver
from .tx_fetcher import TxFetcher
from .event_fetcher import EventFetcher
from .state_fetcher import StateFetcher
from .dex_discovery import DexDiscovery
from .oracle_intel import OracleIntel

__all__ = [
    'ABIFetcher',
    'ProxyResolver', 
    'TxFetcher',
    'EventFetcher',
    'StateFetcher',
    'DexDiscovery',
    'OracleIntel'
]
