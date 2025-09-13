# shadowscan/collectors/evm/proxy_resolver.py
"""Enhanced proxy resolver with comprehensive proxy type detection."""

from web3 import Web3
from typing import Optional, Dict, Any
import logging
from shadowscan.utils.schema import ProxyInfo, ProxyType, RiskLevel
from shadowscan.utils.helpers import is_contract_address

logger = logging.getLogger(__name__)

class ProxyResolver:
    """Enhanced proxy resolver with comprehensive detection capabilities."""
    
    def __init__(self, web3: Web3):
        self.web3 = web3
        
        # Standard storage slots
        self.EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
        self.EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
        self.EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
        
        # OpenZeppelin Transparent Proxy
        self.OZ_IMPL_SLOT = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
        
    def resolve_proxy(self, address: str, provider, block_number: Optional[int] = None) -> ProxyInfo:
        """
        Comprehensive proxy detection and analysis.
        
        Args:
            address: Contract address to analyze
            provider: Web3 provider
            block_number: Optional block number for historical analysis
            
        Returns:
            ProxyInfo with detailed proxy information
        """
        try:
            checksum_addr = Web3.to_checksum_address(address)
            
            # Check EIP-1967 Universal Upgradeable Proxy
            impl_addr = self._get_storage_address(checksum_addr, self.EIP1967_IMPL_SLOT, block_number)
            if impl_addr:
                admin_addr = self._get_storage_address(checksum_addr, self.EIP1967_ADMIN_SLOT, block_number)
                
                return ProxyInfo(
                    is_proxy=True,
                    proxy_type=ProxyType.EIP1967,
                    implementation=impl_addr,
                    admin=admin_addr,
                    upgradeability_risk=self._assess_admin_risk(admin_addr),
                    admin_type=self._classify_admin(admin_addr)
                )
            
            # Check EIP-1967 Beacon Proxy
            beacon_addr = self._get_storage_address(checksum_addr, self.EIP1967_BEACON_SLOT, block_number)
            if beacon_addr:
                beacon_impl = self._get_storage_address(beacon_addr, self.EIP1967_IMPL_SLOT, block_number)
                
                return ProxyInfo(
                    is_proxy=True,
                    proxy_type=ProxyType.BEACON,
                    implementation=beacon_impl,
                    admin=beacon_addr,
                    upgradeability_risk=RiskLevel.MEDIUM,
                    admin_type="beacon"
                )
            
            # Check OpenZeppelin Transparent Proxy  
            oz_impl = self._get_storage_address(checksum_addr, self.OZ_IMPL_SLOT, block_number)
            if oz_impl:
                admin_addr = self._call_admin_function(checksum_addr)
                
                return ProxyInfo(
                    is_proxy=True,
                    proxy_type=ProxyType.TRANSPARENT,
                    implementation=oz_impl,
                    admin=admin_addr,
                    upgradeability_risk=self._assess_admin_risk(admin_addr),
                    admin_type=self._classify_admin(admin_addr)
                )
            
            # Check UUPS (EIP-1822)
            uups_impl = self._check_uups_proxy(checksum_addr)
            if uups_impl:
                return ProxyInfo(
                    is_proxy=True,
                    proxy_type=ProxyType.UUPS,
                    implementation=uups_impl,
                    admin=None,  # UUPS doesn't have external admin
                    upgradeability_risk=RiskLevel.HIGH,  # Implementation controls upgrades
                    admin_type="implementation"
                )
            
            # Check Minimal Proxy (EIP-1167)
            minimal_impl = self._check_minimal_proxy(checksum_addr)
            if minimal_impl:
                return ProxyInfo(
                    is_proxy=True,
                    proxy_type=ProxyType.MINIMAL,
                    implementation=minimal_impl,
                    admin=None,
                    upgradeability_risk=RiskLevel.LOW,  # Not upgradeable
                    admin_type="none"
                )
            
            return ProxyInfo()  # Not a proxy
            
        except Exception as e:
            logger.error(f"Error resolving proxy for {address}: {e}")
            return ProxyInfo()
    
    def _get_storage_address(self, contract_addr: str, slot: str, block_number: Optional[int] = None) -> Optional[str]:
        """Read address from storage slot."""
        try:
            block = block_number or 'latest'
            storage_value = self.web3.eth.get_storage_at(contract_addr, slot, block)
            
            if storage_value == b'\x00' * 32:
                return None
            
            # Extract address from last 20 bytes
            addr_bytes = storage_value[-20:]
            address = Web3.to_checksum_address(addr_bytes)
            
            # Verify it's not zero address
            if address == "0x0000000000000000000000000000000000000000":
                return None
                
            return address
            
        except Exception as e:
            logger.debug(f"Error reading storage slot {slot}: {e}")
            return None
    
    def _call_admin_function(self, contract_addr: str) -> Optional[str]:
        """Call admin() function on transparent proxy."""
        try:
            # admin() function selector: 0xf851a440
            result = self.web3.eth.call({
                'to': contract_addr,
                'data': '0xf851a440'
            })
            
            if len(result) >= 32:
                addr_bytes = result[-20:]
                address = Web3.to_checksum_address(addr_bytes)
                
                if address != "0x0000000000000000000000000000000000000000":
                    return address
                    
        except Exception as e:
            logger.debug(f"Error calling admin() function: {e}")
        
        return None
    
    def _check_uups_proxy(self, contract_addr: str) -> Optional[str]:
        """Check for UUPS proxy pattern."""
        try:
            # Call proxiableUUID() function (0x52d1902d) to detect UUPS
            result = self.web3.eth.call({
                'to': contract_addr,
                'data': '0x52d1902d'
            })
            
            if len(result) == 32:
                # If proxiableUUID returns expected hash, it's likely UUPS
                # Try to get implementation from standard slot
                return self._get_storage_address(contract_addr, self.EIP1967_IMPL_SLOT)
                
        except Exception as e:
            logger.debug(f"Error checking UUPS pattern: {e}")
        
        return None
    
    def _check_minimal_proxy(self, contract_addr: str) -> Optional[str]:
        """Check for minimal proxy (EIP-1167) pattern."""
        try:
            bytecode = self.web3.eth.get_code(contract_addr)
            if not bytecode:
                return None
                
            bytecode_hex = bytecode.hex()
            
            # EIP-1167 standard pattern
            if len(bytecode_hex) >= 90:
                # Check for minimal proxy pattern
                if bytecode_hex.startswith("363d3d373d3d3d363d73") and bytecode_hex.endswith("5af43d82803e903d91602b57fd5bf3"):
                    # Extract implementation address (20 bytes after the prefix)
                    impl_hex = bytecode_hex[20:60]
                    try:
                        impl_address = Web3.to_checksum_address("0x" + impl_hex)
                        return impl_address
                    except Exception:
                        pass
                        
        except Exception as e:
            logger.debug(f"Error checking minimal proxy: {e}")
        
        return None
    
    def _assess_admin_risk(self, admin_addr: Optional[str]) -> RiskLevel:
        """Assess upgrade risk based on admin address type."""
        if not admin_addr:
            return RiskLevel.LOW
        
        try:
            # Check if admin is EOA (no code) - higher risk
            if not is_contract_address(self.web3, admin_addr):
                return RiskLevel.HIGH
            
            # Check if it's a known multisig pattern (basic heuristic)
            admin_code = self.web3.eth.get_code(Web3.to_checksum_address(admin_addr))
            code_size = len(admin_code)
            
            # Large contracts might be governance/multisig - medium risk
            if code_size > 10000:
                return RiskLevel.MEDIUM
            
            # Small contracts might be simple admin - high risk
            return RiskLevel.HIGH
            
        except Exception:
            return RiskLevel.MEDIUM
    
    def _classify_admin(self, admin_addr: Optional[str]) -> str:
        """Classify admin address type."""
        if not admin_addr:
            return "none"
        
        try:
            if not is_contract_address(self.web3, admin_addr):
                return "eoa"
            
            # Basic heuristics for admin classification
            admin_code = self.web3.eth.get_code(Web3.to_checksum_address(admin_addr))
            code_size = len(admin_code)
            
            if code_size > 20000:
                return "governance"
            elif code_size > 10000:
                return "multisig"
            else:
                return "contract"
                
        except Exception:
            return "unknown"
