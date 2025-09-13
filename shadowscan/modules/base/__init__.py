# shadowscan/modules/base/__init__.py
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

class BaseModule(ABC):
    """Abstract base class untuk semua modul ShadowScan
    
    Kelas dasar yang harus diwariskan oleh semua modul di ShadowScan.
    Menyediakan antarmuka standar dan utilitas dasar untuk semua jenis modul.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Any):
        """
        Inisialisasi modul dasar
        
        Args:
            config: Konfigurasi sistem dari ConfigLoader
            logger: Instance logger dari StealthLogger
        """
        self.config = config
        self.logger = logger
        self.name = self.__class__.__name__
        
        # Tentukan kategori dari nama modul
        module_parts = self.__module__.split('.')
        self.category = module_parts[-2] if len(module_parts) > 2 else "unknown"
    
    @abstractmethod
    def scan(self) -> List[Dict[str, Any]]:
        """Metode abstrak yang harus diimplementasikan oleh semua modul
        
        Menjalankan proses scan dan mengembalikan temuan kerentanan
        
        Returns:
            List[Dict[str, Any]]: Daftar temuan kerentanan dalam format dictionary
        """
        pass
    
    def get_info(self) -> Dict[str, Any]:
        """Mendapatkan informasi dasar tentang modul
        
        Returns:
            Dict[str, Any]: Informasi detail tentang modul
        """
        return {
            'name': self.name,
            'category': self.category,
            'description': self._get_description(),
            'version': '1.0.0'
        }
    
    def _get_description(self) -> str:
        """Mendapatkan deskripsi modul dari docstring"""
        if not self.__doc__:
            return 'No description available'
        
        # Ambil baris pertama dari docstring
        first_line = self.__doc__.strip().split('\n')[0].strip()
        return first_line
    
    def _log_debug(self, message: str) -> None:
        """Log pesan debug jika tidak dalam stealth mode
        
        Args:
            message: Pesan yang akan dilog
        """
        if not self.config.get('STEALTH_MODE', False):
            self.logger.info(f"  ↳ {message}")
    
    def _log_vulnerability(self, 
                          vuln_type: str, 
                          description: str, 
                          severity: str, 
                          **kwargs) -> None:
        """Log temuan kerentanan dengan format yang konsisten
        
        Args:
            vuln_type: Jenis kerentanan (misal: REENTRANCY_VULN)
            description: Deskripsi kerentanan
            severity: Tingkat keparahan (high/medium/low)
            **kwargs: Parameter tambahan untuk detail
        """
        self.logger.add_vulnerability(vuln_type, description, severity)
        
        if not self.config.get('STEALTH_MODE', False):
            details = " | ".join(f"{k}={v}" for k, v in kwargs.items())
            self.logger.info(f"    🔍 [{severity.upper()}] {vuln_type}: {description} {details}")
    
    def _is_vulnerable(self, response: Any, payload: str) -> bool:
        """Metode helper untuk deteksi kerentanan (opsional)
        
        Bisa di-override oleh modul turunan
        
        Args:
            response: Respons dari panggilan ke target
            payload: Payload yang digunakan
            
        Returns:
            bool: True jika respons menunjukkan kerentanan
        """
        return False
    
    def _get_token_decimals(self, w3: Any, token_address: str) -> int:
        """Helper untuk mendapatkan token decimals dengan aman
        
        Args:
            w3: Instance Web3
            token_address: Alamat token
            
        Returns:
            int: Jumlah decimals token (default 18)
        """
        try:
            # Coba panggil decimals()
            decimals_selector = w3.keccak(text="decimals()").hex()[:8]
            result = w3.eth.call({
                'to': token_address,
                'data': '0x' + decimals_selector
            })
            return int(result.hex(), 16)
        except:
            return 18  # Default untuk ERC20
    
    def _get_balance(self, w3: Any, token: str, user: str, decimals: int = 18) -> float:
        """Helper untuk mendapatkan balance token pengguna
        
        Args:
            w3: Instance Web3
            token: Alamat token
            user: Alamat pengguna
            decimals: Jumlah decimals token
            
        Returns:
            float: Balance token dalam format desimal
        """
        try:
            data = w3.keccak(text="balanceOf(address)").hex()[:8] + user[2:].rjust(64, '0')
            result = w3.eth.call({'to': token, 'data': data}).hex()
            return int(result, 16) / (10 ** decimals)
        except:
            return 0.0
