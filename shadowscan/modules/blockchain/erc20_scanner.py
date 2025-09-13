# shadowscan/modules/blockchain/erc20_scanner.py
from typing import Dict, Any, List, Optional
from web3 import Web3
from ..base import BaseModule
from ...core.logger import StealthLogger
from ...utils.web3_helper import (
    get_function_selector,
    function_exists,
    get_balance,
    get_token_decimals
)
from ...integrations.tenderly import TenderlyFork

class ERC20Scanner(BaseModule):
    """Modul profesional untuk mendeteksi kerentanan ERC20 tersembunyi"""
    
    def __init__(self, config: Dict[str, Any], logger: StealthLogger, tenderly: Optional[TenderlyFork] = None):
        super().__init__(config, logger)
        self.tenderly = tenderly or TenderlyFork(config)
        self.w3 = self.tenderly.w3
        self.token_address = Web3.to_checksum_address(config['TARGET_CONTRACT'])
        self.attacker = Web3.to_checksum_address(config['ATTACKER_ADDRESS'])
        self.decimals = get_token_decimals(self.w3, self.token_address)
        
    def scan(self) -> List[Dict[str, Any]]:
        """Jalankan scan profesional terhadap kontrak ERC20"""
        self.logger.info("🔍 Memulai scan ERC20 profesional...", force=True)
        self.logger.register_module("erc20_scanner")
        
        findings = []
        
        # Tahap 1: Mapping fungsi kritis
        self.logger.info("📊 Mapping fungsi kontrak ERC20...")
        critical_functions = self._map_critical_functions()
        self.logger.info(f"✅ Ditemukan {len(critical_functions)} fungsi kritis")
        
        # Tahap 2: Deteksi pola supply tersembunyi
        self.logger.info("🧬 Mencari pola supply tersembunyi...")
        supply_mechanisms = self._detect_supply_mechanisms(critical_functions)
        for mechanism in supply_mechanisms:
            findings.append(mechanism)
            self.logger.add_vulnerability(
                mechanism['type'],
                mechanism['description'],
                mechanism['severity']
            )
        
        # Tahap 3: Cek interaksi dengan kontrak terkait
        self.logger.info("🔗 Menganalisis interaksi kontrak terkait...")
        ecosystem_vulns = self._analyze_ecosystem_interactions()
        for vuln in ecosystem_vulns:
            findings.append(vuln)
            self.logger.add_vulnerability(
                vuln['type'],
                vuln['description'],
                vuln['severity']
            )
        
        # Tahap 4: Cek potensi reentrancy
        self.logger.info("🌀 Mencari potensi reentrancy...")
        reentrancy_vulns = self._detect_reentrancy()
        for vuln in reentrancy_vulns:
            findings.append(vuln)
            self.logger.add_vulnerability(
                vuln['type'],
                vuln['description'],
                vuln['severity']
            )
        
        self.logger.info(f"✅ Scan ERC20 selesai. Total temuan: {len(findings)}", force=True)
        return findings
    
    def _map_critical_functions(self) -> Dict[str, str]:
        """Mapping fungsi kritis dengan deteksi dinamis"""
        critical_functions = {}
        patterns = {
            'mint': 'mint(address,uint256)',
            'claim': 'claim()',
            'claimReward': 'claimReward()',
            'airdrop': 'airdrop()',
            'reward': 'reward()',
            'harvest': 'harvest()',
            'distribute': 'distribute()',
            'mintMinerReward': 'mintMinerReward()',
            'transferOwnership': 'transferOwnership(address)',
            'renounceOwnership': 'renounceOwnership()',
            'pause': 'pause()',
            'setFee': 'setFee(uint256)',
            'withdraw': 'withdraw()',
            'selfdestruct': 'selfdestruct(address)'
        }
        
        for name, func in patterns.items():
            selector = get_function_selector(func)
            if function_exists(self.w3, self.token_address, selector):
                critical_functions[name] = selector
        
        return critical_functions
    
    def _detect_supply_mechanisms(self, critical_functions: Dict[str, str]) -> List[Dict[str, Any]]:
        """Deteksi pola supply tersembunyi seperti miner reward"""
        findings = []
        balance_before = get_balance(self.w3, self.token_address, self.attacker, self.decimals)
        
        # Pola 1: Fungsi claim/reward yang mint ke caller
        for func_name in ['claim', 'claimReward', 'airdrop', 'reward', 'harvest', 'distribute']:
            if func_name not in critical_functions:
                continue
                
            selector = critical_functions[func_name]
            data = '0x' + selector
            
            try:
                # Simulasi panggilan fungsi
                self.w3.eth.call({
                    'to': self.token_address,
                    'data': data,
                    'from': self.attacker
                })
                
                # Cek balance setelah
                balance_after = get_balance(self.w3, self.token_address, self.attacker, self.decimals)
                
                if balance_after > balance_before:
                    findings.append({
                        'type': 'DIRECT_CLAIM_EXPLOIT',
                        'description': f'Fungsi {func_name}() bisa mint token ke caller',
                        'severity': 'high',
                        'function': func_name,
                        'proof': f'balance increased from {balance_before} to {balance_after}'
                    })
            except:
                pass
        
        # Pola 2: Miner reward via transfer (dari knowledge base)
        findings.extend(self._detect_miner_reward_via_transfer())
        
        # Pola 3: Receive mint via ETH transfer
        findings.extend(self._detect_receive_mint())
        
        return findings
    
    def _detect_miner_reward_via_transfer(self) -> List[Dict[str, Any]]:
        """Deteksi pola _mintMinerReward() dari knowledge base"""
        findings = []
        
        # Cari transaksi Transfer dari block.coinbase
        try:
            transfer_event = self.w3.keccak(text="Transfer(address,address,uint256)").hex()
            logs = self.w3.eth.get_logs({
                'address': self.token_address,
                'topics': [transfer_event],
                'fromBlock': 0,
                'toBlock': 'latest'
            })
            
            # Analisis pola transfer
            miner_address_count = {}
            for log in logs:
                to_address = "0x" + log['topics'][2].hex()[-40:]
                if to_address != "0x0000000000000000000000000000000000000000":
                    miner_address_count[to_address] = miner_address_count.get(to_address, 0) + 1
            
            # Jika ada alamat yang sering dapat token setelah transfer
            if miner_address_count:
                most_common = max(miner_address_count.items(), key=lambda x: x[1])
                if most_common[1] > 5:  # Minimal 5 transfer
                    findings.append({
                        'type': 'MINER_REWARD_EXPLOIT',
                        'description': f'Potensi pola _mintMinerReward() terdeteksi - {most_common[0]} menerima {most_common[1]} transfer',
                        'severity': 'high',
                        'miner_address': most_common[0],
                        'transfer_count': most_common[1]
                    })
        except Exception as e:
            self.logger.warning(f"Gagal deteksi miner reward: {str(e)}")
        
        return findings
    
    def _detect_receive_mint(self) -> List[Dict[str, Any]]:
        """Deteksi pola mint via receive()"""
        findings = []
        balance_before = get_balance(self.w3, self.token_address, self.attacker, self.decimals)
        
        try:
            # Coba kirim ETH ke kontrak
            tx = {
                'to': self.token_address,
                'value': self.w3.to_wei(0.0001, 'ether'),
                'gas': 100000,
                'nonce': self.w3.eth.get_transaction_count(self.attacker),
            }
            
            self.w3.eth.call(tx)
            
            # Cek balance setelah
            balance_after = get_balance(self.w3, self.token_address, self.attacker, self.decimals)
            
            if balance_after > balance_before:
                findings.append({
                    'type': 'RECEIVE_MINT_EXPLOIT',
                    'description': 'Kontrak menerima ETH dan memberikan token sebagai reward',
                    'severity': 'high',
                    'tokens_received': balance_after - balance_before
                })
        except:
            pass
        
        return findings
    
    def _analyze_ecosystem_interactions(self) -> List[Dict[str, Any]]:
        """Analisis interaksi dengan kontrak terkait untuk deteksi komposisi serangan"""
        findings = []
        
        # Dapatkan kontrak terkait dari Tenderly
        related_contracts = self.tenderly.get_related_contracts(self.token_address)
        
        for contract in related_contracts:
            # Cek apakah kontrak memiliki fungsi berbahaya
            if 'transferOwnership' in contract['functions']:
                findings.append({
                    'type': 'OWNERSHIP_TRANSFER_VULN',
                    'description': f'Kontrak terkait {contract["address"]} memiliki fungsi transferOwnership',
                    'severity': 'high',
                    'related_contract': contract['address']
                })
            
            if 'selfdestruct' in contract['functions']:
                findings.append({
                    'type': 'SELFDESTRUCT_VULN',
                    'description': f'Kontrak terkait {contract["address"]} memiliki fungsi selfdestruct',
                    'severity': 'high',
                    'related_contract': contract['address']
                })
        
        return findings
    
    def _detect_reentrancy(self) -> List[Dict[str, Any]]:
        """Deteksi potensi reentrancy dengan analisis kompleks"""
        findings = []
        
        # Gunakan Tenderly untuk analisis reentrancy
        reentrancy_result = self.tenderly.analyze_reentrancy(self.token_address)
        
        if reentrancy_result['vulnerable']:
            findings.append({
                'type': 'REENTRANCY_VULN',
                'description': 'Potensi reentrancy terdeteksi',
                'severity': 'high',
                'functions': reentrancy_result['vulnerable_functions'],
                'details': reentrancy_result['details']
            })
        
        return findings
