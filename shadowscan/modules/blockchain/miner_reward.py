# shadowscan/modules/blockchain/miner_reward.py
from typing import Dict, Any, List, Optional, Tuple
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

class MinerRewardDetector(BaseModule):
    """Modul profesional untuk mendeteksi pola _mintMinerReward() pada token ERC20
    
    Pola ini tersembunyi karena tidak terlihat di fungsi publik, 
    tapi dijalankan secara otomatis saat transfer terjadi melalui override _transfer().
    
    Berdasarkan knowledge base OpenZeppelin:
    https://forum.openzeppelin.com/t/how-to-implement-erc20-supply-mechanisms/226
    
    Contoh implementasi:
    function _transfer(address from, address to, uint256 value) internal {
        _mintMinerReward();  // Auto mint saat transfer
        super._transfer(from, to, value);
    }
    
    function _mintMinerReward() internal {
        _mint(block.coinbase, 1000);
    }
    """
    
    def __init__(self, config: Dict[str, Any], logger: StealthLogger, tenderly: TenderlyFork = None):
        super().__init__(config, logger)
        self.tenderly = tenderly or TenderlyFork(config)
        self.w3 = self.tenderly.w3
        self.token_address = Web3.to_checksum_address(config['TARGET_CONTRACT'])
        self.attacker = Web3.to_checksum_address(config['ATTACKER_ADDRESS'])
        self.decimals = 18  # Akan diupdate saat scan
        self.block_coinbase = None
    
    def scan(self) -> List[Dict[str, Any]]:
        """Jalankan deteksi pola _mintMinerReward() dengan berbagai pendekatan"""
        self.logger.info("🔍 Mencari pola _mintMinerReward() tersembunyi...", force=True)
        self.logger.register_module("miner_reward")
        
        findings = []
        
        # Tahap 0: Dapatkan block.coinbase untuk referensi
        self._get_block_coinbase()
        
        # Tahap 1: Dapatkan informasi token
        self.logger.info("📊 Mendapatkan informasi token...")
        self.decimals = get_token_decimals(self.w3, self.token_address)
        self.logger.info(f"✅ Token decimals: {self.decimals}")
        
        # Tahap 2: Analisis pola transfer
        self.logger.info("🔄 Menganalisis pola transfer untuk deteksi miner reward...")
        transfer_patterns = self._analyze_transfer_patterns()
        
        # Tahap 3: Deteksi fungsi publik mintMinerReward
        self.logger.info("🔍 Mencari fungsi publik mintMinerReward()...")
        public_mint = self._detect_public_mint_function()
        if public_mint:
            findings.append(public_mint)
        
        # Tahap 4: Deteksi pola otomatis via _transfer override
        self.logger.info("⚙️ Menganalisis kemungkinan override _transfer...")
        transfer_override = self._detect_transfer_override()
        if transfer_override:
            findings.append(transfer_override)
        
        # Tahap 5: Simulasi trigger miner reward
        self.logger.info("🧪 Mensimulasikan trigger miner reward...")
        simulation_results = self._simulate_miner_reward_trigger(transfer_patterns)
        if simulation_results:
            findings.append(simulation_results)
        
        # Tahap 6: Analisis ekosistem untuk kontrak terkait
        self.logger.info("🔗 Menganalisis ekosistem untuk kontrak terkait...")
        ecosystem_vulns = self._analyze_ecosystem_interactions()
        findings.extend(ecosystem_vulns)
        
        self.logger.info(f"{'✅' if findings else '❌'} {'Pola _mintMinerReward() terdeteksi' if findings else 'Tidak ditemukan pola _mintMinerReward()'}", force=True)
        return findings
    
    def _get_block_coinbase(self) -> None:
        """Dapatkan block.coinbase untuk referensi"""
        try:
            block = self.w3.eth.get_block('latest')
            self.block_coinbase = block['miner']
            self._log_debug(f"Block.coinbase saat ini: {self.block_coinbase}")
        except Exception as e:
            self._log_debug(f"Gagal mendapatkan block.coinbase: {str(e)}")
            self.block_coinbase = "0x0000000000000000000000000000000000000000"
    
    def _analyze_transfer_patterns(self) -> List[Dict[str, Any]]:
        """Analisis pola transfer untuk mendeteksi miner reward"""
        patterns = []
        
        try:
            # Ambil beberapa transaksi transfer terbaru
            transfer_event = self.w3.keccak(text="Transfer(address,address,uint256)").hex()
            latest_block = self.w3.eth.block_number
            from_block = max(0, latest_block - 5000)  # Cek 5000 block terakhir
            
            logs = self.w3.eth.get_logs({
                'address': self.token_address,
                'topics': [transfer_event],
                'fromBlock': from_block,
                'toBlock': latest_block
            })
            
            self._log_debug(f"Ditemukan {len(logs)} event Transfer")
            
            # Analisis pola
            miner_address_count = {}
            for log in logs:
                block_number = int(log['blockNumber'], 16)
                
                # Dapatkan block.coinbase untuk block ini
                try:
                    block = self.w3.eth.get_block(block_number)
                    coinbase = block['miner']
                    
                    # Cari transfer ke block.coinbase
                    to_address = "0x" + log['topics'][2].hex()[-40:]
                    if to_address.lower() == coinbase.lower():
                        miner_address_count[coinbase] = miner_address_count.get(coinbase, 0) + 1
                except:
                    continue
            
            # Jika ada alamat yang sering menerima token dari transfer
            if miner_address_count:
                for address, count in miner_address_count.items():
                    if count > 5:  # Minimal 5 transfer
                        patterns.append({
                            'miner_address': address,
                            'transfer_count': count,
                            'probability': min(count / 20, 1.0)  # Probabilitas berdasarkan frekuensi
                        })
        
        except Exception as e:
            self.logger.warning(f"Gagal analisis pola transfer: {str(e)}")
        
        return patterns
    
    def _detect_public_mint_function(self) -> Optional[Dict[str, Any]]:
        """Deteksi fungsi publik mintMinerReward()"""
        try:
            # Cek apakah fungsi mintMinerReward() ada
            selector = get_function_selector("mintMinerReward()")
            if not function_exists(self.w3, self.token_address, selector):
                return None
            
            # Simpan balance sebelum
            balance_before = get_balance(self.w3, self.token_address, self.attacker, self.decimals)
            
            # Coba panggil fungsi
            data = "0x" + selector
            self.w3.eth.call({'to': self.token_address, 'data': data, 'from': self.attacker})
            
            # Cek balance setelah
            balance_after = get_balance(self.w3, self.token_address, self.attacker, self.decimals)
            
            if balance_after > balance_before:
                return {
                    'type': 'PUBLIC_MINT_REWARD',
                    'description': 'Fungsi publik mintMinerReward() terdeteksi dan bisa dipanggil',
                    'severity': 'high',
                    'tokens_received': balance_after - balance_before,
                    'function': 'mintMinerReward()'
                }
        
        except Exception as e:
            if "reverted" not in str(e).lower():
                self._log_debug(f"Gagal deteksi fungsi publik: {str(e)}")
        
        return None
    
    def _detect_transfer_override(self) -> Optional[Dict[str, Any]]:
        """Deteksi kemungkinan override _transfer() yang memicu miner reward"""
        try:
            # Coba kirim transfer kecil
            balance_before = get_balance(self.w3, self.token_address, self.block_coinbase, self.decimals)
            
            # Setup akun untuk simulasi
            from web3.middleware import construct_sign_and_send_raw_middleware
            from web3.middleware import geth_poa_middleware
            
            acct = self.w3.eth.account.from_key(self.config['PRIVATE_KEY'])
            self.w3.middleware_onion.add(construct_sign_and_send_raw_middleware(acct))
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
            
            # Lakukan transfer kecil
            tx = {
                'to': self.token_address,
                'data': get_function_selector("transfer(address,uint256)") + 
                        self.attacker[2:].rjust(64, '0') + 
                        '0000000000000000000000000000000000000000000000000000000000000001',
                'gas': 100000,
                'gasPrice': self.w3.to_wei('2', 'gwei'),
                'nonce': self.w3.eth.get_transaction_count(self.attacker),
            }
            
            # Kirim transaksi
            tx_hash = self.w3.eth.send_transaction(tx)
            self._log_debug(f"Transaksi dikirim: {tx_hash.hex()}")
            
            # Tunggu konfirmasi (di fork, instan)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            self._log_debug(f"Transaksi dikonfirmasi: {receipt['status']}")
            
            # Cek balance block.coinbase setelah
            balance_after = get_balance(self.w3, self.token_address, self.block_coinbase, self.decimals)
            
            # Hitung perubahan
            tokens_minted = balance_after - balance_before
            
            if tokens_minted > 0:
                return {
                    'type': 'TRANSFER_OVERRIDE_REWARD',
                    'description': 'Pola _mintMinerReward() terdeteksi melalui override _transfer()',
                    'severity': 'high',
                    'tokens_minted': tokens_minted,
                    'block_coinbase': self.block_coinbase,
                    'proof': f'Transfer kecil memicu mint {tokens_minted} token ke block.coinbase'
                }
        
        except Exception as e:
            self._log_debug(f"Gagal deteksi override _transfer: {str(e)}")
        
        return None
    
    def _simulate_miner_reward_trigger(self, patterns: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Simulasikan trigger miner reward dengan berbagai teknik"""
        if not patterns:
            return None
        
        # Pilih pola dengan probabilitas tertinggi
        best_pattern = max(patterns, key=lambda x: x['probability'])
        miner_address = best_pattern['miner_address']
        
        results = []
        
        # Teknik 1: Simulasi transfer untuk trigger _transfer override
        self._log_debug("Mencoba trigger via transfer untuk deteksi _transfer override...")
        transfer_result = self._simulate_transfer_trigger(miner_address)
        if transfer_result:
            results.append(transfer_result)
        
        # Teknik 2: Simulasi SELFDESTRUCT untuk mengirim ETH ke kontrak
        self._log_debug("Mencoba trigger via SELFDESTRUCT untuk deteksi receive()...")
        selfdestruct_result = self._simulate_selfdestruct_trigger(miner_address)
        if selfdestruct_result:
            results.append(selfdestruct_result)
        
        # Teknik 3: Simulasi kirim ETH langsung
        self._log_debug("Mencoba trigger via kirim ETH langsung...")
        eth_transfer_result = self._simulate_eth_transfer_trigger(miner_address)
        if eth_transfer_result:
            results.append(eth_transfer_result)
        
        # Ambil hasil dengan nilai tertinggi
        if results:
            best_result = max(results, key=lambda x: x.get('tokens_minted', 0))
            return best_result
        
        return None
    
    def _simulate_transfer_trigger(self, miner_address: str) -> Optional[Dict[str, Any]]:
        """Simulasi transfer untuk trigger _transfer override"""
        try:
            # Simpan balance sebelum
            balance_before = get_balance(self.w3, self.token_address, miner_address, self.decimals)
            
            # Setup akun untuk simulasi
            from web3.middleware import construct_sign_and_send_raw_middleware
            from web3.middleware import geth_poa_middleware
            
            acct = self.w3.eth.account.from_key(self.config['PRIVATE_KEY'])
            self.w3.middleware_onion.add(construct_sign_and_send_raw_middleware(acct))
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
            
            # Lakukan transfer kecil
            tx = {
                'to': self.token_address,
                'data': get_function_selector("transfer(address,uint256)") + 
                        self.attacker[2:].rjust(64, '0') + 
                        '0000000000000000000000000000000000000000000000000000000000000001',
                'gas': 100000,
                'gasPrice': self.w3.to_wei('2', 'gwei'),
                'nonce': self.w3.eth.get_transaction_count(self.attacker),
            }
            
            # Kirim transaksi
            tx_hash = self.w3.eth.send_transaction(tx)
            self._log_debug(f"Transaksi dikirim: {tx_hash.hex()}")
            
            # Tunggu konfirmasi
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            self._log_debug(f"Transaksi dikonfirmasi: {receipt['status']}")
            
            # Cek balance setelah
            balance_after = get_balance(self.w3, self.token_address, miner_address, self.decimals)
            
            # Hitung perubahan
            tokens_minted = balance_after - balance_before
            
            if tokens_minted > 0:
                return {
                    'type': 'TRANSFER_TRIGGERED_REWARD',
                    'description': 'Transfer memicu mint token ke miner',
                    'severity': 'high',
                    'tokens_minted': tokens_minted,
                    'miner_address': miner_address,
                    'proof': f'Transfer kecil memicu mint {tokens_minted} token'
                }
        
        except Exception as e:
            self._log_debug(f"Gagal trigger via transfer: {str(e)}")
        
        return None
    
    def _simulate_selfdestruct_trigger(self, miner_address: str) -> Optional[Dict[str, Any]]:
        """Simulasi SELFDESTRUCT untuk mengirim ETH ke kontrak"""
        try:
            # Cari kontrak dengan fungsi selfdestruct
            related_contracts = self.tenderly.get_related_contracts(self.token_address)
            selfdestruct_contracts = [
                c for c in related_contracts 
                if 'selfdestruct' in c['functions'] or 'kill' in c['functions']
            ]
            
            if not selfdestruct_contracts:
                return None
            
            # Pilih kontrak pertama
            target_contract = selfdestruct_contracts[0]['address']
            self._log_debug(f"Menggunakan kontrak {target_contract} untuk SELFDESTRUCT")
            
            # Simpan balance sebelum
            balance_before = get_balance(self.w3, self.token_address, miner_address, self.decimals)
            
            # Setup akun untuk simulasi
            from web3.middleware import construct_sign_and_send_raw_middleware
            from web3.middleware import geth_poa_middleware
            
            acct = self.w3.eth.account.from_key(self.config['PRIVATE_KEY'])
            self.w3.middleware_onion.add(construct_sign_and_send_raw_middleware(acct))
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
            
            # Cari fungsi selfdestruct
            selfdestruct_selector = None
            for func in selfdestruct_contracts[0]['functions']:
                if 'selfdestruct' in func or 'kill' in func:
                    selfdestruct_selector = get_function_selector(func)
                    break
            
            if not selfdestruct_selector:
                return None
            
            # Siapkan transaksi untuk memicu selfdestruct ke token address
            data = "0x" + selfdestruct_selector + self.token_address[2:].rjust(64, '0')
            
            # Kirim transaksi
            tx = {
                'to': target_contract,
                'data': data,
                'gas': 100000,
                'gasPrice': self.w3.to_wei('2', 'gwei'),
                'nonce': self.w3.eth.get_transaction_count(self.attacker),
                'value': self.w3.to_wei(0.0001, 'ether')
            }
            
            tx_hash = self.w3.eth.send_transaction(tx)
            self._log_debug(f"SELFDESTRUCT dikirim: {tx_hash.hex()}")
            
            # Tunggu konfirmasi
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            self._log_debug(f"Transaksi dikonfirmasi: {receipt['status']}")
            
            # Cek balance setelah
            balance_after = get_balance(self.w3, self.token_address, miner_address, self.decimals)
            
            # Hitung perubahan
            tokens_minted = balance_after - balance_before
            
            if tokens_minted > 0:
                return {
                    'type': 'SELFDESTRUCT_TRIGGERED_REWARD',
                    'description': 'SELFDESTRUCT memicu mint token ke miner',
                    'severity': 'high',
                    'tokens_minted': tokens_minted,
                    'miner_address': miner_address,
                    'trigger_contract': target_contract,
                    'proof': f'SELFDESTRUCT ke token address memicu mint {tokens_minted} token'
                }
        
        except Exception as e:
            self._log_debug(f"Gagal trigger via SELFDESTRUCT: {str(e)}")
        
        return None
    
    def _simulate_eth_transfer_trigger(self, miner_address: str) -> Optional[Dict[str, Any]]:
        """Simulasi kirim ETH langsung ke kontrak"""
        try:
            # Simpan balance sebelum
            balance_before = get_balance(self.w3, self.token_address, miner_address, self.decimals)
            
            # Setup akun untuk simulasi
            from web3.middleware import construct_sign_and_send_raw_middleware
            from web3.middleware import geth_poa_middleware
            
            acct = self.w3.eth.account.from_key(self.config['PRIVATE_KEY'])
            self.w3.middleware_onion.add(construct_sign_and_send_raw_middleware(acct))
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
            
            # Kirim ETH ke kontrak
            tx = {
                'to': self.token_address,
                'value': self.w3.to_wei(0.0001, 'ether'),
                'gas': 100000,
                'gasPrice': self.w3.to_wei('2', 'gwei'),
                'nonce': self.w3.eth.get_transaction_count(self.attacker),
            }
            
            tx_hash = self.w3.eth.send_transaction(tx)
            self._log_debug(f"ETH transfer dikirim: {tx_hash.hex()}")
            
            # Tunggu konfirmasi
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            self._log_debug(f"Transaksi dikonfirmasi: {receipt['status']}")
            
            # Cek balance setelah
            balance_after = get_balance(self.w3, self.token_address, miner_address, self.decimals)
            
            # Hitung perubahan
            tokens_minted = balance_after - balance_before
            
            if tokens_minted > 0:
                return {
                    'type': 'ETH_TRANSFER_TRIGGERED_REWARD',
                    'description': 'Kirim ETH memicu mint token ke miner',
                    'severity': 'high',
                    'tokens_minted': tokens_minted,
                    'miner_address': miner_address,
                    'proof': f'Kirim ETH memicu mint {tokens_minted} token'
                }
        
        except Exception as e:
            self._log_debug(f"Gagal trigger via ETH transfer: {str(e)}")
        
        return None
    
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
            
            # Cek apakah kontrak mungkin memiliki pola yang bisa dimanfaatkan
            if 'withdraw' in contract['functions'] or 'claim' in contract['functions']:
                findings.append({
                    'type': 'POSSIBLE_REWARD_CHAIN',
                    'description': f'Kontrak terkait {contract["address"]} memiliki fungsi yang mungkin terhubung dengan reward',
                    'severity': 'medium',
                    'related_contract': contract['address'],
                    'functions': [f for f in contract['functions'] if 'withdraw' in f or 'claim' in f]
                })
        
        return findings
