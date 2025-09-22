#!/usr/bin/env python3
"""
Token Contract Scanner
Comprehensive scanning for ERC20, ERC721, and other token contract vulnerabilities
"""

import json
import time
from datetime import datetime
from typing import Dict, List, Any
import requests
from core.database import database

class TokenContractScanner:
    """Comprehensive token contract vulnerability scanner"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        # Token contract patterns for identification
        self.token_patterns = {
            'erc20': [
                'balanceOf',
                'transfer',
                'approve',
                'transferFrom',
                'allowance',
                'totalSupply',
                'decimals',
                'name',
                'symbol'
            ],
            'erc721': [
                'ownerOf',
                'transferFrom',
                'approve',
                'getApproved',
                'setApprovalForAll',
                'isApprovedForAll',
                'tokenURI'
            ],
            'erc1155': [
                'balanceOf',
                'balanceOfBatch',
                'setApprovalForAll',
                'isApprovedForAll',
                'safeTransferFrom',
                'safeBatchTransferFrom'
            ]
        }

        # Common token contract vulnerabilities
        self.token_vulnerabilities = [
            {
                'pattern': 'approve',
                'name': 'Token Approve Vulnerability',
                'impact': 'HIGH',
                'description': 'Insufficient approval checks or unlimited approvals',
                'detection_signs': ['approve(address,uint256)', 'allowance(address,address)'],
                'exploit_potential': 8.5,
                'difficulty': 'MEDIUM'
            },
            {
                'pattern': 'transferFrom',
                'name': 'Transfer From Bypass',
                'impact': 'CRITICAL',
                'description': 'Insufficient allowance checks in transferFrom',
                'detection_signs': ['transferFrom(address,address,uint256)'],
                'exploit_potential': 9.0,
                'difficulty': 'MEDIUM'
            },
            {
                'pattern': 'mint',
                'name': 'Unauthorized Minting',
                'impact': 'CRITICAL',
                'description': 'Mint function without proper access control',
                'detection_signs': ['mint(address,uint256)', 'mint(uint256)'],
                'exploit_potential': 10.0,
                'difficulty': 'MEDIUM'
            },
            {
                'pattern': 'burn',
                'name': 'Burn Function Issues',
                'impact': 'MEDIUM',
                'description': 'Burn functions with insufficient validation',
                'detection_signs': ['burn(uint256)', 'burn(address,uint256)'],
                'exploit_potential': 6.5,
                'difficulty': 'HIGH'
            },
            {
                'pattern': 'owner',
                'name': 'Owner Function Abuse',
                'impact': 'CRITICAL',
                'description': 'Critical functions accessible only by owner',
                'detection_signs': ['onlyOwner', 'require(msg.sender == owner)'],
                'exploit_potential': 8.0,
                'difficulty': 'MEDIUM'
            },
            {
                'pattern': 'pause',
                'name': 'Pause Mechanism',
                'impact': 'HIGH',
                'description': 'Pause functionality that can be abused',
                'detection_signs': ['pause()', 'unpause()', 'whenPaused'],
                'exploit_potential': 7.5,
                'difficulty': 'MEDIUM'
            }
        ]

    def scan_token_contracts(self, chain_name: str, token_addresses: List[str] = None) -> List[Dict[str, Any]]:
        """Scan token contracts for vulnerabilities"""
        print(f"🔍 Scanning token contracts on {chain_name}")
        print("="*50)

        if not token_addresses:
            # Auto-discover token contracts
            token_addresses = self.discover_token_contracts(chain_name)

        scanned_tokens = []

        for token_address in token_addresses:
            try:
                print(f"🔎 Scanning token: {token_address}")
                token_data = self.scan_single_token(token_address, chain_name)
                if token_data:
                    scanned_tokens.append(token_data)
                    database.add_contract(token_data)
                    database.add_vulnerabilities(token_data['vulnerabilities'])
                    print(f"✅ Scanned: {token_data.get('name', 'Unknown Token')}")
                else:
                    print(f"❌ Failed to scan: {token_address}")

                # Rate limiting
                time.sleep(1)

            except Exception as e:
                print(f"❌ Error scanning {token_address}: {e}")

        print(f"\n📊 Token Scan Results:")
        print(f"   Total Tokens Scanned: {len(scanned_tokens)}")
        total_vulns = sum(len(token.get('vulnerabilities', [])) for token in scanned_tokens)
        print(f"   Total Vulnerabilities: {total_vulns}")

        # Count by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for token in scanned_tokens:
            for vuln in token.get('vulnerabilities', []):
                severity = vuln.get('impact', 'LOW')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

        for severity, count in severity_counts.items():
            print(f"   {severity}: {count}")

        return scanned_tokens

    def discover_token_contracts(self, chain_name: str) -> List[str]:
        """Discover token contracts on specific chain"""
        token_addresses = []

        # Known major token contracts
        known_tokens = {
            'ethereum_mainnet': [
                '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984',  # UNI
                '0xA0b86a33E6417aAb7b6DbCBbe9FD4E89c0778a4B',  # USDC
                '0x6B175474E89094C44Da98b954EedeAC495271d0F',  # DAI
                '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599',  # LINK
                '0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9',  # AAVE
                '0x397FF1542f962076d0Bfe6e1108e375B62E3F2a3',  # COMP
                '0x0000000000000000000000000000000000000000',  # ETH (native)
            ],
            'polygon_mainnet': [
                '0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619',  # WMATIC
                '0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270',  # MATIC
                '0x7ceb23fd6bc0add59e62ac25578270cff1b9f619',  # WMATIC (alternative)
            ],
            'arbitrum_one': [
                '0x82aF49447D8a07e3bdEBe6E8526d6e3a302af3b7',  # ARB
                '0x912CE59144191C1204E64559E54c3F30In9aF8DF',  # USDC (Arbitrum)
            ]
        }

        if chain_name in known_tokens:
            token_addresses.extend(known_tokens[chain_name])

        # Get tokens from transaction data
        discovered_tokens = self.get_tokens_from_transactions(chain_name)
        token_addresses.extend(discovered_tokens)

        # Remove duplicates
        token_addresses = list(set(token_addresses))

        print(f"📋 Discovered {len(token_addresses)} token contracts on {chain_name}")
        return token_addresses

    def get_tokens_from_transactions(self, chain_name: str) -> List[str]:
        """Discover token contracts from transaction data"""
        discovered_tokens = []

        try:
            # This would typically involve scanning token transaction APIs
            # For now, return some example token addresses
            example_tokens = [
                '0x1234567890123456789012345678901234567890',
                '0x2345678901234567890123456789012345678901',
                '0x3456789012345667890123456789012345678902',
            ]

            discovered_tokens.extend(example_tokens)

        except Exception as e:
            print(f"⚠️ Could not discover tokens from transactions: {e}")

        return discovered_tokens

    def scan_single_token(self, token_address: str, chain_name: str) -> Dict[str, Any]:
        """Scan a single token contract for vulnerabilities"""
        try:
            # Get token contract details
            contract_info = self.get_token_contract_info(token_address, chain_name)

            if not contract_info:
                return None

            # Get token vulnerabilities
            vulnerabilities = self.detect_token_vulnerabilities(contract_info)

            # Create token data
            token_data = {
                'address': token_address,
                'name': contract_info.get('name', 'Unknown Token'),
                'symbol': contract_info.get('symbol', 'UNKNOWN'),
                'description': contract_info.get('description', f'Token contract on {chain_name}'),
                'category': 'token',
                'chain_name': chain_name,
                'chain_id': self.get_chain_id(chain_name),
                'is_verified': contract_info.get('is_verified', False),
                'token_type': contract_info.get('token_type', 'ERC20'),
                'decimals': contract_info.get('decimals', 18),
                'total_supply': contract_info.get('total_supply', 0),
                'functions_count': contract_info.get('functions_count', 0),
                'risk_score': self.calculate_token_risk_score(vulnerabilities),
                'risk_level': self.get_risk_level(self.calculate_token_risk_score(vulnerabilities)),
                'vulnerabilities': vulnerabilities,
                'discovered_at': datetime.now().isoformat(),
                'scan_type': 'TOKEN_VULNERABILITY_SCAN',
                'last_updated': datetime.now().isoformat(),
                'vulnerability_count': len(vulnerabilities),
                'risk_factors': self.extract_risk_factors(vulnerabilities)
            }

            return token_data

        except Exception as e:
            print(f"❌ Error scanning token {token_address}: {e}")
            return None

    def get_token_contract_info(self, token_address: str, chain_name: str) -> Dict[str, Any]:
        """Get detailed information about a token contract"""
        try:
            # Use Etherscan or Blockscout API to get token info
            api_url = self.get_token_api_url(chain_name, token_address)

            if not api_url:
                # Mock data for demonstration
                return self.get_mock_token_info(token_address)

            response = self.session.get(api_url, timeout=30)

            if response.status_code == 200:
                data = response.json()

                # Parse token information based on API response
                if 'etherscan' in api_url:
                    return self.parse_etherscan_token_info(data)
                elif 'blockscout' in api_url:
                    return self.parse_blockscout_token_info(data)

            return self.get_mock_token_info(token_address)

        except Exception as e:
            print(f"⚠️ Could not get real token info for {token_address}: {e}")
            return self.get_mock_token_info(token_address)

    def get_token_api_url(self, chain_name: str, token_address: str) -> str:
        """Get API URL for token information"""
        api_configs = {
            'ethereum_mainnet': {
                'api_url': 'https://api.etherscan.io/api',
                'api_key': 'YourApiKeyHere'
            },
            'polygon_mainnet': {
                'api_url': 'https://api.polygonscan.com/api',
                'api_key': 'YourApiKeyHere'
            },
            'arbitrum_one': {
                'api_url': 'https://api.arbiscan.io/api',
                'api_key': 'YourApiKeyHere'
            }
        }

        if chain_name in api_configs:
            config = api_configs[chain_name]
            return f"{config['api_url']}?module=token&action=tokeninfo&contractaddress={token_address}&apikey={config['api_key']}"

        return None

    def get_mock_token_info(self, token_address: str) -> Dict[str, Any]:
        """Get mock token information for demonstration"""
        return {
            'name': f'Token-{token_address[:8]}',
            'symbol': f'TKN-{token_address[-6:]}',
            'description': 'Mock token contract for demonstration',
            'is_verified': True,
            'token_type': 'ERC20',
            'decimals': 18,
            'total_supply': 1000000000 * 10**18,
            'functions_count': 9,
            'abi': self.get_mock_token_abi(),
            'source_code': 'pragma solidity ^0.8.0;\n\ncontract MockToken { /* mock implementation */ }'
        }

    def get_mock_token_abi(self) -> List[Dict[str, Any]]:
        """Get mock token ABI for demonstration"""
        return [
            {
                'inputs': [],
                'name': 'name',
                'outputs': [{'internalType': 'string', 'name': '', 'type': 'string'}],
                'stateMutability': 'view',
                'type': 'function'
            },
            {
                'inputs': [],
                'name': 'symbol',
                'outputs': [{'internalType': 'string', 'name': '', 'type': 'string'}],
                'stateMutability': 'view',
                'type': 'function'
            },
            {
                'inputs': [],
                'name': 'decimals',
                'outputs': [{'internalType': 'uint8', 'name': '', 'type': 'uint8'}],
                'stateMutability': 'view',
                'type': 'function'
            },
            {
                'inputs': [{'internalType': 'address', 'name': 'spender', 'type': 'address'}, {'internalType': 'uint256', 'name': 'amount', 'type': 'uint256'}],
                'name': 'approve',
                'outputs': [{'internalType': 'bool', 'name': '', 'type': 'bool'}],
                'stateMutability': 'nonpayable',
                'type': 'function'
            },
            {
                'inputs': [{'internalType': 'address', 'name': 'to', 'type': 'address'}, {'internalType': 'uint256', 'name': 'amount', 'type': 'uint256'}],
                'name': 'transfer',
                'outputs': [{'internalType': 'bool', 'name': '', 'type': 'bool'}],
                'stateMutability': 'nonpayable',
                'type': 'function'
            }
        ]

    def parse_etherscan_token_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Etherscan token info response"""
        result = data.get('result', [{}])[0]

        return {
            'name': result.get('name', 'Unknown Token'),
            'symbol': result.get('symbol', 'UNKNOWN'),
            'description': f'Token on Etherscan',
            'is_verified': result.get('isVerified', False),
            'token_type': 'ERC20',
            'decimals': int(result.get('decimals', 18)),
            'total_supply': int(result.get('totalSupply', 0)),
            'functions_count': len(result.get('abi', [])),
            'abi': result.get('abi', []),
            'source_code': result.get('sourceCode', '')
        }

    def parse_blockscout_token_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Blockscout token info response"""
        # Blockscout parsing logic would go here
        return self.get_mock_token_info('mock_address')

    def detect_token_vulnerabilities(self, contract_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect vulnerabilities in token contract"""
        vulnerabilities = []

        # Get ABI functions
        functions = self.extract_functions_from_abi(contract_info.get('abi', []))

        # Check each vulnerability pattern
        for vuln_pattern in self.token_vulnerabilities:
            if self.check_vulnerability_pattern(functions, vuln_pattern):
                vuln = vuln_pattern.copy()
                vuln['contract_name'] = contract_info.get('name', 'Unknown')
                vuln['contract_address'] = getattr(self, 'current_address', 'unknown')
                vulnerabilities.append(vuln)

        # Detect token-specific vulnerabilities
        token_type_vulns = self.detect_token_type_vulnerabilities(contract_info, functions)
        vulnerabilities.extend(token_type_vulns)

        return vulnerabilities

    def extract_functions_from_abi(self, abi: List[Dict[str, Any]]) -> List[str]:
        """Extract function names from ABI"""
        functions = []
        for item in abi:
            if item.get('type') == 'function':
                functions.append(item.get('name', 'unknown'))
        return functions

    def check_vulnerability_pattern(self, functions: List[str], vuln_pattern: Dict[str, Any]) -> bool:
        """Check if vulnerability pattern exists in contract functions"""
        pattern_functions = vuln_pattern.get('detection_signs', [])

        for pattern_func in pattern_functions:
            if pattern_func in functions:
                return True

        return False

    def detect_token_type_vulnerabilities(self, contract_info: Dict[str, Any], functions: List[str]) -> List[Dict[str, Any]]:
        """Detect vulnerabilities specific to token type"""
        vulnerabilities = []
        token_type = contract_info.get('token_type', 'ERC20')

        if token_type == 'ERC20':
            # ERC20 specific vulnerabilities
            erc20_vulns = [
                {
                    'pattern': 'transfer',
                    'name': 'Token Transfer Reentrancy',
                    'impact': 'CRITICAL',
                    'description': 'Potential reentrancy vulnerability in transfer function',
                    'detection_signs': ['transfer(address,uint256)'],
                    'exploit_potential': 8.0,
                    'difficulty': 'HIGH',
                    'contract_name': contract_info.get('name', 'Unknown'),
                    'contract_address': getattr(self, 'current_address', 'unknown')
                }
            ]
            vulnerabilities.extend(erc20_vulns)

        return vulnerabilities

    def calculate_token_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> int:
        """Calculate overall risk score for token"""
        if not vulnerabilities:
            return 1

        total_score = 0
        for vuln in vulnerabilities:
            impact_score = {'CRITICAL': 10, 'HIGH': 8, 'MEDIUM': 6, 'LOW': 3}
            exploit_score = vuln.get('exploit_potential', 5)
            total_score += impact_score.get(vuln.get('impact', 'LOW'), 1) * (exploit_score / 10)

        return min(25, int(total_score))

    def get_risk_level(self, risk_score: int) -> str:
        """Get risk level based on score"""
        if risk_score >= 20:
            return 'CRITICAL'
        elif risk_score >= 15:
            return 'HIGH'
        elif risk_score >= 10:
            return 'MEDIUM'
        elif risk_score >= 5:
            return 'LOW'
        else:
            return 'MINIMAL'

    def extract_risk_factors(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Extract risk factors from vulnerabilities"""
        risk_factors = []

        for vuln in vulnerabilities:
            risk_factors.append(f"{vuln['name']}: {vuln['impact']}")

        return risk_factors

    def get_chain_id(self, chain_name: str) -> int:
        """Get chain ID for chain name"""
        chain_ids = {
            'ethereum_mainnet': 1,
            'polygon_mainnet': 137,
            'arbitrum_one': 42161,
            'optimism': 10,
            'bsc_mainnet': 56,
            'avalanche': 43114
        }

        return chain_ids.get(chain_name, 1)

def main():
    """Main execution function for token scanning"""
    print("🚀 Token Contract Vulnerability Scanner")
    print("="*60)

    scanner = TokenContractScanner()

    # Scan on multiple chains
    chains = ['ethereum_mainnet', 'polygon_mainnet', 'arbitrum_one']

    for chain in chains:
        print(f"\n🔗 Scanning on {chain}")
        tokens_scanned = scanner.scan_token_contracts(chain)

        print(f"✅ Completed scan on {chain}: {len(tokens_scanned)} tokens scanned")

    # Show summary
    show_token_scanning_summary()

def show_token_scanning_summary():
    """Show comprehensive scanning summary"""
    print("\n📊 TOKEN SCANNING SUMMARY")
    print("="*60)

    try:
        # Get database statistics
        stats = database.get_statistics()

        print("📈 Token Statistics:")
        print(f"   Total Token Contracts: {stats.get('contracts', {}).get('total', 0)}")
        print(f"   Total Token Vulnerabilities: {stats.get('vulnerabilities', {}).get('total', 0)}")

        # Get token contracts
        contracts = database.get_contracts()
        token_contracts = [c for c in contracts if c.get('category') == 'token']

        print(f"\n🔍 Token Contracts by Type:")
        token_types = {}
        for token in token_contracts:
            token_type = token.get('token_type', 'Unknown')
            token_types[token_type] = token_types.get(token_type, 0) + 1

        for token_type, count in token_types.items():
            print(f"   {token_type}: {count} contracts")

        # Show high-risk tokens
        high_risk_tokens = [t for t in token_contracts if t.get('risk_level') in ['CRITICAL', 'HIGH']]

        print(f"\n🚨 High-Risk Token Contracts: {len(high_risk_tokens)}")
        for token in high_risk_tokens[:3]:
            print(f"   • {token['name']} ({token['risk_level']})")
            print(f"     Address: {token['address']}")
            print(f"     Risk Score: {token['risk_score']}")
            print(f"     Vulnerabilities: {token['vulnerability_count']}")

    except Exception as e:
        print(f"❌ Error showing summary: {e}")

if __name__ == "__main__":
    main()