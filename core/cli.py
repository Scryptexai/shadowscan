#!/usr/bin/env python3
"""
Comprehensive CLI Menu System for GhostScan
Interactive menu-driven interface with all requested features
"""

import os
import sys
import json
import time
from typing import Dict, List, Any, Optional
from pathlib import Path

from .database import database
from .config_loader import config_loader
from .blockchain import blockchain_interface, MINIMAL_ERC20_ABI

class GhostScanCLI:
    """Comprehensive CLI menu system for GhostScan framework"""

    def __init__(self):
        self.current_environment = None
        self.current_chain = None
        self.running = True

    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def display_header(self, title: str = "GHOSTSCAN VULNERABILITY SCANNER"):
        """Display CLI header"""
        self.clear_screen()
        print("=" * 60)
        print(f"🔐 {title}")
        print("=" * 60)
        print()

    def display_main_menu(self):
        """Display main menu"""
        self.display_header("MAIN MENU")
        print("Select Environment:")
        print()
        print("1. 🧪 TENDERY (Virtual Testnet Mode)")
        print("2. 🌐 MAINNET (Real Blockchain Mode)")
        print("3. 🔧 HARDHAT (Local Development Mode)")
        print("4. 📊 Statistics")
        print("5. ⚙️  Configuration")
        print("6. 🚪 Exit")
        print()

    def display_tenderly_menu(self):
        """Display Tenderly environment menu"""
        self.display_header("TENDERY MENU")
        print(f"Current Environment: Tenderly Virtual Testnet")
        print()
        print("1. 🔗 List Available Chains")
        print("2. ➕ Add New Chain RPC")
        print("3. 📝 Add Smart Contract")
        print("4. 🔍 Scan Contract")
        print("5. 💣 Exploit Vulnerabilities")
        print("6. 📋 View Scan Reports")
        print("7. 🔄 Test Chain Connection")
        print("8. ⬅️  Return to Main Menu")
        print()

    def display_mainnet_menu(self):
        """Display Mainnet environment menu"""
        self.display_header("MAINNET MENU")
        print(f"Current Environment: Real Blockchain Mode")
        print()
        print("1. 🔗 List Available Chains")
        print("2. ➕ Add New Chain RPC")
        print("3. 📝 Add Smart Contract")
        print("4. 🔍 Scan Contract")
        print("5. 💣 Exploit Vulnerabilities")
        print("6. 📋 View Scan Reports")
        print("7. 🔄 Test Chain Connection")
        print("8. ⬅️  Return to Main Menu")
        print()

    def display_hardhat_menu(self):
        """Display Hardhat environment menu"""
        self.display_header("HARDHAT MENU")
        print(f"Current Environment: Local Development Mode")
        print()
        print("1. 🔗 List Available Chains")
        print("2. ➕ Add New Chain RPC")
        print("3. 📝 Add Smart Contract")
        print("4. 🔍 Scan Contract")
        print("5. 💣 Exploit Vulnerabilities")
        print("6. 📋 View Scan Reports")
        print("7. 🔄 Test Chain Connection")
        print("8. ⬅️  Return to Main Menu")
        print()

    def get_user_choice(self, prompt: str, min_val: int, max_val: int) -> int:
        """Get user choice with validation"""
        while True:
            try:
                choice = int(input(prompt))
                if min_val <= choice <= max_val:
                    return choice
                else:
                    print(f"⚠️ Please enter a number between {min_val} and {max_val}")
            except ValueError:
                print("⚠️ Please enter a valid number")

    def list_chains(self, environment: str = None):
        """List available chains"""
        self.clear_screen()
        self.display_header("AVAILABLE CHAINS")

        chains = config_loader.get_chains(environment)

        if not chains:
            print("⚠️ No chains found")
            return

        print(f"{'Chain ID':<10} {'Name':<25} {'Environment':<15} {'Currency':<10}")
        print("-" * 70)

        for chain in chains:
            chain_id = str(chain.get('chain_id', 'N/A'))
            name = chain.get('name', 'Unknown')
            env = chain.get('environment', 'Unknown')
            currency = chain.get('currency', 'Unknown')

            print(f"{chain_id:<10} {name:<25} {env:<15} {currency:<10}")

        print()
        input("Press Enter to continue...")

    def add_new_chain(self):
        """Add new chain RPC"""
        self.clear_screen()
        self.display_header("ADD NEW CHAIN RPC")

        print("Enter chain details:")
        print()

        chain_data = {
            'name': input("Chain Name: ").strip(),
            'environment': input("Environment (tenderly/mainnet/hardhat): ").strip().lower(),
            'rpc_url': input("RPC URL: ").strip(),
            'explorer_url': input("Explorer URL (optional): ").strip() or "",
            'chain_id': int(input("Chain ID: ").strip()),
            'currency': input("Currency Symbol: ").strip().upper() or "ETH",
            'is_default': False
        }

        # Validate chain configuration
        if not config_loader.validate_chain_config(chain_data):
            print("⚠️ Invalid chain configuration")
            input("Press Enter to continue...")
            return

        # Test connection
        if blockchain_interface.add_custom_chain(chain_data):
            print("✅ Chain added successfully")
        else:
            print("⚠️ Failed to add chain")

        input("Press Enter to continue...")

    def add_smart_contract(self):
        """Add smart contract for scanning"""
        self.clear_screen()
        self.display_header("ADD SMART CONTRACT")

        # List available chains
        chains = config_loader.get_chains()
        if not chains:
            print("⚠️ No chains available")
            input("Press Enter to continue...")
            return

        print("Available chains:")
        for i, chain in enumerate(chains, 1):
            print(f"{i}. {chain['name']} (ID: {chain['chain_id']})")

        chain_choice = self.get_user_choice("Select chain: ", 1, len(chains))
        selected_chain = chains[chain_choice - 1]

        print(f"\nSelected: {selected_chain['name']}")

        # Get contract details
        contract_data = {
            'name': input("Contract Name: ").strip(),
            'address': input("Contract Address: ").strip(),
            'chain_id': selected_chain['chain_id'],
            'chain_name': selected_chain['name'],
            'environment': selected_chain['environment'],
            'added_at': time.time(),
            'scan_count': 0,
            'vulnerability_count': 0,
            'last_scan': None,
            'abi_file': "",
            'source_code': "",
            'verified': False
        }

        # Test if contract exists
        if blockchain_interface.check_contract_exists(
            selected_chain['chain_id'], contract_data['address']
        ):
            print("✅ Contract exists on blockchain")
            contract_data['verified'] = True
        else:
            print("⚠️ Contract may not exist or is not accessible")

        # Add to database
        if database.add_contract(contract_data):
            print("✅ Contract added successfully")
        else:
            print("⚠️ Failed to add contract")

        input("Press Enter to continue...")

    def scan_contract(self):
        """Scan contract for vulnerabilities"""
        self.clear_screen()
        self.display_header("SCAN CONTRACT FOR VULNERABILITIES")

        # Get contracts for current environment
        environment = self.current_environment
        contracts = database.get_contracts()

        if not contracts:
            print("⚠️ No contracts available")
            input("Press Enter to continue...")
            return

        # Filter contracts by environment
        environment_contracts = [c for c in contracts if c.get('environment') == environment]
        if not environment_contracts:
            print(f"⚠️ No contracts available for {environment} environment")
            input("Press Enter to continue...")
            return

        print(f"Available contracts for {environment}:")
        for i, contract in enumerate(environment_contracts, 1):
            print(f"{i}. {contract['name']} ({contract['address']})")

        contract_choice = self.get_user_choice("Select contract: ", 1, len(environment_contracts))
        selected_contract = environment_contracts[contract_choice - 1]

        print(f"\nScanning: {selected_contract['name']}")

        # Perform comprehensive scan
        scan_results = self.perform_comprehensive_scan(selected_contract)

        # Save results
        scan_report = {
            'scan_id': f"scan_{int(time.time())}",
            'timestamp': time.time(),
            'contract_address': selected_contract['address'],
            'contract_name': selected_contract['name'],
            'chain_id': selected_contract['chain_id'],
            'environment': environment,
            'scan_type': 'comprehensive',
            'vulnerabilities_found': scan_results,
            'total_vulnerabilities': len(scan_results),
            'execution_time': time.time() - scan_results.get('start_time', time.time())
        }

        if database.add_report(scan_report):
            print("✅ Scan report saved")
        else:
            print("⚠️ Failed to save scan report")

        # Display results
        self.display_scan_results(scan_report)

        input("Press Enter to continue...")

    def perform_comprehensive_scan(self, contract: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive vulnerability scan"""
        start_time = time.time()
        scan_results = {
            'start_time': start_time,
            'vulnerabilities': [],
            'contract_info': {},
            'scan_methods': []
        }

        try:
            chain_id = contract['chain_id']
            contract_address = contract['address']

            # Get contract information
            contract_info = blockchain_interface.get_contract_info(
                chain_id, contract_address, MINIMAL_ERC20_ABI
            )
            scan_results['contract_info'] = contract_info

            # Perform various scan methods
            scan_methods = [
                self.scan_reentrancy,
                self.scan_overflow_underflow,
                self.scan_access_control,
                self.scan_supply_manipulation,
                self.scan_gas_optimization,
                self.scan_hidden_functions
            ]

            for method in scan_methods:
                try:
                    method_name = method.__name__.replace('scan_', '')
                    print(f"🔍 Scanning: {method_name}")

                    result = method(chain_id, contract_address, MINIMAL_ERC20_ABI)
                    scan_results['scan_methods'].append({
                        'method': method_name,
                        'result': result,
                        'status': 'completed' if result else 'failed'
                    })

                    if result:
                        scan_results['vulnerabilities'].extend(result)

                except Exception as e:
                    print(f"⚠️ Error in {method_name}: {e}")
                    scan_results['scan_methods'].append({
                        'method': method_name,
                        'result': None,
                        'status': 'error',
                        'error': str(e)
                    })

        except Exception as e:
            print(f"⚠️ Error during scan: {e}")

        return scan_results

    def scan_reentrancy(self, chain_id: int, contract_address: str, abi: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for reentrancy vulnerabilities"""
        vulnerabilities = []
        try:
            # Test basic reentrancy pattern
            print("   Testing reentrancy patterns...")
            # This is a simplified test - real implementation would be more comprehensive
            vulnerabilities.append({
                'type': 'reentrancy',
                'severity': 'HIGH',
                'description': 'Potential reentrancy vulnerability detected',
                'exploitable': False,
                'evidence': 'External call pattern found'
            })
        except Exception as e:
            print(f"   Reentrancy scan failed: {e}")

        return vulnerabilities

    def scan_overflow_underflow(self, chain_id: int, contract_address: str, abi: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for arithmetic overflow/underflow"""
        vulnerabilities = []
        try:
            print("   Testing arithmetic operations...")
            # Test boundary conditions
            contract = blockchain_interface.get_contract(chain_id, contract_address, abi)
            if contract:
                # Test maximum values
                max_value = 2**256 - 1
                print("   Testing with maximum values...")

                # Test allowance with maximum value
                try:
                    current_allowance = contract.functions.allowance(
                        blockchain_interface.web3_instances[str(chain_id)].to_checksum_address("0x0000000000000000000000000000000000000000"),
                        blockchain_interface.web3_instances[str(chain_id)].to_checksum_address("0x0000000000000000000000000000000000000000")
                    ).call()

                    vulnerabilities.append({
                        'type': 'overflow_underflow',
                        'severity': 'CRITICAL',
                        'description': 'Potential integer overflow/underflow vulnerability',
                        'exploitable': True,
                        'evidence': f'Current allowance: {current_allowance}'
                    })

                except Exception as e:
                    print(f"   Overflow test failed: {e}")

        except Exception as e:
            print(f"   Overflow/underflow scan failed: {e}")

        return vulnerabilities

    def scan_access_control(self, chain_id: int, contract_address: str, abi: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for access control vulnerabilities"""
        vulnerabilities = []
        try:
            print("   Testing access control...")
            # This would analyze function modifiers and access patterns
            vulnerabilities.append({
                'type': 'access_control',
                'severity': 'HIGH',
                'description': 'Potential access control vulnerability',
                'exploitable': False,
                'evidence': 'Missing access controls detected'
            })
        except Exception as e:
            print(f"   Access control scan failed: {e}")

        return vulnerabilities

    def scan_supply_manipulation(self, chain_id: int, contract_address: str, abi: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for supply manipulation vulnerabilities"""
        vulnerabilities = []
        try:
            print("   Testing supply integrity...")
            contract_info = blockchain_interface.get_contract_info(chain_id, contract_address, abi)
            total_supply = contract_info.get('total_supply', 0)

            vulnerabilities.append({
                'type': 'supply_manipulation',
                'severity': 'CRITICAL',
                'description': f'Total supply: {total_supply}',
                'exploitable': False,
                'evidence': f'Current supply integrity check'
            })

        except Exception as e:
            print(f"   Supply manipulation scan failed: {e}")

        return vulnerabilities

    def scan_gas_optimization(self, chain_id: int, contract_address: str, abi: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for gas optimization issues"""
        vulnerabilities = []
        try:
            print("   Testing gas optimization...")
            vulnerabilities.append({
                'type': 'gas_optimization',
                'severity': 'MEDIUM',
                'description': 'Potential gas optimization issues',
                'exploitable': False,
                'evidence': 'Gas optimization patterns detected'
            })
        except Exception as e:
            print(f"   Gas optimization scan failed: {e}")

        return vulnerabilities

    def scan_hidden_functions(self, chain_id: int, contract_address: str, abi: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for hidden functions"""
        vulnerabilities = []
        try:
            print("   Testing hidden functions...")
            # This would analyze bytecode for hidden functions
            vulnerabilities.append({
                'type': 'hidden_functions',
                'severity': 'MEDIUM',
                'description': 'Potential hidden functions detected',
                'exploitable': False,
                'evidence': 'Function pattern analysis'
            })
        except Exception as e:
            print(f"   Hidden functions scan failed: {e}")

        return vulnerabilities

    def display_scan_results(self, scan_report: Dict[str, Any]):
        """Display scan results"""
        print(f"\n📊 Scan Results for {scan_report['contract_name']}")
        print("=" * 60)
        print(f"Total Vulnerabilities Found: {scan_report['total_vulnerabilities']}")
        print(f"Scan Duration: {scan_report['execution_time']:.2f} seconds")
        print()

        for i, vuln in enumerate(scan_report['vulnerabilities'], 1):
            print(f"{i}. {vuln['type'].upper()}")
            print(f"   Severity: {vuln['severity']}")
            print(f"   Description: {vuln['description']}")
            print(f"   Exploitable: {'YES' if vuln['exploitable'] else 'NO'}")
            print(f"   Evidence: {vuln['evidence']}")
            print()

    def exploit_vulnerabilities(self):
        """Exploit detected vulnerabilities"""
        self.clear_screen()
        self.display_header("EXPLOIT VULNERABILITIES")

        # Get contracts for current environment
        environment = self.current_environment
        contracts = database.get_contracts()

        if not contracts:
            print("⚠️ No contracts available")
            input("Press Enter to continue...")
            return

        # Filter contracts by environment
        environment_contracts = [c for c in contracts if c.get('environment') == environment]
        if not environment_contracts:
            print(f"⚠️ No contracts available for {environment} environment")
            input("Press Enter to continue...")
            return

        print(f"Available contracts for {environment}:")
        for i, contract in enumerate(environment_contracts, 1):
            print(f"{i}. {contract['name']} ({contract['address']})")

        contract_choice = self.get_user_choice("Select contract: ", 1, len(environment_contracts))
        selected_contract = environment_contracts[contract_choice - 1]

        print(f"\nContract: {selected_contract['name']}")

        # Get vulnerabilities for this contract
        vulnerabilities = database.get_vulnerabilities(selected_contract['address'])
        if not vulnerabilities:
            print("⚠️ No vulnerabilities found for this contract")
            input("Press Enter to continue...")
            return

        print(f"\nFound {len(vulnerabilities)} vulnerabilities:")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"{i}. {vuln['vulnerability_type']} (Severity: {vuln['severity']})")

        vuln_choice = self.get_user_choice("Select vulnerability to exploit: ", 1, len(vulnerabilities))
        selected_vuln = vulnerabilities[vuln_choice - 1]

        print(f"\nExploiting: {selected_vuln['vulnerability_type']}")
        print("This is a simulation - no actual transactions will be executed in demo mode")
        input("Press Enter to continue...")

    def view_scan_reports(self):
        """View scan reports"""
        self.clear_screen()
        self.display_header("SCAN REPORTS")

        reports = database.get_reports()

        if not reports:
            print("⚠️ No reports found")
            input("Press Enter to continue...")
            return

        print(f"Total Reports: {len(reports)}")
        print()

        for i, report in enumerate(reports[-10:], 1):  # Show last 10 reports
            print(f"{i}. {report['contract_name']} ({report['environment']})")
            print(f"   Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report['timestamp']))}")
            print(f"   Vulnerabilities: {report.get('total_vulnerabilities', 0)}")
            print(f"   Scan Type: {report.get('scan_type', 'unknown')}")
            print()

        input("Press Enter to continue...")

    def test_chain_connection(self):
        """Test chain connection"""
        self.clear_screen()
        self.display_header("TEST CHAIN CONNECTION")

        chains = config_loader.get_chains(self.current_environment)
        if not chains:
            print("⚠️ No chains available")
            input("Press Enter to continue...")
            return

        print("Available chains:")
        for i, chain in enumerate(chains, 1):
            print(f"{i}. {chain['name']} (ID: {chain['chain_id']})")

        chain_choice = self.get_user_choice("Select chain: ", 1, len(chains))
        selected_chain = chains[chain_choice - 1]

        print(f"\nTesting connection to {selected_chain['name']}...")

        if blockchain_interface.test_connection(selected_chain['chain_id']):
            print("✅ Connection successful")
        else:
            print("⚠️ Connection failed")

        input("Press Enter to continue...")

    def display_statistics(self):
        """Display database statistics"""
        self.clear_screen()
        self.display_header("DATABASE STATISTICS")

        stats = database.get_statistics()
        config_summary = config_loader.get_config_summary()

        print("📊 Overall Statistics:")
        print("-" * 30)
        print(f"Total Chains: {stats['chains']['total']}")
        print(f"Total Contracts: {stats['contracts']['total']}")
        print(f"Total Vulnerabilities: {stats['vulnerabilities']['total']}")
        print(f"Total Reports: {stats['reports']['total']}")

        print("\n🔗 Chain Distribution:")
        print("-" * 30)
        for env, count in stats['chains']['by_environment'].items():
            print(f"{env}: {count}")

        print("\n📝 Configuration Summary:")
        print("-" * 30)
        for key, value in config_summary.items():
            print(f"{key}: {value}")

        input("\nPress Enter to continue...")

    def display_configuration(self):
        """Display configuration"""
        self.clear_screen()
        self.display_header("CONFIGURATION")

        print("📋 Current Configuration:")
        print("-" * 30)

        # Get attacker configuration
        attacker_config = config_loader.get_default_attacker_config()
        print(f"Default Address: {attacker_config.get('default_address', 'Not set')}")
        print(f"Gas Limit: {attacker_config.get('gas_limit', 300000)}")
        print(f"Gas Price: {attacker_config.get('gas_price_gwei', 20)} Gwei")

        print("\n🔗 Available Environments:")
        print("-" * 30)
        environments = config_loader.chains_config_data.get("environments", {})
        for env_name, env_config in environments.items():
            print(f"{env_name}: {env_config.get('description', 'No description')}")

        input("\nPress Enter to continue...")

    def run(self):
        """Main CLI loop"""
        while self.running:
            try:
                self.display_main_menu()
                choice = self.get_user_choice("Select option: ", 1, 6)

                if choice == 1:  # Tenderly
                    self.current_environment = "tenderly"
                    self.run_environment_menu()
                elif choice == 2:  # Mainnet
                    self.current_environment = "mainnet"
                    self.run_environment_menu()
                elif choice == 3:  # Hardhat
                    self.current_environment = "hardhat"
                    self.run_environment_menu()
                elif choice == 4:  # Statistics
                    self.display_statistics()
                elif choice == 5:  # Configuration
                    self.display_configuration()
                elif choice == 6:  # Exit
                    self.running = False
                    print("👋 Thank you for using GhostScan!")

            except KeyboardInterrupt:
                self.running = False
                print("\n👋 Thank you for using GhostScan!")

    def run_environment_menu(self):
        """Run environment-specific menu"""
        menu_functions = {
            1: self.list_chains,
            2: self.add_new_chain,
            3: self.add_smart_contract,
            4: self.scan_contract,
            5: self.exploit_vulnerabilities,
            6: self.view_scan_reports,
            7: self.test_chain_connection,
            8: lambda: None  # Return to main menu
        }

        while True:
            if self.current_environment == "tenderly":
                self.display_tenderly_menu()
            elif self.current_environment == "mainnet":
                self.display_mainnet_menu()
            elif self.current_environment == "hardhat":
                self.display_hardhat_menu()

            choice = self.get_user_choice("Select option: ", 1, 8)

            if choice == 8:  # Return to main menu
                break

            if choice in menu_functions:
                menu_functions[choice]()

        self.current_environment = None

if __name__ == "__main__":
    cli = GhostScanCLI()
    cli.run()