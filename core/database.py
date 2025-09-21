#!/usr/bin/env python3
"""
Database Management System for GhostScan
JSON-based persistent storage for chains, contracts, vulnerabilities, and reports
"""

import json
import os
import time
import threading
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
from pathlib import Path

class GhostScanDatabase:
    """Comprehensive database management for GhostScan framework"""

    def __init__(self, db_path: str = "database"):
        self.db_path = Path(db_path)
        self.db_path.mkdir(exist_ok=True)

        # Database files
        self.chains_file = self.db_path / "chains.json"
        self.contracts_file = self.db_path / "contracts.json"
        self.vulnerabilities_file = self.db_path / "vulnerabilities.json"
        self.reports_file = self.db_path / "reports.json"
        self.config_file = self.db_path / "config.json"

        # Initialize database files
        self._initialize_database()

        # Thread safety
        self._lock = threading.Lock()

        # Cache system
        self._cache = {}
        self._cache_ttl = {}
        self.cache_timeout = 300  # 5 minutes

    def _initialize_database(self):
        """Initialize database files with default structure"""
        default_structure = {
            "chains": {"chains": [], "last_updated": time.time()},
            "contracts": {"contracts": [], "last_updated": time.time()},
            "vulnerabilities": {"vulnerabilities": [], "last_updated": time.time()},
            "reports": {"reports": [], "last_updated": time.time()},
            "config": {"version": "1.0", "last_updated": time.time()}
        }

        for filename, default_data in default_structure.items():
            file_path = getattr(self, f"{filename}_file")
            if not file_path.exists():
                with open(file_path, 'w') as f:
                    json.dump(default_data, f, indent=2)

    def _load_data(self, file_path: Path, cache_key: str = None) -> Dict[str, Any]:
        """Load data from JSON file with caching"""
        try:
            # Check cache first
            if cache_key and cache_key in self._cache:
                if time.time() - self._cache_ttl.get(cache_key, 0) < self.cache_timeout:
                    return self._cache[cache_key]

            with open(file_path, 'r') as f:
                data = json.load(f)

            # Update cache
            if cache_key:
                self._cache[cache_key] = data
                self._cache_ttl[cache_key] = time.time()

            return data

        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"⚠️ Error loading {file_path}: {e}")
            return {"last_updated": time.time()}

    def _save_data(self, file_path: Path, data: Dict[str, Any], cache_key: str = None):
        """Save data to JSON file and update cache"""
        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)

            # Update cache
            if cache_key:
                self._cache[cache_key] = data
                self._cache_ttl[cache_key] = time.time()

            return True

        except Exception as e:
            print(f"⚠️ Error saving {file_path}: {e}")
            return False

    def clear_cache(self):
        """Clear all cached data"""
        self._cache.clear()
        self._cache_ttl.clear()

    # Chain Management
    def add_chain(self, chain_data: Dict[str, Any]) -> bool:
        """Add a new blockchain configuration"""
        with self._lock:
            data = self._load_data(self.chains_file, "chains")
            data["chains"].append(chain_data)
            data["last_updated"] = time.time()
            return self._save_data(self.chains_file, data, "chains")

    def get_chains(self, environment: str = None) -> List[Dict[str, Any]]:
        """Get all chains, optionally filtered by environment"""
        with self._lock:
            data = self._load_data(self.chains_file, "chains")
            chains = data.get("chains", [])

            if environment:
                chains = [chain for chain in chains if chain.get("environment") == environment]

            return chains

    def get_chain(self, chain_id: Union[str, int]) -> Optional[Dict[str, Any]]:
        """Get a specific chain by ID or name"""
        with self._lock:
            data = self._load_data(self.chains_file, "chains")
            chains = data.get("chains", [])

            for chain in chains:
                if chain.get("chain_id") == chain_id or chain.get("name") == chain_id:
                    return chain

            return None

    def update_chain(self, chain_id: Union[str, int], updated_data: Dict[str, Any]) -> bool:
        """Update an existing chain configuration"""
        with self._lock:
            data = self._load_data(self.chains_file, "chains")
            chains = data.get("chains", [])

            for i, chain in enumerate(chains):
                if chain.get("chain_id") == chain_id or chain.get("name") == chain_id:
                    chains[i].update(updated_data)
                    data["last_updated"] = time.time()
                    return self._save_data(self.chains_file, data, "chains")

            return False

    def delete_chain(self, chain_id: Union[str, int]) -> bool:
        """Delete a chain configuration"""
        with self._lock:
            data = self._load_data(self.chains_file, "chains")
            chains = data.get("chains", [])

            original_count = len(chains)
            data["chains"] = [chain for chain in chains
                            if not (chain.get("chain_id") == chain_id or chain.get("name") == chain_id)]

            if len(data["chains"]) < original_count:
                data["last_updated"] = time.time()
                return self._save_data(self.chains_file, data, "chains")

            return False

    # Contract Management
    def add_contract(self, contract_data: Dict[str, Any]) -> bool:
        """Add a new smart contract to scan"""
        with self._lock:
            data = self._load_data(self.contracts_file, "contracts")
            data["contracts"].append(contract_data)
            data["last_updated"] = time.time()
            return self._save_data(self.contracts_file, data, "contracts")

    def get_contracts(self, chain_id: Union[str, int] = None) -> List[Dict[str, Any]]:
        """Get all contracts, optionally filtered by chain"""
        with self._lock:
            data = self._load_data(self.contracts_file, "contracts")
            contracts = data.get("contracts", [])

            if chain_id:
                contracts = [contract for contract in contracts
                           if contract.get("chain_id") == chain_id]

            return contracts

    def get_contract(self, contract_address: str) -> Optional[Dict[str, Any]]:
        """Get a specific contract by address"""
        with self._lock:
            data = self._load_data(self.contracts_file, "contracts")
            contracts = data.get("contracts", [])

            for contract in contracts:
                if contract.get("address").lower() == contract_address.lower():
                    return contract

            return None

    def update_contract(self, contract_address: str, updated_data: Dict[str, Any]) -> bool:
        """Update contract information"""
        with self._lock:
            data = self._load_data(self.contracts_file, "contracts")
            contracts = data.get("contracts", [])

            for i, contract in enumerate(contracts):
                if contract.get("address").lower() == contract_address.lower():
                    contracts[i].update(updated_data)
                    data["last_updated"] = time.time()
                    return self._save_data(self.contracts_file, data, "contracts")

            return False

    # Vulnerability Management
    def add_vulnerability(self, vuln_data: Dict[str, Any]) -> bool:
        """Add a new vulnerability finding"""
        with self._lock:
            data = self._load_data(self.vulnerabilities_file, "vulnerabilities")
            data["vulnerabilities"].append(vuln_data)
            data["last_updated"] = time.time()
            return self._save_data(self.vulnerabilities_file, data, "vulnerabilities")

    def get_vulnerabilities(self, contract_address: str = None, severity: str = None) -> List[Dict[str, Any]]:
        """Get vulnerabilities, optionally filtered"""
        with self._lock:
            data = self._load_data(self.vulnerabilities_file, "vulnerabilities")
            vulnerabilities = data.get("vulnerabilities", [])

            if contract_address:
                vulnerabilities = [vuln for vuln in vulnerabilities
                                if vuln.get("contract_address").lower() == contract_address.lower()]

            if severity:
                vulnerabilities = [vuln for vuln in vulnerabilities
                                if vuln.get("severity") == severity]

            return vulnerabilities

    def get_vulnerability_summary(self) -> Dict[str, Any]:
        """Get vulnerability statistics"""
        with self._lock:
            data = self._load_data(self.vulnerabilities_file, "vulnerabilities")
            vulnerabilities = data.get("vulnerabilities", [])

            summary = {
                "total": len(vulnerabilities),
                "by_severity": {},
                "by_contract": {},
                "by_chain": {},
                "by_exploitability": {}
            }

            for vuln in vulnerabilities:
                # Count by severity
                severity = vuln.get("severity", "UNKNOWN")
                summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

                # Count by contract
                contract = vuln.get("contract_address", "UNKNOWN")
                summary["by_contract"][contract] = summary["by_contract"].get(contract, 0) + 1

                # Count by chain
                chain = vuln.get("chain_id", "UNKNOWN")
                summary["by_chain"][chain] = summary["by_chain"].get(chain, 0) + 1

                # Count by exploitability
                exploitability = vuln.get("exploitable", False)
                key = "exploitable" if exploitability else "not_exploitable"
                summary["by_exploitability"][key] = summary["by_exploitability"].get(key, 0) + 1

            return summary

    # Report Management
    def add_report(self, report_data: Dict[str, Any]) -> bool:
        """Add a new scan report"""
        with self._lock:
            data = self._load_data(self.reports_file, "reports")
            data["reports"].append(report_data)
            data["last_updated"] = time.time()
            return self._save_data(self.reports_file, data, "reports")

    def get_reports(self, contract_address: str = None, scan_type: str = None) -> List[Dict[str, Any]]:
        """Get reports, optionally filtered"""
        with self._lock:
            data = self._load_data(self.reports_file, "reports")
            reports = data.get("reports", [])

            if contract_address:
                reports = [report for report in reports
                          if report.get("contract_address").lower() == contract_address.lower()]

            if scan_type:
                reports = [report for report in reports
                          if report.get("scan_type") == scan_type]

            return reports

    def get_latest_report(self, contract_address: str) -> Optional[Dict[str, Any]]:
        """Get the latest report for a contract"""
        with self._lock:
            data = self._load_data(self.reports_file, "reports")
            reports = data.get("reports", [])

            contract_reports = [report for report in reports
                              if report.get("contract_address").lower() == contract_address.lower()]

            if contract_reports:
                return max(contract_reports, key=lambda x: x.get("timestamp", 0))

            return None

    # Configuration Management
    def get_config(self, key: str = None) -> Dict[str, Any]:
        """Get configuration data"""
        with self._lock:
            data = self._load_data(self.config_file, "config")

            if key:
                return data.get(key, {})

            return data

    def set_config(self, key: str, value: Any) -> bool:
        """Set configuration data"""
        with self._lock:
            data = self._load_data(self.config_file, "config")
            data[key] = value
            data["last_updated"] = time.time()
            return self._save_data(self.config_file, data, "config")

    # Utility Methods
    def export_database(self, export_path: str) -> bool:
        """Export entire database to a file"""
        try:
            export_data = {
                "chains": self._load_data(self.chains_file, "chains"),
                "contracts": self._load_data(self.contracts_file, "contracts"),
                "vulnerabilities": self._load_data(self.vulnerabilities_file, "vulnerabilities"),
                "reports": self._load_data(self.reports_file, "reports"),
                "config": self._load_data(self.config_file, "config"),
                "export_timestamp": time.time()
            }

            with open(export_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)

            return True

        except Exception as e:
            print(f"⚠️ Error exporting database: {e}")
            return False

    def import_database(self, import_path: str) -> bool:
        """Import database from a file"""
        try:
            with open(import_path, 'r') as f:
                import_data = json.load(f)

            # Import each component
            for component, data in import_data.items():
                if component in ["chains", "contracts", "vulnerabilities", "reports", "config"]:
                    file_map = {
                        "chains": self.chains_file,
                        "contracts": self.contracts_file,
                        "vulnerabilities": self.vulnerabilities_file,
                        "reports": self.reports_file,
                        "config": self.config_file
                    }

                    if component in file_map:
                        self._save_data(file_map[component], data, component)

            self.clear_cache()
            return True

        except Exception as e:
            print(f"⚠️ Error importing database: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive database statistics"""
        with self._lock:
            chains_data = self._load_data(self.chains_file, "chains")
            contracts_data = self._load_data(self.contracts_file, "contracts")
            vulnerabilities_data = self._load_data(self.vulnerabilities_file, "vulnerabilities")
            reports_data = self._load_data(self.reports_file, "reports")

            stats = {
                "chains": {
                    "total": len(chains_data.get("chains", [])),
                    "by_environment": {}
                },
                "contracts": {
                    "total": len(contracts_data.get("contracts", [])),
                    "by_chain": {}
                },
                "vulnerabilities": {
                    "total": len(vulnerabilities_data.get("vulnerabilities", [])),
                    "by_severity": {},
                    "by_exploitability": {}
                },
                "reports": {
                    "total": len(reports_data.get("reports", [])),
                    "by_type": {}
                },
                "last_updated": {
                    "chains": chains_data.get("last_updated", 0),
                    "contracts": contracts_data.get("last_updated", 0),
                    "vulnerabilities": vulnerabilities_data.get("last_updated", 0),
                    "reports": reports_data.get("last_updated", 0)
                }
            }

            # Calculate detailed statistics
            for chain in chains_data.get("chains", []):
                env = chain.get("environment", "unknown")
                stats["chains"]["by_environment"][env] = stats["chains"]["by_environment"].get(env, 0) + 1

            for contract in contracts_data.get("contracts", []):
                chain_id = contract.get("chain_id", "unknown")
                stats["contracts"]["by_chain"][chain_id] = stats["contracts"]["by_chain"].get(chain_id, 0) + 1

            for vuln in vulnerabilities_data.get("vulnerabilities", []):
                severity = vuln.get("severity", "unknown")
                stats["vulnerabilities"]["by_severity"][severity] = stats["vulnerabilities"]["by_severity"].get(severity, 0) + 1

                exploitable = vuln.get("exploitable", False)
                key = "exploitable" if exploitable else "not_exploitable"
                stats["vulnerabilities"]["by_exploitability"][key] = stats["vulnerabilities"]["by_exploitability"].get(key, 0) + 1

            for report in reports_data.get("reports", []):
                report_type = report.get("scan_type", "unknown")
                stats["reports"]["by_type"][report_type] = stats["reports"]["by_type"].get(report_type, 0) + 1

            return stats

# Global database instance
database = GhostScanDatabase()

if __name__ == "__main__":
    # Test the database system
    db = GhostScanDatabase()

    # Test adding a chain
    test_chain = {
        "name": "Test Chain",
        "environment": "tenderly",
        "rpc_url": "https://test.rpc.url",
        "chain_id": 999,
        "currency": "TEST"
    }

    if db.add_chain(test_chain):
        print("✅ Chain added successfully")

    # Test adding a contract
    test_contract = {
        "address": "0x1234567890123456789012345678901234567890",
        "name": "Test Contract",
        "chain_id": 999,
        "abi_file": "test_abi.json",
        "source_code": "// Test contract",
        "deployed_at": time.time()
    }

    if db.add_contract(test_contract):
        print("✅ Contract added successfully")

    # Test adding a vulnerability
    test_vuln = {
        "contract_address": "0x1234567890123456789012345678901234567890",
        "chain_id": 999,
        "vulnerability_type": "reentrancy",
        "severity": "HIGH",
        "description": "Test vulnerability",
        "exploitable": True,
        "timestamp": time.time()
    }

    if db.add_vulnerability(test_vuln):
        print("✅ Vulnerability added successfully")

    # Get statistics
    stats = db.get_statistics()
    print(f"\n📊 Database Statistics:")
    print(f"   Chains: {stats['chains']['total']}")
    print(f"   Contracts: {stats['contracts']['total']}")
    print(f"   Vulnerabilities: {stats['vulnerabilities']['total']}")
    print(f"   Reports: {stats['reports']['total']}")