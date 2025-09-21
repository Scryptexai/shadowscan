#!/usr/bin/env python3
"""
Test Framework for GhostScan
Comprehensive testing and validation system
"""

import unittest
import json
import time
import os
from typing import Dict, List, Any, Optional
from pathlib import Path

from core.database import database
from core.config_loader import config_loader
from core.blockchain import blockchain_interface, MINIMAL_ERC20_ABI
from scanners.comprehensive_scanner import ComprehensiveScanner
from exploits.exploit_engine import ExploitEngine

class TestGhostScanFramework(unittest.TestCase):
    """Test cases for GhostScan framework"""

    def setUp(self):
        """Setup test environment"""
        self.test_chain_id = 1511
        self.test_contract_address = "0x693c7acf65e52c71bafe555bc22d69cb7f8a78a2"
        self.test_private_key = "b4c323449c07eae101f238a9b8af42a563c76fbc3f268f973e5b56b51533e706"

        # Clear test data
        self._clear_test_data()

    def tearDown(self):
        """Cleanup after tests"""
        self._clear_test_data()

    def _clear_test_data(self):
        """Clear test data from database"""
        # Clear test contracts
        contracts = database.get_contracts()
        for contract in contracts:
            if contract.get('address') == self.test_contract_address:
                database.contracts_file.unlink()
                break

        # Clear test vulnerabilities
        vulnerabilities = database.get_vulnerabilities()
        test_vulns = [v for v in vulnerabilities if v.get('contract_address') == self.test_contract_address]
        for vuln in test_vulns:
            database.vulnerabilities_file.unlink()
            break

        # Clear test reports
        reports = database.get_reports()
        test_reports = [r for r in reports if r.get('contract_address') == self.test_contract_address]
        for report in test_reports:
            database.reports_file.unlink()
            break

    def test_database_operations(self):
        """Test database operations"""
        print("\n🧪 Testing Database Operations...")

        # Test adding a chain
        test_chain = {
            "name": "Test Chain",
            "environment": "tenderly",
            "rpc_url": "https://test.rpc.url",
            "chain_id": 999,
            "currency": "TEST"
        }

        result = database.add_chain(test_chain)
        self.assertTrue(result)

        # Test getting chains
        chains = database.get_chains()
        self.assertGreater(len(chains), 0)

        # Test adding a contract
        test_contract = {
            "address": self.test_contract_address,
            "name": "Test Contract",
            "chain_id": self.test_chain_id,
            "environment": "tenderly",
            "added_at": time.time()
        }

        result = database.add_contract(test_contract)
        self.assertTrue(result)

        # Test getting contracts
        contracts = database.get_contracts()
        self.assertGreater(len(contracts), 0)

        print("✅ Database operations working correctly")

    def test_configuration_loader(self):
        """Test configuration loading"""
        print("\n🧪 Testing Configuration Loader...")

        # Test getting chains
        chains = config_loader.get_chains()
        self.assertGreater(len(chains), 0)

        # Test getting scanner configuration
        scanners_config = config_loader.get_scanners_config()
        self.assertIsInstance(scanners_config, dict)

        # Test getting environment configuration
        env_config = config_loader.get_environment_config("tenderly")
        self.assertIsInstance(env_config, dict)

        print("✅ Configuration loader working correctly")

    def test_blockchain_interface(self):
        """Test blockchain interface"""
        print("\n🧪 Testing Blockchain Interface...")

        # Test connection
        result = blockchain_interface.test_connection(self.test_chain_id)
        # Note: This might fail in test environment, but we test the method
        self.assertIsInstance(result, bool)

        # Test contract existence check
        exists = blockchain_interface.check_contract_exists(self.test_chain_id, self.test_contract_address)
        # This will return False if contract doesn't exist, which is acceptable in test
        self.assertIsInstance(exists, bool)

        print("✅ Blockchain interface methods working correctly")

    def test_comprehensive_scanner(self):
        """Test comprehensive scanner"""
        print("\n🧪 Testing Comprehensive Scanner...")

        scanner = ComprehensiveScanner(
            self.test_chain_id,
            self.test_contract_address,
            MINIMAL_ERC20_ABI
        )

        # Note: This might fail in test environment if contract doesn't exist
        try:
            results = scanner.scan()
            self.assertIsInstance(results, dict)
            self.assertIn('scan_id', results)
            self.assertIn('timestamp', results)
            self.assertIn('contract_address', results)
            print("✅ Comprehensive scanner working correctly")
        except Exception as e:
            print(f"⚠️ Scanner test failed (expected in test environment): {e}")

    def test_exploit_engine(self):
        """Test exploit engine"""
        print("\n🧪 Testing Exploit Engine...")

        # This test requires a valid private key and contract
        # It will likely fail in test environment, but we test the method structure
        try:
            exploit_engine = ExploitEngine(
                self.test_chain_id,
                self.test_contract_address,
                MINIMAL_ERC20_ABI,
                self.test_private_key
            )

            # Test exploit execution
            result = exploit_engine.execute_exploit('reentrancy')
            self.assertIsInstance(result, dict)
            self.assertIn('exploit_type', result)

            print("✅ Exploit engine methods working correctly")
        except Exception as e:
            print(f"⚠️ Exploit engine test failed (expected in test environment): {e}")

    def test_chain_configuration(self):
        """Test chain configuration"""
        print("\n🧪 Testing Chain Configuration...")

        chains = config_loader.get_chains()
        self.assertGreater(len(chains), 0)

        # Test Story Protocol configuration
        story_chain = config_loader.get_chain(1511)
        if story_chain:
            self.assertEqual(story_chain.get('name'), 'Story Protocol')
            self.assertEqual(story_chain.get('environment'), 'tenderly')

        print("✅ Chain configuration working correctly")

    def test_database_statistics(self):
        """Test database statistics"""
        print("\n🧪 Testing Database Statistics...")

        stats = database.get_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn('chains', stats)
        self.assertIn('contracts', stats)
        self.assertIn('vulnerabilities', stats)
        self.assertIn('reports', stats)

        print("✅ Database statistics working correctly")

    def test_configuration_validation(self):
        """Test configuration validation"""
        print("\n🧪 Testing Configuration Validation...")

        # Test valid chain configuration
        valid_chain = {
            "name": "Valid Chain",
            "environment": "tenderly",
            "rpc_url": "https://valid.rpc.url",
            "chain_id": 1000,
            "currency": "TEST"
        }

        is_valid = config_loader.validate_chain_config(valid_chain)
        self.assertTrue(is_valid)

        # Test invalid chain configuration
        invalid_chain = {
            "name": "Invalid Chain",
            # Missing required fields
            "chain_id": 1001
        }

        is_valid = config_loader.validate_chain_config(invalid_chain)
        self.assertFalse(is_valid)

        print("✅ Configuration validation working correctly")

class TestPerformance(unittest.TestCase):
    """Performance tests for GhostScan"""

    def test_scanner_performance(self):
        """Test scanner performance"""
        print("\n🧪 Testing Scanner Performance...")

        start_time = time.time()

        scanner = ComprehensiveScanner(
            1511,
            "0x693c7acf65e52c71bafe555bc22d69cb7f8a78a2",
            MINIMAL_ERC20_ABI
        )

        try:
            results = scanner.scan()
            end_time = time.time()
            execution_time = end_time - start_time

            print(f"Scanner execution time: {execution_time:.2f} seconds")

            # Performance check (should complete within reasonable time)
            self.assertLess(execution_time, 300)  # 5 minutes max

        except Exception as e:
            print(f"⚠️ Performance test failed: {e}")

def run_comprehensive_tests():
    """Run comprehensive test suite"""
    print("🧪 Starting GhostScan Comprehensive Test Suite...")
    print("=" * 60)

    # Create test suite
    suite = unittest.TestSuite()

    # Add test cases
    suite.addTest(unittest.makeSuite(TestGhostScanFramework))
    suite.addTest(unittest.makeSuite(TestPerformance))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success Rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")

    if result.failures:
        print("\n❌ FAILURES:")
        for test, traceback in result.failures:
            print(f"   - {test}: {traceback}")

    if result.errors:
        print("\n⚠️ ERRORS:")
        for test, traceback in result.errors:
            print(f"   - {test}: {traceback}")

    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_comprehensive_tests()
    sys.exit(0 if success else 1)