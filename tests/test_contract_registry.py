"""
Unit tests for ContractRegistry functionality.
Tests thread-safe operations, persistence, and session management.
"""

import pytest
import tempfile
import shutil
import json
import threading
import time
from pathlib import Path
from unittest.mock import Mock, patch

from shadowscan.data.contracts import ContractRegistry, ContractInfo, TargetSession


class TestContractRegistry:
    """Test suite for ContractRegistry functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.registry = ContractRegistry(data_dir=self.temp_dir)
    
    def teardown_method(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization(self):
        """Test registry initialization creates data directory."""
        assert self.registry.data_dir.exists()
        assert len(self.registry._contracts) == 0
        assert len(self.registry._sessions) == 0
        # Files are created only when data is saved
        # assert self.registry.contracts_file.exists()
        # assert self.registry.sessions_file.exists()
    
    def test_create_session(self):
        """Test session creation."""
        target = "0x1234567890123456789012345678901234567890"
        chain = "ethereum"
        session_id = "test-session-123"
        
        session = self.registry.create_session(target, chain, session_id)
        
        assert session.target == target
        assert session.chain == chain
        assert session.session_id == session_id
        assert session.status == "active"
        assert len(session.discovered_contracts) == 0
        
        # Verify session is stored
        assert session_id in self.registry._sessions
        assert f"{target}:{chain}" in self.registry._target_index
    
    def test_add_contract(self):
        """Test adding contracts to registry."""
        target = "0x1234567890123456789012345678901234567890"
        chain = "ethereum"
        address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        session_id = "test-session-123"
        
        # Create session first
        self.registry.create_session(target, chain, session_id)
        
        # Add contract
        contract = self.registry.add_contract(target, chain, address, "token", {"symbol": "TEST"})
        
        assert contract.address == address.lower()
        assert contract.chain == chain
        assert contract.role == "token"
        assert contract.metadata["symbol"] == "TEST"
        
        # Verify contract is stored
        key = f"{chain}:{address.lower()}"
        assert key in self.registry._contracts
        
        # Verify contract is added to session
        session = self.registry._sessions[session_id]
        assert address.lower() in session.discovered_contracts
    
    def test_add_duplicate_contract(self):
        """Test adding duplicate contract updates metadata."""
        target = "0x1234567890123456789012345678901234567890"
        chain = "ethereum"
        address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        session_id = "test-session-123"
        
        # Create session and add initial contract
        self.registry.create_session(target, chain, session_id)
        self.registry.add_contract(target, chain, address, "token", {"symbol": "TEST"})
        
        # Add same contract with updated metadata
        updated_contract = self.registry.add_contract(target, chain, address, "dex", {"decimals": 18})
        
        # Verify role was updated and metadata merged
        assert updated_contract.role == "dex"
        assert updated_contract.metadata["symbol"] == "TEST"
        assert updated_contract.metadata["decimals"] == 18
        
        # Should still be only one contract entry
        assert len(self.registry._contracts) == 1
    
    def test_get_contracts_for_target(self):
        """Test retrieving contracts for a specific target."""
        target = "0x1234567890123456789012345678901234567890"
        chain = "ethereum"
        session_id = "test-session-123"
        
        # Create session and add multiple contracts
        self.registry.create_session(target, chain, session_id)
        self.registry.add_contract(target, chain, "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd", "token")
        self.registry.add_contract(target, chain, "0x1111111111111111111111111111111111111111", "dex")
        
        contracts = self.registry.get_contracts_for_target(target, chain)
        
        assert len(contracts) == 2
        roles = [c.role for c in contracts]
        assert "token" in roles
        assert "dex" in roles
    
    def test_load_existing_session(self):
        """Test loading existing session."""
        target = "0x1234567890123456789012345678901234567890"
        chain = "ethereum"
        session_id = "test-session-123"
        
        # Create session
        original_session = self.registry.create_session(target, chain, session_id)
        
        # Create new registry instance (should load existing data)
        new_registry = ContractRegistry(data_dir=self.temp_dir)
        loaded_session = new_registry.load(target, chain)
        
        assert loaded_session is not None
        assert loaded_session.target == target
        assert loaded_session.chain == chain
        assert loaded_session.session_id == session_id
    
    def test_update_session_status(self):
        """Test updating session status and discovered contracts."""
        target = "0x1234567890123456789012345678901234567890"
        chain = "ethereum"
        session_id = "test-session-123"
        
        # Create session
        self.registry.create_session(target, chain, session_id)
        
        # Update session
        discovered_contracts = {"0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"}
        updated_session = self.registry.update_session(
            session_id, "completed", discovered_contracts
        )
        
        assert updated_session.status == "completed"
        assert updated_session.discovered_contracts == discovered_contracts
        assert updated_session.session_end is not None
    
    def test_persistence(self):
        """Test data persistence across registry instances."""
        target = "0x1234567890123456789012345678901234567890"
        chain = "ethereum"
        address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        session_id = "test-session-123"
        
        # Create session and add contract
        self.registry.create_session(target, chain, session_id)
        self.registry.add_contract(target, chain, address, "token", {"symbol": "TEST"})
        
        # Create new registry instance
        new_registry = ContractRegistry(data_dir=self.temp_dir)
        
        # Verify data was persisted
        contracts = new_registry.get_contracts_for_target(target, chain)
        assert len(contracts) == 1
        assert contracts[0].metadata["symbol"] == "TEST"
        
        session = new_registry.load(target, chain)
        assert session is not None
        assert session.session_id == session_id
    
    def test_find_contracts_by_role(self):
        """Test finding contracts by role."""
        target = "0x1234567890123456789012345678901234567890"
        chain = "ethereum"
        session_id = "test-session-123"
        
        # Create session and add contracts with different roles
        self.registry.create_session(target, chain, session_id)
        self.registry.add_contract(target, chain, "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd", "token")
        self.registry.add_contract(target, chain, "0x1111111111111111111111111111111111111111", "token")
        self.registry.add_contract(target, chain, "0x2222222222222222222222222222222222222222", "dex")
        
        token_contracts = self.registry.find_contracts_by_role(chain, "token")
        dex_contracts = self.registry.find_contracts_by_role(chain, "dex")
        
        assert len(token_contracts) == 2
        assert len(dex_contracts) == 1
    
    def test_get_statistics(self):
        """Test getting registry statistics."""
        target = "0x1234567890123456789012345678901234567890"
        chain = "ethereum"
        session_id = "test-session-123"
        
        # Create session and add contracts
        self.registry.create_session(target, chain, session_id)
        self.registry.add_contract(target, chain, "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd", "token")
        self.registry.add_contract(target, chain, "0x1111111111111111111111111111111111111111", "dex")
        
        stats = self.registry.get_statistics()
        
        assert stats["total_contracts"] == 2
        assert stats["total_sessions"] == 1
        assert stats["contracts_by_chain"]["ethereum"] == 2
        assert stats["contracts_by_role"]["token"] == 1
        assert stats["contracts_by_role"]["dex"] == 1
        assert stats["active_sessions"] == 1
    
    def test_cleanup_old_sessions(self):
        """Test cleaning up old sessions."""
        target = "0x1234567890123456789012345678901234567890"
        chain = "ethereum"
        
        # Create old session (simulate by setting end time in past)
        old_session_id = "old-session"
        self.registry.create_session(target, chain, old_session_id)
        old_session = self.registry._sessions[old_session_id]
        old_session.session_end = "2020-01-01T00:00:00"  # Old date
        
        # Create recent session
        recent_session_id = "recent-session"
        self.registry.create_session(target, chain, recent_session_id)
        
        # Cleanup old sessions (older than 1 day)
        self.registry.cleanup_old_sessions(days=1)
        
        # Verify only recent session remains
        assert len(self.registry._sessions) == 1
        assert recent_session_id in self.registry._sessions
        assert old_session_id not in self.registry._sessions


class TestContractRegistryThreading:
    """Test thread safety of ContractRegistry operations."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.registry = ContractRegistry(data_dir=self.temp_dir)
    
    def teardown_method(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_concurrent_contract_addition(self):
        """Test concurrent contract addition doesn't cause conflicts."""
        target = "0x1234567890123456789012345678901234567890"
        chain = "ethereum"
        session_id = "test-session"
        
        # Create session
        self.registry.create_session(target, chain, session_id)
        
        def add_contracts(start_idx, count):
            """Add contracts in a separate thread."""
            for i in range(start_idx, start_idx + count):
                address = f"0x{'a' * (40 - len(str(i)))}{i}"
                self.registry.add_contract(target, chain, address, "token")
        
        # Create multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=add_contracts, args=(i * 10, 10))
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all contracts were added
        contracts = self.registry.get_contracts_for_target(target, chain)
        assert len(contracts) == 50  # 5 threads * 10 contracts each
    
    def test_concurrent_session_creation(self):
        """Test concurrent session creation."""
        chain = "ethereum"
        
        def create_session(target_idx):
            """Create session in separate thread."""
            target = f"0x{'1' * 39}{target_idx}"
            session_id = f"session-{target_idx}"
            self.registry.create_session(target, chain, session_id)
        
        # Create multiple threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=create_session, args=(i,))
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all sessions were created
        assert len(self.registry._sessions) == 10
        assert len(self.registry._target_index) == 10
    
    @patch('shadowscan.data.contracts.time.sleep')
    def test_file_locking_contention(self, mock_sleep):
        """Test file locking handles contention gracefully."""
        target = "0x1234567890123456789012345678901234567890"
        chain = "ethereum"
        session_id = "test-session"
        
        # Simulate lock file always existing (contention)
        self.registry.lock_file.touch()
        
        # This should timeout gracefully
        with pytest.raises(RuntimeError, match="Failed to acquire registry lock"):
            self.registry.create_session(target, chain, session_id)
        
        # Verify sleep was called (backoff behavior)
        mock_sleep.assert_called()


class TestContractInfo:
    """Test ContractInfo dataclass."""
    
    def test_contract_info_creation(self):
        """Test ContractInfo creation with defaults."""
        contract = ContractInfo(
            address="0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            chain="ethereum"
        )
        
        assert contract.address == "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        assert contract.chain == "ethereum"
        assert contract.role == "unknown"
        assert contract.metadata == {}
        assert contract.first_seen is not None
        assert contract.last_updated is not None
    
    def test_contract_info_serialization(self):
        """Test ContractInfo serialization."""
        contract = ContractInfo(
            address="0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            chain="ethereum",
            role="token",
            metadata={"symbol": "TEST", "decimals": 18}
        )
        
        # Test to_dict conversion
        contract_dict = contract.to_dict()
        assert contract_dict["address"] == contract.address
        assert contract_dict["chain"] == contract.chain
        assert contract_dict["role"] == contract.role
        assert contract_dict["metadata"]["symbol"] == "TEST"
        
        # Test from_dict conversion
        recreated = ContractInfo.from_dict(contract_dict)
        assert recreated.address == contract.address
        assert recreated.chain == contract.chain
        assert recreated.role == contract.role
        assert recreated.metadata["symbol"] == "TEST"


class TestTargetSession:
    """Test TargetSession dataclass."""
    
    def test_target_session_creation(self):
        """Test TargetSession creation with defaults."""
        session = TargetSession(
            target="0x1234567890123456789012345678901234567890",
            chain="ethereum",
            session_id="test-session",
            discovered_contracts=set()
        )
        
        assert session.target == "0x1234567890123456789012345678901234567890"
        assert session.chain == "ethereum"
        assert session.session_id == "test-session"
        assert session.status == "active"
        assert len(session.discovered_contracts) == 0
        assert session.session_start is not None
    
    def test_target_session_with_list_conversion(self):
        """Test TargetSession converts list to set for discovered_contracts."""
        session = TargetSession(
            target="0x1234567890123456789012345678901234567890",
            chain="ethereum",
            session_id="test-session",
            discovered_contracts=["0xabc", "0xdef"]  # List instead of set
        )
        
        assert isinstance(session.discovered_contracts, set)
        assert len(session.discovered_contracts) == 2