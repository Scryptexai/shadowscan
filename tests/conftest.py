"""
Pytest configuration for ShadowScan tests.
"""

import pytest
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

@pytest.fixture
def mock_web3():
    """Mock Web3 instance for testing."""
    from unittest.mock import Mock
    from web3 import Web3
    
    mock_web3 = Mock(spec=Web3)
    mock_web3.is_connected.return_value = True
    mock_web3.eth.block_number = 15000
    return mock_web3

@pytest.fixture
def sample_contract_address():
    """Sample contract address for testing."""
    return "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"

@pytest.fixture
def sample_target_address():
    """Sample target address for testing."""
    return "0x1234567890123456789012345678901234567890"

@pytest.fixture
def temp_directory():
    """Temporary directory for file-based tests."""
    import tempfile
    import shutil
    
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    
    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)