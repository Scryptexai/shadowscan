"""
ShadowScan - Universal Cyber Attack Test Engine
"""

import sys
import warnings
from pathlib import Path

__version__ = "1.0.0"
__author__ = "ShadowScan Team"
__email__ = "team@shadowscan.dev"
__license__ = "MIT"

# Minimum Python version check
MINIMUM_PYTHON_VERSION = (3, 8)

if sys.version_info < MINIMUM_PYTHON_VERSION:
    raise RuntimeError(
        f"ShadowScan requires Python {'.'.join(map(str, MINIMUM_PYTHON_VERSION))} "
        f"or higher. You are using Python {'.'.join(map(str, sys.version_info[:2]))}."
    )

def get_version():
    return __version__

# Initialize logging
import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())
