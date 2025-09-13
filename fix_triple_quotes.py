#!/usr/bin/env python3
"""
Fix triple quotes in tx_fetcher.py
"""

import re

# Read the file
with open('shadowscan/collectors/evm/tx_fetcher.py', 'r') as f:
    content = f.read()

# Replace problematic triple quotes with single quotes
# This is a temporary fix to get the tests running
content = re.sub(r'"""([^"]*?)"""', r"'\1'", content)

# Write back
with open('shadowscan/collectors/evm/tx_fetcher.py', 'w') as f:
    f.write(content)

print("Fixed triple quotes in tx_fetcher.py")