#!/usr/bin/env python3
"""
Setup script for ShadowScan Security Platform
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    requirements = requirements_path.read_text().strip().split('\n')

setup(
    name="shadowscan",
    version="3.0.0",
    author="ShadowScan Security Team",
    author_email="security@shadowscan.dev",
    description="Advanced Blockchain Security Scanning Platform with Attack Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shadowscan/shadowscan",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-asyncio>=0.21",
            "black>=22.0",
            "flake8>=5.0",
            "mypy>=1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "shadowscan=shadowscan.cli.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "shadowscan": [
            "config/*.json",
            "contracts/**/*.sol",
            "templates/**/*",
        ],
    },
    keywords="blockchain security smart-contract vulnerability-scanning attack-framework",
    project_urls={
        "Bug Reports": "https://github.com/shadowscan/shadowscan/issues",
        "Source": "https://github.com/shadowscan/shadowscan",
        "Documentation": "https://docs.shadowscan.dev",
    },
)