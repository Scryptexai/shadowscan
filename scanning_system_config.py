#!/usr/bin/env python3
"""
Structured Scanning System Configuration
Define the 6-phase scanning methodology with detailed breakdown
"""

import json
from datetime import datetime
from typing import Dict, List, Any

class ScanningSystemConfig:
    """Configuration for the 6-phase structured scanning system"""

    def __init__(self):
        self.system_name = "DEFI_DEX_Structured_Scanner"
        self.version = "1.0.0"
        self.created_at = datetime.now().isoformat()

    def get_phase_definitions(self) -> Dict[str, Any]:
        """Define all 6 phases with detailed breakdown"""
        return {
            "phase_1": {
                "name": "DEFI/DEX Discovery and Collection",
                "description": "Scan and collect new DEFI/DEX websites on emerging blockchains",
                "objectives": [
                    "Identify new/unaudited DEFI protocols",
                    "Check protocol age and maturity",
                    "Categorize by type (DEX, Lending, Yield, etc.)",
                    "Verify blockchain presence and status"
                ],
                "methodology": [
                    "Web scraping of emerging blockchain ecosystems",
                    "API discovery from new chains (Story, Berachain, etc.)",
                    "Social media and community monitoring",
                    "News and announcement tracking"
                ],
                "output": "defi_discovery_database.json",
                "success_criteria": {
                    "minimum_protocols": 50,
                    "minimum_chains": 10,
                    "age_filter": "< 6 months for new protocols"
                },
                "tools": [
                    "BeautifulSoup for web scraping",
                    "Requests for API calls",
                    "Playwright for dynamic content",
                    "Selenium for browser automation"
                ]
            },
            "phase_2": {
                "name": "Database Structuring and Storage",
                "description": "Save discovered DEFI/DEX list in structured JSON database",
                "objectives": [
                    "Create consistent database schema",
                    "Store all discovered protocols systematically",
                    "Ensure data integrity and naming conventions",
                    "Setup proper indexing for fast access"
                ],
                "methodology": [
                    "JSON database design with nested structures",
                    "Protocol categorization by risk level",
                    "Chain-based organization",
                    "Metadata tagging and versioning"
                ],
                "output": "defi_protocol_database.json",
                "success_criteria": {
                    "consistent_schema": True,
                    "data_integrity": 100,
                    "naming_convention": "protocol_chain_type_version"
                },
                "tools": [
                    "JSON with validation",
                    "SQLite for indexing",
                    "Pandas for data manipulation",
                    "Redis for caching"
                ]
            },
            "phase_3": {
                "name": "Contract and Backend Intelligence Gathering",
                "description": "Gather detailed contract and backend technology information for each protocol",
                "objectives": [
                    "Identify all smart contracts (router, swap, bridge, etc.)",
                    "Analyze backend technology stack",
                    "Map contract relationships and dependencies",
                    "Gather API endpoints and service architecture"
                ],
                "methodology": [
                    "Blockchain API exploration (Blockscout, Etherscan)",
                    "Contract ABI and source code analysis",
                    "Backend service enumeration",
                    "Dependency mapping and architectural analysis"
                ],
                "output": "contract_intelligence_database.json",
                "success_criteria": {
                    "contract_coverage": "100% of identified protocols",
                    "backend_discovery": "full stack mapping",
                    "relationship_mapping": "complete dependency graph"
                },
                "tools": [
                    "OWASP ZAP for API testing",
                    "Nmap for service discovery",
                    "Sublist3r for subdomain enumeration",
                    "Wappalyzer for tech stack detection"
                ]
            },
            "phase_4": {
                "name": "Detailed Protocol Documentation",
                "description": "Save comprehensive information for each protocol in separate files",
                "objectives": [
                    "Create individual protocol documentation files",
                    "Store all gathered information systematically",
                    "Maintain consistent naming and structure",
                    "Include all technical details and specifications"
                ],
                "methodology": [
                    "File-based organization by protocol name",
                    "Structured data storage in JSON format",
                    "Version control for information updates",
                    "Cross-reference documentation"
                ],
                "output": "protocol_databases/protocol_name.json",
                "success_criteria": {
                    "file_organization": "one file per protocol",
                    "data_completeness": "100% required fields",
                    "naming_consistency": "strict protocol naming"
                },
                "tools": [
                    "File system organization",
                    "JSON schema validation",
                    "Git for version control",
                    "Documentation automation"
                ]
            },
            "phase_5": {
                "name": "Deep Vulnerability Screening",
                "description": "Screen collected data for real vulnerabilities using deep analysis",
                "objectives": [
                    "Identify non-public vulnerabilities",
                    "Confirm real vs theoretical vulnerabilities",
                    "Deep dive into sensitive information",
                    "Utilize external tools for enhanced detection"
                ],
                "methodology": [
                    "Confirmed vulnerability database cross-referencing",
                    "External tool integration for deep analysis",
                    "Manual verification of findings",
                    "Exploit pattern matching"
                ],
                "output": "vulnerability_screening_database.json",
                "success_criteria": {
                    "confirmed_vulnerabilities": "verified real issues",
                    "false_positive_rate": "< 5%",
                    "exploit_confidence": "high confidence"
                },
                "tools": [
                    "Burp Suite for proxy testing",
                    "Metasploit for exploit validation",
                    "Custom exploit development tools",
                    "Vulnerability correlation systems"
                ]
            },
            "phase_6": {
                "name": "Confirmed Vulnerability Storage",
                "description": "Save confirmed vulnerabilities with attack vectors",
                "objectives": [
                    "Store confirmed vulnerabilities with details",
                    "Map appropriate attack vectors",
                    "Eliminate guessing with confirmed data",
                    "Create actionable intelligence"
                ],
                "methodology": [
                    "Vulnerability classification and categorization",
                    "Attack vector mapping and prioritization",
                    "Exploit development guidance",
                    "Continuous monitoring and updates"
                ],
                "output": "confirmed_vulnerabilities_database.json",
                "success_criteria": {
                    "confirmed_data": "100% verified",
                    "attack_mapping": "detailed exploit vectors",
                    "actionable_intelligence": "ready for execution"
                },
                "tools": [
                    "Vulnerability management systems",
                    "Exploit development frameworks",
                    "Attack surface mapping tools",
                    "Intelligence correlation systems"
                ]
            }
        }

    def get_emerging_blockchains(self) -> List[Dict[str, Any]]:
        """Define target emerging blockchains"""
        return [
            {
                "chain_name": "story_protocol",
                "chain_id": 1514,
                "rpc_url": "https://story-rpc.publicnode.com",
                "description": "Narrative-based DEFI ecosystem",
                "risk_level": "HIGH",
                "maturity": "NEW",
                "keywords": ["narrator", "story", "creative", "nft", "royalty", "storydex"]
            },
            {
                "chain_name": "berachain",
                "chain_id": 80085,
                "rpc_url": "https://bera.rpc.publicnode.com",
                "description": "Binance ecosystem with Hubble consensus",
                "risk_level": "CRITICAL",
                "maturity": "EMERGING",
                "keywords": ["bex", "hubble", "liquidity", "farm", "swap", "bera_swap"]
            },
            {
                "chain_name": "shiden",
                "chain_id": 336,
                "rpc_url": "https://rpc.shiden.astar.io",
                "description": "Acala ecosystem on Kusama",
                "risk_level": "HIGH",
                "maturity": "EMERGING",
                "keywords": ["acala", "shiden", "liquid", "swap", "shdex", "acala_router"]
            },
            {
                "chain_name": "karura",
                "chain_id": 686,
                "rpc_url": "https://karura-rpc.aca-staging.network",
                "description": "Kusama DeFi hub",
                "risk_level": "MEDIUM",
                "maturity": "EMERGING",
                "keywords": ["karura", "koin", "swap", "liquid", "staking", "karura_dex"]
            },
            {
                "chain_name": "moonbeam",
                "chain_id": 1284,
                "rpc_url": "https://moonbeam.public-rpc.com",
                "description": "EVM-compatible Polkadot",
                "risk_level": "MEDIUM",
                "maturity": "GROWING",
                "keywords": ["moonswap", "beamswap", "solarbeam", "parallel", "moonriver"]
            },
            {
                "chain_name": "klaytn",
                "chain_id": 8217,
                "rpc_url": "https://api.klaytnrpc.com",
                "description": "Ethereum-compatible blockchain",
                "risk_level": "MEDIUM",
                "maturity": "GROWING",
                "keywords": ["klip", "klayswap", "baobab", "cypress", "klay_dex"]
            },
            {
                "chain_name": "velas",
                "chain_id": 106,
                "rpc_url": "https://evm-rpc.velas.com",
                "description": "High-performance EVM chain",
                "risk_level": "MEDIUM",
                "maturity": "GROWING",
                "keywords": ["velaswap", "swap", "liquid", "stake", "velas_dex"]
            },
            {
                "chain_name": "bifrost",
                "chain_id": 2047,
                "rpc_url": "https://bifrost-rpc.publicnode.com",
                "description": "Polkadot liquid staking",
                "risk_level": "HIGH",
                "maturity": "EMERGING",
                "keywords": ["bifrost", "liquid", "staking", "swap", "nft", "liquid_stake"]
            },
            {
                "chain_name": "astar",
                "chain_id": 60805,
                "rpc_url": "https://astar.public-rpc.com",
                "description": "Smart Contract chain on Polkadot",
                "risk_level": "MEDIUM",
                "maturity": "GROWING",
                "keywords": ["shiden", "astar", "swap", "nft", "defi", "astar_dex"]
            },
            {
                "chain_name": "tomochain",
                "chain_id": 88,
                "rpc_url": "https://mainnet.tomochain.com",
                "description": "EVM-compatible blockchain",
                "risk_level": "LOW",
                "maturity": "ESTABLISHING",
                "keywords": ["tomo", "swap", "dex", "tomodex", "liquid", "tomo_swap"]
            }
        ]

    def get_database_schemas(self) -> Dict[str, Any]:
        """Define database schemas for each phase"""
        return {
            "defi_discovery_database": {
                "version": "1.0.0",
                "description": "Phase 1: DEFI/DEX discovery results",
                "structure": {
                    "discovery_metadata": {
                        "scan_date": "string",
                        "scan_tool": "string",
                        "total_protocols": "integer",
                        "chains_scanned": "array"
                    },
                    "protocols": [
                        {
                            "protocol_name": "string",
                            "website": "string",
                            "blockchain": "string",
                            "chain_id": "integer",
                            "category": "string",
                            "maturity_level": "string",
                            "age_months": "integer",
                            "risk_level": "string",
                            "keywords": "array",
                            "social_media": "object",
                            "discovery_date": "string",
                            "last_updated": "string"
                        }
                    ]
                }
            },
            "defi_protocol_database": {
                "version": "1.0.0",
                "description": "Phase 2: Structured protocol database",
                "structure": {
                    "database_metadata": {
                        "created_date": "string",
                        "total_protocols": "integer",
                        "schema_version": "string"
                    },
                    "protocols": [
                        {
                            "protocol_id": "string",
                            "protocol_name": "string",
                            "display_name": "string",
                            "blockchain": "string",
                            "chain_id": "integer",
                            "category": "string",
                            "subcategory": "string",
                            "risk_level": "string",
                            "maturity_level": "string",
                            "official_website": "string",
                            "documentation": "string",
                            "github": "string",
                            "social_links": "object",
                            "contract_addresses": "object",
                            "api_endpoints": "array",
                            "technologies": "array",
                            "created_at": "string",
                            "updated_at": "string"
                        }
                    ]
                }
            },
            "contract_intelligence_database": {
                "version": "1.0.0",
                "description": "Phase 3: Contract and backend intelligence",
                "structure": {
                    "intelligence_metadata": {
                        "collection_date": "string",
                        "collection_tool": "string",
                        "total_contracts": "integer"
                    },
                    "contracts": [
                        {
                            "contract_id": "string",
                            "protocol_name": "string",
                            "contract_name": "string",
                            "contract_address": "string",
                            "contract_type": "string",
                            "abi": "array",
                            "source_code": "string",
                            "bytecode": "string",
                            "function_signatures": "array",
                            "event_signatures": "array",
                            "backend_technology": "object",
                            "api_endpoints": "array",
                            "dependencies": "array",
                            "related_contracts": "array",
                            "audit_status": "string",
                            "security_score": "integer",
                            "created_at": "string",
                            "updated_at": "string"
                        }
                    ]
                }
            },
            "protocol_databases": {
                "version": "1.0.0",
                "description": "Phase 4: Individual protocol files",
                "file_structure": "protocol_name_chain_type_version.json",
                "content": {
                    "protocol_info": "object",
                    "contract_data": "object",
                    "backend_architecture": "object",
                    "security_assessment": "object",
                    "attack_surface": "object",
                    "related_protocols": "array",
                    "metadata": "object"
                }
            },
            "vulnerability_screening_database": {
                "version": "1.0.0",
                "description": "Phase 5: Vulnerability screening results",
                "structure": {
                    "screening_metadata": {
                        "screening_date": "string",
                        "screening_tool": "string",
                        "total_findings": "integer"
                    },
                    "findings": [
                        {
                            "finding_id": "string",
                            "protocol_name": "string",
                            "component": "string",
                            "vulnerability_type": "string",
                            "severity": "string",
                            "description": "string",
                            "cvss_score": "float",
                            "confirmed": "boolean",
                            "confidence_level": "string",
                            "evidence": "array",
                            "external_tools_used": "array",
                            "manual_verification": "string",
                            "potential_impact": "string",
                            "created_at": "string",
                            "updated_at": "string"
                        }
                    ]
                }
            },
            "confirmed_vulnerabilities_database": {
                "version": "1.0.0",
                "description": "Phase 6: Confirmed vulnerabilities with attack vectors",
                "structure": {
                    "confirmed_metadata": {
                        "confirmation_date": "string",
                        "confirmation_method": "string",
                        "total_confirmed": "integer"
                    },
                    "confirmed_vulnerabilities": [
                        {
                            "vulnerability_id": "string",
                            "protocol_name": "string",
                            "component": "string",
                            "vulnerability_type": "string",
                            "severity": "string",
                            "cvss_score": "float",
                            "confirmed_date": "string",
                            "confirmed_by": "string",
                            "attack_vector": "object",
                            "exploit_steps": "array",
                            "required_tools": "array",
                            "success_probability": "float",
                            "potential_profit": "string",
                            "risk_assessment": "object",
                            "mitigation": "string",
                            "references": "array",
                            "created_at": "string",
                            "updated_at": "string"
                        }
                    ]
                }
            }
        }

    def save_configuration(self):
        """Save the complete configuration"""
        config = {
            "system_config": {
                "name": self.system_name,
                "version": self.version,
                "created_at": self.created_at
            },
            "phase_definitions": self.get_phase_definitions(),
            "emerging_blockchains": self.get_emerging_blockchains(),
            "database_schemas": self.get_database_schemas()
        }

        with open('structured_scanning_config.json', 'w') as f:
            json.dump(config, f, indent=2)

        print(f"✅ Configuration saved to structured_scanning_config.json")
        print(f"📊 Total phases: {len(self.get_phase_definitions())}")
        print(f"🌐 Target blockchains: {len(self.get_emerging_blockchains())}")

if __name__ == "__main__":
    config = ScanningSystemConfig()
    config.save_configuration()