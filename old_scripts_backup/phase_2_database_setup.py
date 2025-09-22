#!/usr/bin/env python3
"""
Phase 2: Database Structuring and Storage
Setup structured JSON database for discovered DEFI/DEX protocols
"""

import json
import os
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DEFIDatabaseManager:
    """Manages the structured DEFI/DEX protocol database"""

    def __init__(self, database_file: str = "defi_protocol_database.json"):
        self.database_file = database_file
        self.schema_version = "1.0.0"
        self.created_date = datetime.now().isoformat()

        # Initialize database structure
        self.database = {
            "database_metadata": {
                "created_date": self.created_date,
                "total_protocols": 0,
                "schema_version": self.schema_version,
                "last_updated": self.created_date
            },
            "protocols": [],
            "categories_summary": {},
            "chains_summary": {},
            "risk_distribution": {},
            "maturity_distribution": {}
        }

        # Ensure directory exists
        os.makedirs(os.path.dirname(self.database_file) or ".", exist_ok=True)

    def add_protocol(self, protocol_data: Dict[str, Any]) -> bool:
        """Add a protocol to the database with validation"""
        try:
            # Validate protocol data structure
            if not self._validate_protocol_data(protocol_data):
                logger.error(f"Invalid protocol data structure for {protocol_data.get('protocol_name', 'Unknown')}")
                return False

            # Add protocol ID and timestamps
            protocol_data["protocol_id"] = self._generate_protocol_id(protocol_data)
            protocol_data["created_at"] = datetime.now().isoformat()
            protocol_data["updated_at"] = datetime.now().isoformat()

            # Add to database
            self.database["protocols"].append(protocol_data)

            # Update metadata
            self.database["database_metadata"]["total_protocols"] = len(self.database["protocols"])
            self.database["database_metadata"]["last_updated"] = datetime.now().isoformat()

            # Update summary statistics
            self._update_summary_statistics()

            logger.info(f"Added protocol: {protocol_data['protocol_name']}")
            return True

        except Exception as e:
            logger.error(f"Error adding protocol {protocol_data.get('protocol_name', 'Unknown')}: {e}")
            return False

    def _validate_protocol_data(self, data: Dict[str, Any]) -> bool:
        """Validate protocol data structure"""
        required_fields = [
            "protocol_name", "blockchain", "chain_id",
            "category", "subcategory", "risk_level"
        ]

        for field in required_fields:
            if field not in data or data[field] is None:
                logger.warning(f"Missing required field: {field}")
                return False

        # Validate risk level
        valid_risk_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        if data["risk_level"] not in valid_risk_levels:
            logger.warning(f"Invalid risk level: {data['risk_level']}")
            return False

        # Validate and normalize category
        valid_categories = ["DEX", "LENDING", "YIELD", "BRIDGE", "NFT", "AGGREGATOR", "GOVERNANCE"]

        # Normalize category if it's the generic "DEFI"
        if data["category"] == "DEFI":
            data["category"] = "AGGREGATOR"  # Default to aggregator for general defi protocols
            logger.info(f"Normalized category 'DEFI' to 'AGGREGATOR'")

        if data["category"] not in valid_categories:
            logger.warning(f"Invalid category: {data['category']}")
            return False

        return True

    def _generate_protocol_id(self, protocol_data: Dict[str, Any]) -> str:
        """Generate unique protocol ID"""
        chain_name = protocol_data["blockchain"].lower().replace(" ", "_")
        protocol_name = protocol_data["protocol_name"].lower().replace(" ", "_")
        category = protocol_data["category"].lower()

        return f"{chain_name}_{protocol_name}_{category}_{datetime.now().strftime('%Y%m%d')}"

    def _update_summary_statistics(self):
        """Update summary statistics for the database"""
        protocols = self.database["protocols"]

        # Category summary
        categories = {}
        for protocol in protocols:
            category = protocol.get("category", "UNKNOWN")
            categories[category] = categories.get(category, 0) + 1

        # Chain summary
        chains = {}
        for protocol in protocols:
            blockchain = protocol.get("blockchain", "UNKNOWN")
            chains[blockchain] = chains.get(blockchain, 0) + 1

        # Risk distribution
        risk_dist = {}
        for protocol in protocols:
            risk = protocol.get("risk_level", "UNKNOWN")
            risk_dist[risk] = risk_dist.get(risk, 0) + 1

        # Maturity distribution
        maturity_dist = {}
        for protocol in protocols:
            maturity = protocol.get("maturity_level", "UNKNOWN")
            maturity_dist[maturity] = maturity_dist.get(maturity, 0) + 1

        # Update database summaries
        self.database["categories_summary"] = categories
        self.database["chains_summary"] = chains
        self.database["risk_distribution"] = risk_dist
        self.database["maturity_distribution"] = maturity_dist

    def save_database(self) -> bool:
        """Save database to JSON file"""
        try:
            # Pretty print JSON with indentation
            with open(self.database_file, 'w', encoding='utf-8') as f:
                json.dump(self.database, f, indent=2, ensure_ascii=False)

            logger.info(f"Database saved to {self.database_file}")
            return True

        except Exception as e:
            logger.error(f"Error saving database: {e}")
            return False

    def load_database(self) -> bool:
        """Load database from JSON file if it exists"""
        try:
            if os.path.exists(self.database_file):
                with open(self.database_file, 'r', encoding='utf-8') as f:
                    loaded_data = json.load(f)

                # Validate loaded data structure
                if self._validate_database_structure(loaded_data):
                    self.database = loaded_data
                    logger.info(f"Database loaded from {self.database_file}")
                    return True
                else:
                    logger.warning("Invalid database structure, creating new one")
                    return False
            else:
                logger.info("Database file not found, creating new one")
                return False

        except Exception as e:
            logger.error(f"Error loading database: {e}")
            return False

    def _validate_database_structure(self, data: Dict[str, Any]) -> bool:
        """Validate loaded database structure"""
        required_keys = ["database_metadata", "protocols", "categories_summary",
                        "chains_summary", "risk_distribution", "maturity_distribution"]

        for key in required_keys:
            if key not in data:
                return False

        # Validate metadata
        metadata = data["database_metadata"]
        if "schema_version" not in metadata or "total_protocols" not in metadata:
            return False

        return True

    def get_protocol_by_name(self, protocol_name: str) -> Optional[Dict[str, Any]]:
        """Get protocol by name"""
        for protocol in self.database["protocols"]:
            if protocol.get("protocol_name", "").lower() == protocol_name.lower():
                return protocol
        return None

    def get_protocols_by_chain(self, blockchain: str) -> List[Dict[str, Any]]:
        """Get protocols by blockchain"""
        return [p for p in self.database["protocols"] if p.get("blockchain", "").lower() == blockchain.lower()]

    def get_protocols_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get protocols by category"""
        return [p for p in self.database["protocols"] if p.get("category", "").upper() == category.upper()]

    def get_protocols_by_risk(self, risk_level: str) -> List[Dict[str, Any]]:
        """Get protocols by risk level"""
        return [p for p in self.database["protocols"] if p.get("risk_level", "").upper() == risk_level.upper()]

    def get_database_statistics(self) -> Dict[str, Any]:
        """Get comprehensive database statistics"""
        return {
            "total_protocols": len(self.database["protocols"]),
            "categories": self.database["categories_summary"],
            "chains": self.database["chains_summary"],
            "risk_distribution": self.database["risk_distribution"],
            "maturity_distribution": self.database["maturity_distribution"],
            "protocols": self.database["protocols"]
        }

    def export_to_sqlite(self, sqlite_file: str = "defi_protocols.db") -> bool:
        """Export database to SQLite for better querying"""
        try:
            conn = sqlite3.connect(sqlite_file)
            cursor = conn.cursor()

            # Create protocols table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS protocols (
                    protocol_id TEXT PRIMARY KEY,
                    protocol_name TEXT NOT NULL,
                    display_name TEXT,
                    blockchain TEXT NOT NULL,
                    chain_id INTEGER,
                    category TEXT NOT NULL,
                    subcategory TEXT,
                    risk_level TEXT NOT NULL,
                    maturity_level TEXT,
                    official_website TEXT,
                    documentation TEXT,
                    github TEXT,
                    social_links TEXT,
                    contract_addresses TEXT,
                    api_endpoints TEXT,
                    technologies TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    age_months INTEGER,
                    keywords TEXT
                )
            ''')

            # Insert protocols
            for protocol in self.database["protocols"]:
                cursor.execute('''
                    INSERT OR REPLACE INTO protocols (
                        protocol_id, protocol_name, display_name, blockchain, chain_id,
                        category, subcategory, risk_level, maturity_level,
                        official_website, documentation, github, social_links,
                        contract_addresses, api_endpoints, technologies,
                        created_at, updated_at, age_months, keywords
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    protocol.get("protocol_id"),
                    protocol.get("protocol_name"),
                    protocol.get("display_name"),
                    protocol.get("blockchain"),
                    protocol.get("chain_id"),
                    protocol.get("category"),
                    protocol.get("subcategory"),
                    protocol.get("risk_level"),
                    protocol.get("maturity_level"),
                    protocol.get("official_website"),
                    protocol.get("documentation"),
                    protocol.get("github"),
                    json.dumps(protocol.get("social_links", {})),
                    json.dumps(protocol.get("contract_addresses", {})),
                    json.dumps(protocol.get("api_endpoints", [])),
                    json.dumps(protocol.get("technologies", [])),
                    protocol.get("created_at"),
                    protocol.get("updated_at"),
                    protocol.get("age_months"),
                    json.dumps(protocol.get("keywords", []))
                ))

            conn.commit()
            conn.close()

            logger.info(f"Database exported to SQLite: {sqlite_file}")
            return True

        except Exception as e:
            logger.error(f"Error exporting to SQLite: {e}")
            return False


def load_discovery_data() -> List[Dict[str, Any]]:
    """Load Phase 1 discovery data"""
    discovery_file = "defi_discovery_database.json"

    try:
        with open(discovery_file, 'r', encoding='utf-8') as f:
            discovery_data = json.load(f)

        # Extract protocols from discovery data
        protocols = discovery_data.get("discovered_websites", [])
        logger.info(f"Loaded {len(protocols)} protocols from discovery phase")
        return protocols

    except FileNotFoundError:
        logger.warning(f"Discovery file not found: {discovery_file}")
        return []
    except Exception as e:
        logger.error(f"Error loading discovery data: {e}")
        return []


def main():
    """Main function to run Phase 2 database setup"""
    logger.info("Starting Phase 2: Database Structuring and Storage")

    # Initialize database manager
    db_manager = DEFIDatabaseManager()

    # Load existing database if available
    if not db_manager.load_database():
        logger.info("Creating new database")

    # Load discovery data from Phase 1
    discovered_protocols = load_discovery_data()

    # Process and add protocols to database
    added_count = 0
    for protocol_data in discovered_protocols:
        if db_manager.add_protocol(protocol_data):
            added_count += 1

    # Save database
    if db_manager.save_database():
        logger.info(f"Phase 2 completed. Database contains {db_manager.database['database_metadata']['total_protocols']} protocols")

        # Print statistics
        stats = db_manager.get_database_statistics()
        logger.info(f"Categories: {stats['categories']}")
        logger.info(f"Chains: {stats['chains']}")
        logger.info(f"Risk distribution: {stats['risk_distribution']}")

        # Export to SQLite
        db_manager.export_to_sqlite()

        logger.info("Phase 2 completed successfully")
    else:
        logger.error("Failed to save database")
        return False

    return True


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)