#!/usr/bin/env python3
"""
Phase 3 Runner - Contract and Backend Intelligence Gathering
Coordinates the modular contract scanner for comprehensive intelligence gathering
"""

import json
import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

from ..core import BaseManager, ConfigManager, DiagnosticTools, handle_error, ErrorSeverity, ErrorCategory
from ..scanners import ContractScanner

class Phase3Runner(BaseManager):
    """Phase 3 Runner - Contract and Backend Intelligence Gathering"""

    def __init__(self, config: Dict[str, Any] = None):
        # Initialize config first
        self.config = config or {}
        self.debug_mode = self.config.get('debug_mode', False)

        # Now call parent with proper config
        super().__init__("Phase3Runner", self.config)
        self.diagnostic = DiagnosticTools()

        # Initialize components
        self.config_manager = ConfigManager()
        self.contract_scanner = ContractScanner(config)

        # Setup logging
        self.logger.info("Phase3Runner initialized")

    def run_phase_3(self) -> bool:
        """Execute Phase 3 - Contract and Backend Intelligence Gathering"""
        try:
            self.logger.info("Starting Phase 3: Contract and Backend Intelligence Gathering")

            with self.diagnostic.trace_operation("Phase3Runner", "execute_phase_3"):
                # Validate prerequisites
                if not self._validate_prerequisites():
                    self.logger.error("Phase 3 validation failed")
                    return False

                # Run contract scanner
                self.logger.info("Starting contract scanning")
                contract_results = self.contract_scanner.run()

                if contract_results:
                    # Process results
                    processed_results = self._process_contract_results(contract_results)

                    # Save comprehensive database
                    self._save_intelligence_database(processed_results)

                    # Generate summary report
                    self._generate_summary_report(processed_results)

                    self.logger.info("Phase 3 completed successfully")
                    return True
                else:
                    self.logger.error("Contract scanning failed")
                    return False

        except Exception as e:
            error_data = handle_error(e, "Phase3Runner")
            self.logger.error(f"Phase 3 execution failed: {e}")
            return False

    def _validate_prerequisites(self) -> bool:
        """Validate Phase 3 prerequisites"""
        try:
            # Check if Phase 1 database exists
            phase1_file = "defi_protocol_database.json"
            if not Path(phase1_file).exists():
                self.logger.error(f"Phase 1 database not found: {phase1_file}")
                return False

            # Check configuration
            required_keys = [
                'network.max_retries',
                'network.timeout',
                'scanning.phase_3.enabled',
                'scanning.phase_3.max_contracts'
            ]

            for key in required_keys:
                if not self.config_manager.get(key):
                    self.logger.warning(f"Missing configuration: {key}")

            return True

        except Exception as e:
            self.logger.error(f"Prerequisites validation failed: {e}")
            return False

    def _process_contract_results(self, contract_results: Dict[str, Any]) -> Dict[str, Any]:
        """Process contract scanner results"""
        try:
            processed = {
                'metadata': {
                    'phase': 'Phase 3',
                    'executed_at': datetime.now().isoformat(),
                    'tool': 'ContractScanner',
                    'total_protocols': 0,
                    'total_contracts': 0,
                    'average_confidence': 0.0
                },
                'contract_intelligence': {},
                'summary_statistics': {}
            }

            # Process each protocol's contract intelligence
            total_confidence = 0
            contract_count = 0

            for protocol_name, intelligence_list in contract_results.get('contract_intelligence', {}).items():
                processed['contract_intelligence'][protocol_name] = []

                for intelligence in intelligence_list:
                    processed['contract_intelligence'][protocol_name].append(intelligence)
                    total_confidence += intelligence.confidence_level
                    contract_count += 1

            # Update metadata
            processed['metadata']['total_protocols'] = len(processed['contract_intelligence'])
            processed['metadata']['total_contracts'] = contract_count
            processed['metadata']['average_confidence'] = total_confidence / max(contract_count, 1)

            # Generate summary statistics
            processed['summary_statistics'] = self._generate_statistics(processed)

            return processed

        except Exception as e:
            self.logger.error(f"Error processing contract results: {e}")
            return {}

    def _generate_statistics(self, processed_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary statistics from processed results"""
        try:
            stats = {
                'contract_types': {},
                'security_scores': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
                'audit_status': {},
                'confidence_levels': [],
                'chains': {},
                'functions_per_contract': [],
                'events_per_contract': []
            }

            for protocol_name, intelligence_list in processed_results.get('contract_intelligence', {}).items():
                for intelligence in intelligence_list:
                    # Contract types
                    contract_type = intelligence.contract_type
                    stats['contract_types'][contract_type] = stats['contract_types'].get(contract_type, 0) + 1

                    # Security scores
                    score = intelligence.security_score
                    if score < 30:
                        stats['security_scores']['critical'] += 1
                    elif score < 60:
                        stats['security_scores']['low'] += 1
                    elif score < 80:
                        stats['security_scores']['medium'] += 1
                    else:
                        stats['security_scores']['high'] += 1

                    # Audit status
                    audit_status = intelligence.audit_status
                    stats['audit_status'][audit_status] = stats['audit_status'].get(audit_status, 0) + 1

                    # Confidence levels
                    stats['confidence_levels'].append(intelligence.confidence_level)

                    # Chains
                    chain = intelligence.chain_name
                    stats['chains'][chain] = stats['chains'].get(chain, 0) + 1

                    # Functions and events
                    stats['functions_per_contract'].append(len(intelligence.function_signatures))
                    stats['events_per_contract'].append(len(intelligence.event_signatures))

            return stats

        except Exception as e:
            self.logger.error(f"Error generating statistics: {e}")
            return {}

    def _save_intelligence_database(self, processed_results: Dict[str, Any]):
        """Save comprehensive intelligence database"""
        try:
            # Create output directory
            output_dir = Path("intelligence_databases")
            output_dir.mkdir(exist_ok=True)

            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"contract_intelligence_database_{timestamp}.json"
            filepath = output_dir / filename

            # Save database
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(processed_results, f, indent=2, ensure_ascii=False)

            self.logger.info(f"Intelligence database saved to: {filepath}")

            # Export SQLite version
            self._export_sqlite_database(processed_results, filepath)

        except Exception as e:
            self.logger.error(f"Error saving intelligence database: {e}")

    def _export_sqlite_database(self, processed_results: Dict[str, Any], json_file_path: Path):
        """Export intelligence database to SQLite"""
        try:
            import sqlite3

            sqlite_file = json_file_path.parent / "contract_intelligence.db"
            conn = sqlite3.connect(sqlite_file)
            cursor = conn.cursor()

            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS contracts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    protocol_name TEXT NOT NULL,
                    contract_address TEXT NOT NULL,
                    contract_type TEXT,
                    chain_id INTEGER,
                    chain_name TEXT,
                    security_score INTEGER,
                    audit_status TEXT,
                    confidence_level REAL,
                    functions_count INTEGER,
                    events_count INTEGER,
                    abi_text TEXT,
                    bytecode TEXT,
                    discovered_at TEXT,
                    UNIQUE(contract_address, chain_id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS functions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    contract_id INTEGER,
                    signature TEXT,
                    FOREIGN KEY (contract_id) REFERENCES contracts (id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    contract_id INTEGER,
                    signature TEXT,
                    FOREIGN KEY (contract_id) REFERENCES contracts (id)
                )
            ''')

            # Insert contract data
            for protocol_name, intelligence_list in processed_results.get('contract_intelligence', {}).items():
                for intelligence in intelligence_list:
                    cursor.execute('''
                        INSERT OR REPLACE INTO contracts (
                            protocol_name, contract_address, contract_type, chain_id,
                            chain_name, security_score, audit_status, confidence_level,
                            functions_count, events_count, abi_text, bytecode, discovered_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        protocol_name,
                        intelligence.contract_address,
                        intelligence.contract_type,
                        intelligence.chain_id,
                        intelligence.chain_name,
                        intelligence.security_score,
                        intelligence.audit_status,
                        intelligence.confidence_level,
                        len(intelligence.function_signatures),
                        len(intelligence.event_signatures),
                        json.dumps(intelligence.abi),
                        intelligence.bytecode,
                        intelligence.discovered_at.isoformat()
                    ))

                    # Get contract ID
                    cursor.execute('SELECT id FROM contracts WHERE contract_address = ? AND chain_id = ?',
                                 (intelligence.contract_address, intelligence.chain_id))
                    contract_id = cursor.fetchone()[0]

                    # Insert functions
                    for function in intelligence.function_signatures:
                        cursor.execute('INSERT INTO functions (contract_id, signature) VALUES (?, ?)',
                                     (contract_id, function))

                    # Insert events
                    for event in intelligence.event_signatures:
                        cursor.execute('INSERT INTO events (contract_id, signature) VALUES (?, ?)',
                                     (contract_id, event))

            conn.commit()
            conn.close()

            self.logger.info(f"SQLite database exported to: {sqlite_file}")

        except Exception as e:
            self.logger.error(f"Error exporting SQLite database: {e}")

    def _generate_summary_report(self, processed_results: Dict[str, Any]):
        """Generate Phase 3 summary report"""
        try:
            # Create reports directory
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)

            # Generate summary report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = reports_dir / f"phase_3_summary_{timestamp}.txt"

            with open(report_file, 'w', encoding='utf-8') as f:
                f.write("PHASE 3: CONTRACT AND BACKEND INTELLIGENCE GATHERING\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"Executed at: {processed_results['metadata']['executed_at']}\n")
                f.write(f"Total protocols scanned: {processed_results['metadata']['total_protocols']}\n")
                f.write(f"Total contracts discovered: {processed_results['metadata']['total_contracts']}\n")
                f.write(f"Average confidence level: {processed_results['metadata']['average_confidence']:.2%}\n\n")

                # Summary statistics
                stats = processed_results.get('summary_statistics', {})
                f.write("SUMMARY STATISTICS\n")
                f.write("-" * 30 + "\n")

                if stats.get('contract_types'):
                    f.write("Contract Types:\n")
                    for contract_type, count in stats['contract_types'].items():
                        f.write(f"  {contract_type}: {count}\n")

                if stats.get('security_scores'):
                    f.write("\nSecurity Score Distribution:\n")
                    for level, count in stats['security_scores'].items():
                        f.write(f"  {level}: {count}\n")

                if stats.get('audit_status'):
                    f.write("\nAudit Status Distribution:\n")
                    for status, count in stats['audit_status'].items():
                        f.write(f"  {status}: {count}\n")

                if stats.get('chains'):
                    f.write("\nChains:\n")
                    for chain, count in stats['chains'].items():
                        f.write(f"  {chain}: {count}\n")

            self.logger.info(f"Summary report generated: {report_file}")

        except Exception as e:
            self.logger.error(f"Error generating summary report: {e}")

    def run(self) -> bool:
        """Run Phase 3"""
        return self.run_phase_3()


def main():
    """Main function to run Phase 3"""
    runner = Phase3Runner()
    success = runner.run()
    runner.cleanup()
    exit(0 if success else 1)


if __name__ == "__main__":
    main()