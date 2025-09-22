#!/usr/bin/env python3
"""
Main Entry Point for Modular Scanning System
Provides CLI interface and system coordination
"""

import argparse
import sys
import json
import logging
from pathlib import Path
from datetime import datetime

# Add modular system to path
sys.path.append(str(Path(__file__).parent / "modular_system"))

from modular_system.system_controller import ModularSystemController, SystemPhase, get_system_status, start_phase, get_diagnostics, set_config

def setup_logging(log_level: str = "INFO"):
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('modular_system.log')
        ]
    )

def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(description="Modular Scanning System - Advanced DEFI/DEX Vulnerability Scanner")

    # Global options
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--log-level', '-l', default='INFO', help='Log level (DEBUG, INFO, WARNING, ERROR)')
    parser.add_argument('--env', '-e', default='development', help='Environment (development, testing, production)')

    # System commands
    system_group = parser.add_mutually_exclusive_group()
    system_group.add_argument('--init', action='store_true', help='Initialize the system')
    system_group.add_argument('--status', action='store_true', help='Get system status')
    system_group.add_argument('--diagnostics', action='store_true', help='Export system diagnostics')
    system_group.add_argument('--cleanup', action='store_true', help='Cleanup system resources')

    # Phase commands
    phase_group = parser.add_mutually_exclusive_group()
    phase_group.add_argument('--phase3', action='store_true', help='Run Phase 3: Contract Intelligence')

    # Options for phase execution
    parser.add_argument('--dry-run', action='store_true', help='Dry run mode (no actual execution)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)

    try:
        # Initialize system controller
        controller = ModularSystemController()

        # Set environment
        set_config('system.environment', args.env)

        # Handle commands
        if args.init:
            logger.info("Initializing modular scanning system...")
            success = controller.initialize_system()
            if success:
                logger.info("System initialized successfully")
                return 0
            else:
                logger.error("System initialization failed")
                return 1

        elif args.status:
            status = get_system_status()
            print(json.dumps(status, indent=2))
            return 0

        elif args.diagnostics:
            logger.info("Exporting system diagnostics...")
            diag_file = controller.export_diagnostics()
            if diag_file:
                logger.info(f"Diagnostics exported to: {diag_file}")
                return 0
            else:
                logger.error("Failed to export diagnostics")
                return 1

        elif args.cleanup:
            logger.info("Cleaning up system...")
            controller.cleanup()
            logger.info("Cleanup completed")
            return 0

        elif args.phase3:
            logger.info("Starting Phase 3: Contract Intelligence Gathering...")
            success = start_phase(SystemPhase.PHASE_3)
            if success:
                logger.info("Phase 3 started successfully")
                return 0
            else:
                logger.error("Failed to start Phase 3")
                return 1

        else:
            # Default: run the system
            logger.info("Starting modular scanning system...")

            if args.dry_run:
                logger.info("Dry run mode - no actual execution")
                return 0

            if args.debug:
                set_config('system.debug_mode', True)
                logger.info("Debug mode enabled")

            success = controller.run()
            controller.cleanup()

            if success:
                logger.info("System execution completed successfully")
                return 0
            else:
                logger.error("System execution failed")
                return 1

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    exit(main())