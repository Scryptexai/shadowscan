#!/usr/bin/env python3
"""
Simple script to run Phase 3 contract scanning
"""

import sys
from pathlib import Path

# Add modular system to path
sys.path.append(str(Path(__file__).parent / "modular_system"))

from modular_system.system_controller import ModularSystemController, SystemPhase

def main():
    """Run Phase 3 directly"""
    try:
        # Initialize controller
        controller = ModularSystemController()

        # Initialize system
        if not controller.initialize_system():
            print("Failed to initialize system")
            return 1

        # Start Phase 3
        print("Starting Phase 3: Contract Intelligence Gathering...")
        success = controller.start_phase(SystemPhase.PHASE_3)

        if success:
            print("Phase 3 started successfully")
            return 0
        else:
            print("Failed to start Phase 3")
            return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1

if __name__ == "__main__":
    exit(main())