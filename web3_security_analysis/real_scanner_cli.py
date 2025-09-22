#!/usr/bin/env python3
"""
REAL SECURITY SCANNER CLI
Simple CLI untuk scanning real-time website targets dengan fokus pada response 200 OK
Usage: python3 real_scanner_cli.py target1 target2 target3
"""

import sys
import json
from modular_real_scanner import ModularRealSecurityScanner

def main():
    if len(sys.argv) < 2:
        print("🎯 REAL SECURITY SCANNER CLI")
        print("=" * 50)
        print("Usage: python3 real_scanner_cli.py <target1> <target2> <target3>")
        print("Example: python3 real_scanner_cli.com claim.holoworld.com example.com")
        print()
        print("Supported targets:")
        print("- claim.holoworld.com")
        print("- example.com")
        print("- Any website with HTTP/HTTPS support")
        sys.exit(1)

    targets = sys.argv[1:]

    print("🎯 REAL SECURITY SCANNER CLI")
    print("=" * 50)
    print(f"🔍 Targets: {', '.join(targets)}")
    print("🚀 Starting real-time security assessment...")
    print("=" * 50)

    results = {}

    for target in targets:
        print(f"\n🔍 SCANNING: {target}")
        print("-" * 40)

        scanner = ModularRealSecurityScanner(target)
        report = scanner.run_full_scan()
        results[target] = report

        print(f"\n✅ COMPLETED: {target}")
        print("-" * 40)

    # Print final summary
    print(f"\n🎯 ALL SCANS COMPLETED")
    print("=" * 50)

    for target, report in results.items():
        metrics = report.get('scan_metrics', {})
        print(f"📊 {target}: {metrics.get('risk_level', 'UNKNOWN')} risk ({metrics.get('successful_tests', 0)} vulnerabilities)")

if __name__ == "__main__":
    main()