"""
ShadowScan Report Generator - Simplified Version
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

class ReportGenerator:
    """Simplified report generator."""
    
    def __init__(self):
        self.report_dir = Path("reports")
        self.report_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_json_report(self, results: Dict[str, Any], output_path: str) -> None:
        """Generate JSON report."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        results["report_metadata"] = {
            "generated_at": datetime.now().isoformat(),
            "format": "json",
            "version": "1.0.0"
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
    
    def generate_html_report(self, results: Dict[str, Any], output_path: str) -> None:
        """Generate HTML report."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        findings = results.get("verified_vulnerabilities", results.get("findings", []))
        target = results.get("report_metadata", {}).get("target", "Unknown")
        
        html_content = f'''<!DOCTYPE html>
<html><head><title>ShadowScan Professional Report</title></head>
<body>
<h1>ShadowScan Professional Report</h1>
<p>Target: {target}</p>
<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<p>Total Findings: {len(findings)}</p>
</body></html>'''
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def generate_pdf_report(self, results: Dict[str, Any], output_path: str) -> None:
        """Generate PDF report (fallback to HTML)."""
        html_path = output_path.replace('.pdf', '.html')
        self.generate_html_report(results, html_path)
