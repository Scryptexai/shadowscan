"""
ShadowScan Report Generator - Minimal Implementation
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any


class ReportGenerator:
    def generate_json_report(self, results: Dict[str, Any], output_path: str) -> None:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        results["report_metadata"] = {
            "generated_at": datetime.now().isoformat(),
            "format": "json",
            "version": "1.0.0"
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
    
    def generate_html_report(self, results: Dict[str, Any], output_path: str) -> None:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        findings = results.get("findings", [])
        target = results.get("target", "Unknown")
        
        html_content = f'''<!DOCTYPE html>
<html><head><title>ShadowScan Report</title></head>
<body>
<h1>🌑 ShadowScan Security Report</h1>
<p>Target: {target}</p>
<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<p>Total Findings: {len(findings)}</p>
<div>
'''
        for finding in findings:
            html_content += f'''
<div style="border: 1px solid #ddd; margin: 10px 0; padding: 10px;">
<h3>{finding.get("title", "Unknown")}</h3>
<p>Severity: {finding.get("severity", "UNKNOWN")}</p>
<p>{finding.get("description", "")}</p>
<p><strong>Recommendation:</strong> {finding.get("recommendation", "")}</p>
</div>
'''
        html_content += '</div></body></html>'
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def generate_pdf_report(self, results: Dict[str, Any], output_path: str) -> None:
        html_path = output_path.replace('.pdf', '.html')
        self.generate_html_report(results, html_path)
