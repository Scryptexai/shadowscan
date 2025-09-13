# shadowscan/core/engine.py
from typing import Dict, Any, List, Optional
from .logger import StealthLogger
from ..config import ConfigLoader
from ..modules.base import BaseModule
import importlib
import pkgutil
import os

class ShadowScanEngine:
    """Engine utama ShadowScan untuk mengoordinasikan semua modul"""
    
    def __init__(self, config: ConfigLoader):
        self.config = config
        self.logger = StealthLogger(config)
        self.modules = self._load_modules()
    
    def _load_modules(self) -> List[BaseModule]:
        """Load semua modul berdasarkan target"""
        modules = []
        
        # Tentukan kategori modul berdasarkan target
        if self.config.get('TARGET_TYPE') == 'blockchain':
            module_categories = ['blockchain']
        elif self.config.get('TARGET_TYPE') == 'web':
            module_categories = ['web']
        elif self.config.get('TARGET_TYPE') == 'network':
            module_categories = ['network']
        else:
            module_categories = ['blockchain', 'web', 'network']
        
        # Load modul dari kategori yang relevan
        base_package = 'shadowscan.modules'
        modules_dir = os.path.dirname(__file__) + '/../../modules'
        
        for category in module_categories:
            try:
                # Cari semua modul di kategori ini
                category_path = os.path.join(modules_dir, category)
                if not os.path.isdir(category_path):
                    continue
                
                for _, name, _ in pkgutil.iter_modules([category_path]):
                    if name.startswith('_'):
                        continue
                    
                    try:
                        # Import modul
                        module_path = f"{base_package}.{category}.{name}"
                        module = importlib.import_module(module_path)
                        
                        # Cari kelas modul
                        for attribute_name in dir(module):
                            attribute = getattr(module, attribute_name)
                            if (
                                isinstance(attribute, type) and 
                                issubclass(attribute, BaseModule) and 
                                attribute != BaseModule
                            ):
                                # Inisialisasi modul
                                try:
                                    if category == 'blockchain':
                                        from ..integrations.tenderly import TenderlyFork
                                        tenderly = TenderlyFork(self.config.all())
                                        instance = attribute(self.config.all(), self.logger, tenderly)
                                    else:
                                        instance = attribute(self.config.all(), self.logger)
                                    
                                    modules.append(instance)
                                    break
                                except Exception as e:
                                    self.logger.warning(f"Gagal inisialisasi modul {name}: {str(e)}")
                    except Exception as e:
                        self.logger.warning(f"Gagal load modul {name} di kategori {category}: {str(e)}")
            except Exception as e:
                self.logger.warning(f"Gagal load kategori {category}: {str(e)}")
        
        self.logger.info(f"✅ {len(modules)} modul berhasil dimuat", force=True)
        return modules
    
    def run(self) -> Dict[str, Any]:
        """Jalankan semua scan dan kumpulkan hasil"""
        self.logger.start_scan(self._get_target_name())
        
        all_findings = []
        for module in self.modules:
            try:
                findings = module.scan()
                all_findings.extend(findings)
            except Exception as e:
                self.logger.error(f"❌ Gagal menjalankan modul {module.name}: {str(e)}")
        
        self.logger.end_scan()
        
        # Generate laporan
        report_path = self._generate_report(all_findings)
        
        return {
            'target': self._get_target_name(),
            'findings': all_findings,
            'report_path': report_path
        }
    
    def _get_target_name(self) -> str:
        """Dapatkan nama target untuk logging"""
        if self.config.get('TARGET_TYPE') == 'blockchain':
            return f"Blockchain Contract {self.config.get('TARGET_CONTRACT')[:10]}..."
        elif self.config.get('TARGET_TYPE') == 'web':
            return f"Web Application {self.config.get('TARGET_URL')}"
        elif self.config.get('TARGET_TYPE') == 'network':
            return f"Network Target {self.config.get('TARGET_URL')}"
        return "Unknown Target"
    
    def _generate_report(self, findings: List[Dict[str, Any]]) -> str:
        """Generate laporan sederhana"""
        report_dir = self.config.get('REPORT_DIR', 'reports')
        os.makedirs(report_dir, exist_ok=True)
        
        # Buat nama file berdasarkan timestamp
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_format = self.config.get('REPORT_FORMAT', 'html')
        
        report_path = f"{report_dir}/shadowscan_report_{timestamp}.{report_format}"
        
        if report_format == 'html':
            self._generate_html(findings, report_path)
        elif report_format == 'json':
            self._generate_json(findings, report_path)
        else:  # pdf
            # Untuk demo, kita gunakan HTML sebagai fallback
            html_path = f"{report_dir}/shadowscan_report_{timestamp}.html"
            self._generate_html(findings, html_path)
            report_path = html_path
        
        self.logger.info(f"📄 Laporan berhasil dibuat: {report_path}", force=True)
        return report_path
    
    def _generate_html(self, findings: List[Dict[str, Any]], output_path: str) -> None:
        """Generate laporan HTML sederhana"""
        target = self._get_target_name()
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Kelompokkan temuan berdasarkan severity
        high_findings = [f for f in findings if f.get('severity', '').lower() == 'high']
        medium_findings = [f for f in findings if f.get('severity', '').lower() == 'medium']
        low_findings = [f for f in findings if f.get('severity', '').lower() == 'low']
        
        # Template HTML sederhana
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>ShadowScan Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .card {{ padding: 15px; border-radius: 5px; }}
        .high {{ background: #ffebee; border-left: 5px solid #f44336; }}
        .medium {{ background: #fff8e1; border-left: 5px solid #ffc107; }}
        .low {{ background: #e8f5e9; border-left: 5px solid #4caf50; }}
        .finding {{ margin: 15px 0; padding: 10px; border: 1px solid #ddd; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>ShadowScan Security Report</h1>
        <p>Analisis keamanan untuk {target}</p>
    </div>
    
    <div class="summary">
        <div class="card high">
            <h3>Tinggi</h3>
            <p>{len(high_findings)} kerentanan</p>
        </div>
        <div class="card medium">
            <h3>Menengah</h3>
            <p>{len(medium_findings)} kerentanan</p>
        </div>
        <div class="card low">
            <h3>Rendah</h3>
            <p>{len(low_findings)} kerentanan</p>
        </div>
    </div>
    
    {'<h2>Kerentanan Tingkat Tinggi</h2>' if high_findings else ''}
    {''.join(f'<div class="finding high"><h3>{f["description"]}</h3><p>{f.get("proof", "")}</p></div>' for f in high_findings)}
    
    {'<h2>Kerentanan Tingkat Menengah</h2>' if medium_findings else ''}
    {''.join(f'<div class="finding medium"><h3>{f["description"]}</h3><p>{f.get("proof", "")}</p></div>' for f in medium_findings)}
    
    {'<h2>Kerentanan Tingkat Rendah</h2>' if low_findings else ''}
    {''.join(f'<div class="finding low"><h3>{f["description"]}</h3><p>{f.get("proof", "")}</p></div>' for f in low_findings)}
    
    {'' if findings else '<h2>Tidak Ditemukan Kerentanan</h2><p>Target yang dianalisis tidak menunjukkan kerentanan yang signifikan.</p>'}
    
    <div class="footer">
        <p>Dilaporkan pada: {timestamp}</p>
        <p>ShadowScan v1.0.0 - Universal Cyber Attack Test Engine</p>
    </div>
</body>
</html>
"""
        
        with open(output_path, 'w') as f:
            f.write(html)
    
    def _generate_json(self, findings: List[Dict[str, Any]], output_path: str) -> None:
        """Generate laporan JSON sederhana"""
        import json
        from datetime import datetime
        
        report_data = {
            'target': self._get_target_name(),
            'timestamp': datetime.now().isoformat(),
            'total_findings': len(findings),
            'findings': findings
        }
        
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2)
