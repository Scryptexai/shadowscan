#!/usr/bin/env python3
# shadowscan/test_modules_workflow.py
"""Complete workflow test for 3-Module System Validation

This script validates the complete workflow:
Module 1: Main Contract Screening + Ecosystem Tracking
Module 2: Verification & Data Processing for Attack
Module 3: Attack Execution with Data from Module 1&2
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from shadowscan.core.pipeline.screening_engine import ScreeningEngine
from shadowscan.core.attack.attack_framework import AttackFramework
from shadowscan.collectors.evm.dex_discovery import DexDiscovery
from shadowscan.utils.schema import ScreeningSession

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ModuleWorkflowTest:
    """Test complete 3-module workflow system."""
    
    def __init__(self):
        """Initialize test with environment configuration."""
        self.env_config = self._load_env_config()
        self.module1_results = {}
        self.module2_results = {}
        self.module3_results = {}
        self.test_session_id = f"workflow_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
    def _load_env_config(self) -> Dict[str, str]:
        """Load configuration from .env file."""
        config = {}
        env_file = Path(__file__).parent / '.env'
        
        if env_file.exists():
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        config[key] = value
        
        logger.info(f"Loaded configuration: {list(config.keys())}")
        return config
    
    async def test_module1_screening_ecosystem(self) -> Dict[str, Any]:
        """
        Module 1: Main Contract Screening + Ecosystem Tracking
        
        - Screen main target contract from .env
        - Discover DEX and DApp ecosystem interactions
        - Track related contracts through transaction analysis
        - Screen discovered contracts for vulnerabilities
        """
        logger.info("=" * 70)
        logger.info("🔍 MODULE 1: MAIN CONTRACT SCREENING + ECOSYSTEM TRACKING")
        logger.info("=" * 70)
        
        # Get target from environment
        target_contract = self.env_config.get('TARGET_CONTRACT')
        rpc_url = self.env_config.get('TENDERLY_RPC')
        etherscan_key = self.env_config.get('ETHERSCAN_API_KEY')
        
        if not target_contract:
            raise ValueError("TARGET_CONTRACT not found in .env")
        
        if not rpc_url:
            raise ValueError("TENDERLY_RPC not found in .env")
        
        logger.info(f"🎯 Target Contract: {target_contract}")
        logger.info(f"🌐 RPC URL: {rpc_url}")
        
        try:
            # Initialize screening engine
            logger.info("🔧 Initializing Screening Engine...")
            engine = ScreeningEngine(rpc_url, etherscan_key)
            
            # Run comprehensive screening with ecosystem tracking
            logger.info("🚀 Starting main contract screening...")
            screening_opts = {
                'with_graph': True,
                'with_events': True,
                'with_state': True,
                'concurrency': 8,
                'timeout': 300,
                'output': f'test_output/{self.test_session_id}/module1'
            }
            
            result = engine.run_screening(
                target=target_contract,
                chain='ethereum',
                mode='fork',
                depth='full',
                opts=screening_opts
            )
            
            if not result['success']:
                raise Exception(f"Screening failed: {result.get('summary', {}).get('error', 'Unknown error')}")
            
            summary = result['summary']
            
            # Extract ecosystem information
            ecosystem_data = self._extract_ecosystem_data(summary, result['session_file'])
            
            module1_result = {
                'success': True,
                'target_contract': target_contract,
                'main_contract_vulnerabilities': summary.get('vulnerabilities_by_severity', {}),
                'function_count': summary.get('function_count', 0),
                'is_proxy': summary.get('is_proxy', False),
                'dex_relations': ecosystem_data['dex_relations'],
                'related_contracts': ecosystem_data['related_contracts'],
                'session_file': result['session_file'],
                'execution_time': result.get('execution_time', 0)
            }
            
            logger.info(f"✅ Module 1 completed in {module1_result['execution_time']:.2f}s")
            logger.info(f"📊 Main Contract: {len(module1_result['main_contract_vulnerabilities'])} vulnerability types")
            logger.info(f"🕸️  DEX Relations: {len(module1_result['dex_relations'])}")
            logger.info(f"🔗 Related Contracts: {len(module1_result['related_contracts'])}")
            
            self.module1_results = module1_result
            return module1_result
            
        except Exception as e:
            logger.error(f"❌ Module 1 failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _extract_ecosystem_data(self, summary: Dict, session_file: str) -> Dict[str, List]:
        """Extract ecosystem tracking data from screening results."""
        try:
            session_path = Path(session_file)
            if not session_path.exists():
                logger.warning(f"Session file not found: {session_file}")
                return {'dex_relations': [], 'related_contracts': []}
            
            with open(session_file, 'r') as f:
                session_data = json.load(f)
            
            # Extract DEX relations
            dex_relations = []
            if 'dex_analysis' in session_data:
                for dex_name, dex_info in session_data['dex_analysis'].items():
                    dex_relations.append({
                        'name': dex_name,
                        'address': dex_info.get('address', ''),
                        'type': dex_info.get('type', 'unknown'),
                        'liquidity_usd': dex_info.get('liquidity_usd', 0),
                        'interactions': dex_info.get('interactions', [])
                    })
            
            # Extract related contracts from transaction analysis
            related_contracts = []
            if 'transaction_analysis' in session_data:
                for tx in session_data['transaction_analysis'].get('transactions', []):
                    for interaction in tx.get('interactions', []):
                        contract_addr = interaction.get('contract_address')
                        if contract_addr and contract_addr != summary.get('target_address'):
                            related_contracts.append({
                                'address': contract_addr,
                                'type': interaction.get('type', 'unknown'),
                                'interaction_count': 1
                            })
            
            # Remove duplicates
            unique_contracts = {}
            for contract in related_contracts:
                addr = contract['address']
                if addr not in unique_contracts:
                    unique_contracts[addr] = contract
                else:
                    unique_contracts[addr]['interaction_count'] += 1
            
            return {
                'dex_relations': dex_relations,
                'related_contracts': list(unique_contracts.values())
            }
            
        except Exception as e:
            logger.error(f"Error extracting ecosystem data: {e}")
            return {'dex_relations': [], 'related_contracts': []}
    
    async def test_module2_verification_processing(self) -> Dict[str, Any]:
        """
        Module 2: Verification & Data Processing for Attack
        
        - Verify vulnerabilities found in Module 1
        - Process ecosystem data for attack preparation
        - Create attack scenarios based on verified findings
        - Prepare attack data for Module 3 execution
        """
        logger.info("=" * 70)
        logger.info("🔬 MODULE 2: VERIFICATION & DATA PROCESSING FOR ATTACK")
        logger.info("=" * 70)
        
        if not self.module1_results.get('success'):
            raise Exception("Module 1 must complete successfully before Module 2")
        
        try:
            logger.info("🔍 Processing Module 1 findings...")
            
            # Initialize attack framework for verification
            rpc_url = self.env_config.get('TENDERLY_RPC')
            etherscan_key = self.env_config.get('ETHERSCAN_API_KEY')
            
            attack_framework = AttackFramework()
            
            # Verify main contract vulnerabilities
            logger.info("📋 Verifying main contract vulnerabilities...")
            verified_vulns = await self._verify_vulnerabilities(
                self.module1_results['main_contract_vulnerabilities'],
                self.module1_results['target_contract'],
                attack_framework
            )
            
            # Screen related contracts for vulnerabilities
            logger.info("🔗 Screening related contracts...")
            related_contract_vulns = await self._screen_related_contracts(
                self.module1_results['related_contracts'],
                attack_framework
            )
            
            # Prepare attack scenarios
            logger.info("⚔️  Preparing attack scenarios...")
            attack_scenarios = self._prepare_attack_scenarios(
                verified_vulns,
                related_contract_vulns,
                self.module1_results['dex_relations']
            )
            
            module2_result = {
                'success': True,
                'verified_main_contract_vulns': verified_vulns,
                'related_contract_vulns': related_contract_vulns,
                'attack_scenarios': attack_scenarios,
                'processing_time': 0  # Will be calculated
            }
            
            logger.info(f"✅ Module 2 completed")
            logger.info(f"📊 Verified Vulnerabilities: {len(verified_vulns)}")
            logger.info(f"🔗 Related Contracts with Vulns: {len(related_contract_vulns)}")
            logger.info(f"⚔️  Attack Scenarios: {len(attack_scenarios)}")
            
            self.module2_results = module2_result
            return module2_result
            
        except Exception as e:
            logger.error(f"❌ Module 2 failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    async def _verify_vulnerabilities(self, vulns: Dict, target: str, framework: AttackFramework) -> List[Dict]:
        """Verify vulnerabilities using attack framework."""
        verified = []
        
        for severity, count in vulns.items():
            if count > 0:
                logger.info(f"  🔍 Verifying {severity} vulnerabilities...")
                
                # Create verification plan
                plan = await framework.plan_attack(
                    target_address=target,
                    chain='ethereum',
                    vulnerability_types=[severity],
                    value_eth=1.0
                )
                
                if plan['feasibility_score'] > 0.3:  # Minimum feasibility threshold
                    verified.append({
                        'severity': severity,
                        'count': count,
                        'feasibility_score': plan['feasibility_score'],
                        'attack_methods': plan['recommended_methods'],
                        'target': target
                    })
        
        return verified
    
    async def _screen_related_contracts(self, contracts: List[Dict], framework: AttackFramework) -> List[Dict]:
        """Screen related contracts for vulnerabilities."""
        vuln_contracts = []
        
        for contract in contracts[:5]:  # Limit to first 5 for testing
            logger.info(f"  🔍 Screening related contract: {contract['address']}")
            
            try:
                # Quick vulnerability check
                plan = await framework.plan_attack(
                    target_address=contract['address'],
                    chain='ethereum',
                    vulnerability_types=['reentrancy', 'flashloan', 'access_control'],
                    value_eth=1.0
                )
                
                if plan['feasibility_score'] > 0.3:
                    vuln_contracts.append({
                        'address': contract['address'],
                        'type': contract['type'],
                        'interaction_count': contract['interaction_count'],
                        'feasibility_score': plan['feasibility_score'],
                        'vulnerability_types': plan['recommended_methods']
                    })
                    
            except Exception as e:
                logger.warning(f"    ⚠️  Error screening {contract['address']}: {e}")
        
        return vuln_contracts
    
    def _prepare_attack_scenarios(self, main_vulns: List[Dict], related_vulns: List[Dict], dex_relations: List[Dict]) -> List[Dict]:
        """Prepare attack scenarios based on verified findings."""
        scenarios = []
        
        # Main contract attack scenarios
        for vuln in main_vulns:
            for method in vuln['attack_methods']:
                scenarios.append({
                    'target': vuln['target'],
                    'type': 'main_contract',
                    'vulnerability': vuln['severity'],
                    'attack_method': method,
                    'feasibility_score': vuln['feasibility_score'],
                    'priority': 'high' if vuln['severity'] in ['critical', 'high'] else 'medium'
                })
        
        # Related contract attack scenarios
        for contract in related_vulns:
            for vuln_type in contract['vulnerability_types']:
                scenarios.append({
                    'target': contract['address'],
                    'type': 'related_contract',
                    'vulnerability': vuln_type,
                    'attack_method': vuln_type,
                    'feasibility_score': contract['feasibility_score'],
                    'priority': 'medium'
                })
        
        # DEX-based attack scenarios
        for dex in dex_relations:
            if dex['liquidity_usd'] > 10000:  # Only consider DEX with significant liquidity
                scenarios.append({
                    'target': dex['address'],
                    'type': 'dex_contract',
                    'vulnerability': 'flashloan',
                    'attack_method': 'flashloan',
                    'feasibility_score': 0.8,  # High feasibility for DEX with liquidity
                    'priority': 'high',
                    'liquidity_usd': dex['liquidity_usd']
                })
        
        # Sort by priority and feasibility
        priority_order = {'high': 3, 'medium': 2, 'low': 1}
        scenarios.sort(key=lambda x: (priority_order.get(x['priority'], 0), x['feasibility_score']), reverse=True)
        
        return scenarios
    
    async def test_module3_attack_execution(self) -> Dict[str, Any]:
        """
        Module 3: Attack Execution with Data from Module 1&2
        
        - Execute attacks based on processed data from Module 2
        - Run attacks in fork environment (safe testing)
        - Validate attack results and generate reports
        - Test mainnet preparation with real evidence
        """
        logger.info("=" * 70)
        logger.info("⚔️  MODULE 3: ATTACK EXECUTION WITH DATA FROM MODULE 1&2")
        logger.info("=" * 70)
        
        if not self.module2_results.get('success'):
            raise Exception("Module 2 must complete successfully before Module 3")
        
        try:
            logger.info("🚀 Starting attack execution...")
            
            # Initialize attack framework
            rpc_url = self.env_config.get('TENDERLY_RPC')
            etherscan_key = self.env_config.get('ETHERSCAN_API_KEY')
            private_key = self.env_config.get('PRIVATE_KEY')
            attacker_address = self.env_config.get('ATTACKER_ADDRESS')
            
            attack_framework = AttackFramework()
            
            # Execute top 3 attack scenarios (fork environment only)
            attack_results = []
            scenarios_to_test = self.module2_results['attack_scenarios'][:3]
            
            logger.info(f"🎯 Testing {len(scenarios_to_test)} attack scenarios...")
            
            for i, scenario in enumerate(scenarios_to_test):
                logger.info(f"\n  {i+1}. Testing {scenario['attack_method']} on {scenario['target']}")
                
                try:
                    # Prepare attack
                    attack_id = await attack_framework.prepare_attack(
                        target_address=scenario['target'],
                        chain='ethereum',
                        attack_mode=scenario['attack_method'],
                        environment='fork',
                        value_eth=0.1  # Small amount for testing
                    )
                    
                    # Execute attack in fork environment (dry run)
                    execution_result = await attack_framework.execute_attack(
                        attack_id=attack_id,
                        dry_run=True  # Safe simulation only
                    )
                    
                    attack_results.append({
                        'scenario': scenario,
                        'attack_id': attack_id,
                        'execution_success': execution_result,
                        'execution_time': 0  # Will be calculated
                    })
                    
                    status = "✅ Success" if execution_result else "❌ Failed"
                    logger.info(f"     {status} - Attack ID: {attack_id}")
                    
                except Exception as e:
                    logger.error(f"     ❌ Attack failed: {e}")
                    attack_results.append({
                        'scenario': scenario,
                        'attack_id': None,
                        'execution_success': False,
                        'error': str(e)
                    })
            
            # Generate comprehensive report
            logger.info("📊 Generating attack report...")
            report_path = f"test_output/{self.test_session_id}/module3/attack_report.json"
            
            module3_result = {
                'success': True,
                'attack_results': attack_results,
                'successful_attacks': len([r for r in attack_results if r['execution_success']]),
                'total_scenarios_tested': len(scenarios_to_test),
                'report_path': report_path,
                'execution_time': 0  # Will be calculated
            }
            
            # Save report
            self._save_attack_report(module3_result, report_path)
            
            logger.info(f"✅ Module 3 completed")
            logger.info(f"🎯 Successful Attacks: {module3_result['successful_attacks']}/{module3_result['total_scenarios_tested']}")
            logger.info(f"📄 Report saved to: {report_path}")
            
            self.module3_results = module3_result
            return module3_result
            
        except Exception as e:
            logger.error(f"❌ Module 3 failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _save_attack_report(self, result: Dict, report_path: str):
        """Save attack execution report."""
        try:
            Path(report_path).parent.mkdir(parents=True, exist_ok=True)
            
            report = {
                'session_id': self.test_session_id,
                'timestamp': datetime.now().isoformat(),
                'module1_results': self.module1_results,
                'module2_results': self.module2_results,
                'module3_results': {
                    'success': result['success'],
                    'successful_attacks': result['successful_attacks'],
                    'total_scenarios_tested': result['total_scenarios_tested'],
                    'attack_results': result['attack_results']
                },
                'summary': {
                    'total_execution_time': (
                        self.module1_results.get('execution_time', 0) +
                        self.module2_results.get('processing_time', 0) +
                        result.get('execution_time', 0)
                    ),
                    'main_contract_vulnerabilities': len(self.module1_results.get('main_contract_vulnerabilities', {})),
                    'ecosystem_contracts_discovered': len(self.module1_results.get('related_contracts', [])),
                    'attack_scenarios_prepared': len(self.module2_results.get('attack_scenarios', [])),
                    'successful_attacks': result['successful_attacks']
                }
            }
            
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
                
        except Exception as e:
            logger.error(f"Error saving report: {e}")
    
    async def run_complete_workflow_test(self) -> Dict[str, Any]:
        """Run complete 3-module workflow test."""
        logger.info("🚀 STARTING COMPLETE 3-MODULE WORKFLOW TEST")
        logger.info("=" * 70)
        logger.info(f"Session ID: {self.test_session_id}")
        logger.info(f"Target Contract: {self.env_config.get('TARGET_CONTRACT')}")
        logger.info("=" * 70)
        
        start_time = datetime.now()
        
        try:
            # Create output directory
            output_dir = Path(f"test_output/{self.test_session_id}")
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Run Module 1
            module1_start = datetime.now()
            module1_result = await self.test_module1_screening_ecosystem()
            module1_time = (datetime.now() - module1_start).total_seconds()
            if 'execution_time' in module1_result:
                module1_result['execution_time'] = module1_time
            
            if not module1_result['success']:
                raise Exception("Module 1 failed - aborting workflow")
            
            # Run Module 2
            module2_start = datetime.now()
            module2_result = await self.test_module2_verification_processing()
            module2_time = (datetime.now() - module2_start).total_seconds()
            module2_result['processing_time'] = module2_time
            
            if not module2_result['success']:
                raise Exception("Module 2 failed - aborting workflow")
            
            # Run Module 3
            module3_start = datetime.now()
            module3_result = await self.test_module3_attack_execution()
            module3_time = (datetime.now() - module3_start).total_seconds()
            module3_result['execution_time'] = module3_time
            
            # Generate final summary
            total_time = (datetime.now() - start_time).total_seconds()
            
            final_result = {
                'session_id': self.test_session_id,
                'success': all([
                    module1_result['success'],
                    module2_result['success'], 
                    module3_result['success']
                ]),
                'module1': module1_result,
                'module2': module2_result,
                'module3': module3_result,
                'total_execution_time': total_time,
                'target_contract': self.env_config.get('TARGET_CONTRACT'),
                'timestamp': datetime.now().isoformat()
            }
            
            # Save final workflow report
            final_report_path = output_dir / "complete_workflow_report.json"
            with open(final_report_path, 'w') as f:
                json.dump(final_result, f, indent=2, default=str)
            
            # Print summary
            self._print_workflow_summary(final_result)
            
            return final_result
            
        except Exception as e:
            logger.error(f"❌ Workflow test failed: {str(e)}")
            return {
                'session_id': self.test_session_id,
                'success': False,
                'error': str(e),
                'total_execution_time': (datetime.now() - start_time).total_seconds()
            }
    
    def _print_workflow_summary(self, result: Dict):
        """Print comprehensive workflow summary."""
        logger.info("\n" + "=" * 70)
        logger.info("🎉 COMPLETE WORKFLOW TEST SUMMARY")
        logger.info("=" * 70)
        
        logger.info(f"🆔 Session ID: {result['session_id']}")
        logger.info(f"🎯 Target Contract: {result['target_contract']}")
        logger.info(f"⏱️  Total Time: {result['total_execution_time']:.2f}s")
        
        # Module 1 Summary
        m1 = result['module1']
        logger.info(f"\n🔍 MODULE 1 - Screening & Ecosystem:")
        logger.info(f"   ✅ Status: {'SUCCESS' if m1['success'] else 'FAILED'}")
        logger.info(f"   📊 Main Contract Vulns: {len(m1['main_contract_vulnerabilities'])} types")
        logger.info(f"   🕸️  DEX Relations: {len(m1['dex_relations'])}")
        logger.info(f"   🔗 Related Contracts: {len(m1['related_contracts'])}")
        logger.info(f"   ⏱️  Execution Time: {m1.get('execution_time', 0):.2f}s")
        
        # Module 2 Summary
        m2 = result['module2']
        logger.info(f"\n🔬 MODULE 2 - Verification & Processing:")
        logger.info(f"   ✅ Status: {'SUCCESS' if m2['success'] else 'FAILED'}")
        logger.info(f"   ✅ Verified Main Vulns: {len(m2['verified_main_contract_vulns'])}")
        logger.info(f"   📋 Related Contracts with Vulns: {len(m2['related_contract_vulns'])}")
        logger.info(f"   ⚔️  Attack Scenarios: {len(m2['attack_scenarios'])}")
        logger.info(f"   ⏱️  Processing Time: {m2.get('processing_time', 0):.2f}s")
        
        # Module 3 Summary
        m3 = result['module3']
        logger.info(f"\n⚔️  MODULE 3 - Attack Execution:")
        logger.info(f"   ✅ Status: {'SUCCESS' if m3['success'] else 'FAILED'}")
        logger.info(f"   🎯 Successful Attacks: {m3['successful_attacks']}/{m3['total_scenarios_tested']}")
        logger.info(f"   📄 Report: {m3.get('report_path', 'N/A')}")
        logger.info(f"   ⏱️  Execution Time: {m3.get('execution_time', 0):.2f}s")
        
        # Overall Status
        status = "🎉 COMPLETE SUCCESS" if result['success'] else "❌ FAILED"
        logger.info(f"\n🏆 OVERALL STATUS: {status}")
        
        if result['success']:
            logger.info(f"\n📁 Output Directory: test_output/{result['session_id']}")
            logger.info(f"📄 Final Report: test_output/{result['session_id']}/complete_workflow_report.json")

async def main():
    """Main test execution function."""
    try:
        # Initialize and run workflow test
        workflow_test = ModuleWorkflowTest()
        result = await workflow_test.run_complete_workflow_test()
        
        if result['success']:
            logger.info("\n🎉 All 3 modules working correctly!")
            sys.exit(0)
        else:
            logger.error(f"\n❌ Workflow test failed: {result.get('error', 'Unknown error')}")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"❌ Test execution error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())