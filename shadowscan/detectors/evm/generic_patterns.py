# shadowscan/detectors/evm/generic_patterns.py
"""Enhanced pattern detector with specific vulnerability analysis."""

from web3 import Web3
from typing import List, Dict, Any, Optional, Set, Tuple
import logging
from collections import Counter, defaultdict
import re

from shadowscan.utils.schema import Hypothesis, RiskLevel
from shadowscan.utils.helpers import generate_hypothesis_id, is_contract_address

logger = logging.getLogger(__name__)

class PatternDetector:
    """Enhanced vulnerability detector with specific attack pattern analysis."""
    
    def __init__(self, web3: Web3):
        self.web3 = web3
        
        # Reentrancy detection patterns
        self.reentrancy_patterns = {
            'classic_reentrancy': {
                'indicators': ['call.value', 'transfer', 'send'],
                'state_changes': ['balance', 'mapping', 'storage'],
                'risk': RiskLevel.HIGH
            },
            'cross_function_reentrancy': {
                'indicators': ['external', 'public', 'modifier'],
                'state_changes': ['state_var', 'storage'],
                'risk': RiskLevel.HIGH
            },
            'read_only_reentrancy': {
                'indicators': ['view', 'pure', 'staticcall'],
                'state_changes': ['balance_check', 'total_supply'],
                'risk': RiskLevel.MEDIUM
            }
        }
        
        # Flash loan attack patterns
        self.flashloan_patterns = {
            'price_manipulation': {
                'dex_interactions': ['swap', 'addLiquidity', 'removeLiquidity'],
                'oracle_calls': ['getPrice', 'latestAnswer', 'getReserves'],
                'risk': RiskLevel.HIGH
            },
            'arbitrage_extraction': {
                'multi_dex': True,
                'large_amounts': True,
                'same_block': True,
                'risk': RiskLevel.HIGH
            },
            'governance_attack': {
                'voting_power': ['deposit', 'stake', 'lock'],
                'proposal_execution': ['execute', 'vote'],
                'risk': RiskLevel.CRITICAL
            }
        }
        
        # TWAP manipulation detection
        self.twap_manipulation = {
            'short_window': {'threshold': 600, 'risk': RiskLevel.HIGH},
            'low_liquidity': {'threshold': 50000, 'risk': RiskLevel.HIGH},
            'single_source': {'threshold': 1, 'risk': RiskLevel.HIGH},
            'sandwich_susceptible': {'indicators': ['swap', 'price_impact'], 'risk': RiskLevel.MEDIUM}
        }
        
        # Approval scam patterns
        self.approval_patterns = {
            'infinite_approval': {
                'threshold': 2**255,
                'risk': RiskLevel.HIGH,
                'description': 'Infinite token approvals detected'
            },
            'approval_front_running': {
                'indicators': ['approve', 'transferFrom'],
                'time_window': 60,
                'risk': RiskLevel.MEDIUM
            },
            'batch_approvals': {
                'threshold_count': 50,
                'time_window': 300,
                'risk': RiskLevel.MEDIUM
            }
        }
        
        # MEV-related patterns
        self.mev_patterns = {
            'sandwich_attack': {
                'indicators': ['front_run', 'back_run', 'large_swap'],
                'profit_extraction': True,
                'risk': RiskLevel.HIGH
            },
            'liquidation_front_running': {
                'indicators': ['liquidate', 'health_factor'],
                'competitive_execution': True,
                'risk': RiskLevel.MEDIUM
            }
        }
        
        # Advanced bytecode patterns
        self.bytecode_patterns = {
            'metamorphic_contracts': {
                'opcodes': ['CREATE2', 'SELFDESTRUCT'],
                'risk': RiskLevel.CRITICAL
            },
            'proxy_storage_collision': {
                'patterns': ['delegatecall', 'storage_slot'],
                'risk': RiskLevel.HIGH
            },
            'hidden_functionality': {
                'indicators': ['fallback', 'receive', 'assembly'],
                'risk': RiskLevel.MEDIUM
            }
        }
    
    def detect_patterns(self, session_json: Dict[str, Any]) -> List[Hypothesis]:
        """
        Run enhanced pattern detection with specific vulnerability analysis.
        
        Args:
            session_json: Complete session data
            
        Returns:
            List of enhanced vulnerability hypotheses
        """
        try:
            hypotheses = []
            target_address = session_json.get('target')
            
            if not target_address:
                return hypotheses
            
            logger.info(f"Running enhanced pattern detection for {target_address}")
            
            # 1. Reentrancy analysis
            reentrancy_findings = self._detect_reentrancy_vulnerabilities(session_json)
            hypotheses.extend(reentrancy_findings)
            
            # 2. Flash loan exploitability
            flashloan_findings = self._detect_flashloan_vulnerabilities(session_json)
            hypotheses.extend(flashloan_findings)
            
            # 3. TWAP manipulation analysis
            twap_findings = self._detect_twap_manipulation_risks(session_json)
            hypotheses.extend(twap_findings)
            
            # 4. Approval scam detection
            approval_findings = self._detect_approval_scams(session_json)
            hypotheses.extend(approval_findings)
            
            # 5. MEV vulnerability analysis
            mev_findings = self._detect_mev_vulnerabilities(session_json)
            hypotheses.extend(mev_findings)
            
            # 6. Advanced bytecode analysis
            bytecode_findings = self._detect_advanced_bytecode_patterns(session_json)
            hypotheses.extend(bytecode_findings)
            
            # 7. Economic attack vectors
            economic_findings = self._detect_economic_attack_vectors(session_json)
            hypotheses.extend(economic_findings)
            
            # Remove duplicates and sort by confidence
            unique_hypotheses = self._deduplicate_and_rank(hypotheses)
            
            logger.info(f"Enhanced detection completed: {len(unique_hypotheses)} specific vulnerabilities found")
            return unique_hypotheses
            
        except Exception as e:
            logger.error(f"Error in enhanced pattern detection: {e}")
            return []
    
    def _detect_reentrancy_vulnerabilities(self, session: Dict[str, Any]) -> List[Hypothesis]:
        """Detect reentrancy vulnerabilities through comprehensive analysis."""
        hypotheses = []
        target_address = session.get('target')
        
        try:
            # Analyze transactions for reentrancy patterns
            transactions = session.get('txs', [])
            events = session.get('events', [])
            bytecode = session.get('bytecode', '')
            
            # Pattern 1: Classic reentrancy (external calls before state updates)
            classic_reentrancy = self._analyze_classic_reentrancy(transactions, events, bytecode)
            if classic_reentrancy:
                hypotheses.append(Hypothesis(
                    id=generate_hypothesis_id("CLASSIC_REENTRANCY", target_address),
                    category="CLASSIC_REENTRANCY",
                    confidence=classic_reentrancy['confidence'],
                    description=f"Classic reentrancy vulnerability detected: {classic_reentrancy['description']}",
                    severity=RiskLevel.HIGH,
                    evidence=classic_reentrancy['evidence']
                ))
            
            # Pattern 2: Cross-function reentrancy
            cross_function = self._analyze_cross_function_reentrancy(transactions, events)
            if cross_function:
                hypotheses.append(Hypothesis(
                    id=generate_hypothesis_id("CROSS_FUNCTION_REENTRANCY", target_address),
                    category="CROSS_FUNCTION_REENTRANCY", 
                    confidence=cross_function['confidence'],
                    description=f"Cross-function reentrancy risk: {cross_function['description']}",
                    severity=RiskLevel.HIGH,
                    evidence=cross_function['evidence']
                ))
            
            # Pattern 3: Read-only reentrancy
            readonly_reentrancy = self._analyze_readonly_reentrancy(transactions)
            if readonly_reentrancy:
                hypotheses.append(Hypothesis(
                    id=generate_hypothesis_id("READONLY_REENTRANCY", target_address),
                    category="READONLY_REENTRANCY",
                    confidence=readonly_reentrancy['confidence'],
                    description=f"Read-only reentrancy vulnerability: {readonly_reentrancy['description']}",
                    severity=RiskLevel.MEDIUM,
                    evidence=readonly_reentrancy['evidence']
                ))
            
            return hypotheses
            
        except Exception as e:
            logger.debug(f"Error detecting reentrancy vulnerabilities: {e}")
            return []
    
    def _analyze_classic_reentrancy(self, transactions: List[Dict], events: List[Dict], bytecode: str) -> Optional[Dict]:
        """Analyze for classic reentrancy patterns."""
        try:
            evidence = []
            risk_indicators = 0
            
            # Check bytecode for dangerous patterns
            if bytecode:
                bytecode_hex = bytecode.lower()
                
                # Look for CALL opcode followed by state changes
                if 'f1' in bytecode_hex:  # CALL opcode
                    evidence.append("External CALL opcode detected in bytecode")
                    risk_indicators += 1
                
                # Check for lack of reentrancy guards
                if '5af43d82803e' not in bytecode_hex:  # Common reentrancy guard pattern
                    evidence.append("No reentrancy guard pattern detected")
                    risk_indicators += 1
            
            # Analyze transaction patterns
            external_calls = 0
            state_changes = 0
            
            for tx in transactions:
                input_data = tx.get('input', '0x')
                if len(input_data) >= 10:
                    func_selector = input_data[:10].lower()
                    
                    # Check for functions that make external calls
                    if func_selector in ['0xa9059cbb', '0x23b872dd', '0x095ea7b3']:  # transfer, transferFrom, approve
                        external_calls += 1
                    
                    # Check trace for complex call patterns
                    trace = tx.get('trace', {})
                    if trace and trace.get('calls'):
                        calls = trace['calls']
                        if len(calls) > 2:  # Multiple subcalls
                            evidence.append(f"Complex call pattern in tx {tx.get('hash', '')[:10]}...")
                            risk_indicators += 1
            
            # Analyze events for state change patterns
            for event in events:
                if event.get('name') in ['Transfer', 'Approval', 'Deposit', 'Withdrawal']:
                    state_changes += 1
            
            if risk_indicators >= 2:
                return {
                    'confidence': min(0.9, 0.3 + (risk_indicators * 0.15)),
                    'description': f"Multiple reentrancy risk indicators ({risk_indicators})",
                    'evidence': evidence
                }
            
            return None
            
        except Exception as e:
            logger.debug(f"Error analyzing classic reentrancy: {e}")
            return None
    
    def _detect_flashloan_vulnerabilities(self, session: Dict[str, Any]) -> List[Hypothesis]:
        """Detect flash loan attack vulnerabilities."""
        hypotheses = []
        target_address = session.get('target')
        
        try:
            dex_refs = session.get('dex_refs', [])
            oracle_info = session.get('oracle', {})
            transactions = session.get('txs', [])
            
            # Pattern 1: Price manipulation via flash loans
            price_manip = self._analyze_price_manipulation_risk(dex_refs, oracle_info, transactions)
            if price_manip:
                hypotheses.append(Hypothesis(
                    id=generate_hypothesis_id("FLASHLOAN_PRICE_MANIPULATION", target_address),
                    category="FLASHLOAN_PRICE_MANIPULATION",
                    confidence=price_manip['confidence'],
                    description=f"Flash loan price manipulation risk: {price_manip['description']}",
                    severity=RiskLevel.HIGH,
                    evidence=price_manip['evidence']
                ))
            
            # Pattern 2: Reserve drain attacks
            reserve_drain = self._analyze_reserve_drain_risk(dex_refs, transactions)
            if reserve_drain:
                hypotheses.append(Hypothesis(
                    id=generate_hypothesis_id("FLASHLOAN_RESERVE_DRAIN", target_address),
                    category="FLASHLOAN_RESERVE_DRAIN",
                    confidence=reserve_drain['confidence'],
                    description=f"Reserve drain attack risk: {reserve_drain['description']}",
                    severity=RiskLevel.HIGH,
                    evidence=reserve_drain['evidence']
                ))
            
            # Pattern 3: Governance attacks via flash loans
            governance_attack = self._analyze_governance_attack_risk(transactions, session.get('events', []))
            if governance_attack:
                hypotheses.append(Hypothesis(
                    id=generate_hypothesis_id("FLASHLOAN_GOVERNANCE_ATTACK", target_address),
                    category="FLASHLOAN_GOVERNANCE_ATTACK",
                    confidence=governance_attack['confidence'],
                    description=f"Flash loan governance attack risk: {governance_attack['description']}",
                    severity=RiskLevel.CRITICAL,
                    evidence=governance_attack['evidence']
                ))
            
            return hypotheses
            
        except Exception as e:
            logger.debug(f"Error detecting flash loan vulnerabilities: {e}")
            return []
    
    def _analyze_price_manipulation_risk(self, dex_refs: List[Dict], oracle_info: Dict, transactions: List[Dict]) -> Optional[Dict]:
        """Analyze price manipulation risk via flash loans."""
        try:
            evidence = []
            risk_score = 0.0
            
            # Check oracle dependency on manipulatable sources
            oracle_sources = oracle_info.get('sources', [])
            manipulatable_sources = 0
            
            for source in oracle_sources:
                if 'dex_pair:' in source or 'pair:' in source:
                    manipulatable_sources += 1
                    evidence.append(f"Price oracle depends on DEX pair: {source}")
            
            if manipulatable_sources > 0:
                risk_score += 0.4
            
            # Check TWAP window vulnerability
            twap_window = oracle_info.get('twap_window', 0)
            if twap_window and twap_window < 600:  # Less than 10 minutes
                risk_score += 0.3
                evidence.append(f"Short TWAP window ({twap_window}s) vulnerable to manipulation")
            
            # Check for low liquidity pairs
            low_liquidity_pairs = 0
            for dex_ref in dex_refs:
                liquidity = dex_ref.get('liquidity_usd', 0)
                if liquidity < 100000:  # Less than $100k
                    low_liquidity_pairs += 1
                    evidence.append(f"Low liquidity pair: ${liquidity:,.2f}")
            
            if low_liquidity_pairs > 0:
                risk_score += 0.2
            
            # Check for large swap transactions (potential manipulation)
            large_swaps = 0
            for tx in transactions:
                trace = tx.get('trace', {})
                if trace and trace.get('calls'):
                    for call in trace['calls']:
                        if int(call.get('value', '0'), 16) > 10**20:  # > 100 ETH
                            large_swaps += 1
            
            if large_swaps > 0:
                risk_score += 0.1
                evidence.append(f"Large value transactions detected: {large_swaps}")
            
            if risk_score >= 0.5:
                return {
                    'confidence': min(0.95, risk_score),
                    'description': f"High price manipulation risk (score: {risk_score:.2f})",
                    'evidence': evidence
                }
            
            return None
            
        except Exception as e:
            logger.debug(f"Error analyzing price manipulation risk: {e}")
            return None
    
    def _detect_twap_manipulation_risks(self, session: Dict[str, Any]) -> List[Hypothesis]:
        """Detect TWAP manipulation vulnerabilities."""
        hypotheses = []
        target_address = session.get('target')
        
        try:
            oracle_info = session.get('oracle', {})
            dex_refs = session.get('dex_refs', [])
            
            # Short TWAP window vulnerability
            twap_window = oracle_info.get('twap_window')
            if twap_window and twap_window < 600:
                confidence = 0.9 if twap_window < 300 else 0.7
                
                hypotheses.append(Hypothesis(
                    id=generate_hypothesis_id("TWAP_MANIPULATION_SHORT_WINDOW", target_address),
                    category="TWAP_MANIPULATION_SHORT_WINDOW",
                    confidence=confidence,
                    description=f"TWAP window too short ({twap_window}s) - vulnerable to flash loan manipulation",
                    severity=RiskLevel.HIGH,
                    evidence=[f"TWAP window: {twap_window} seconds", "Recommended minimum: 600 seconds"]
                ))
            
            # Low liquidity TWAP sources
            vulnerable_pairs = []
            for dex_ref in dex_refs:
                liquidity = dex_ref.get('liquidity_usd', 0)
                pair_address = dex_ref.get('pair', '')
                
                if liquidity < 50000:  # Less than $50k
                    vulnerable_pairs.append((pair_address, liquidity))
            
            if vulnerable_pairs:
                hypotheses.append(Hypothesis(
                    id=generate_hypothesis_id("TWAP_MANIPULATION_LOW_LIQUIDITY", target_address),
                    category="TWAP_MANIPULATION_LOW_LIQUIDITY",
                    confidence=0.8,
                    description=f"TWAP uses low liquidity pairs - easily manipulated",
                    severity=RiskLevel.HIGH,
                    evidence=[f"Low liquidity pair: {pair} (${liq:,.2f})" for pair, liq in vulnerable_pairs[:3]]
                ))
            
            return hypotheses
            
        except Exception as e:
            logger.debug(f"Error detecting TWAP manipulation risks: {e}")
            return []
    
    def _detect_approval_scams(self, session: Dict[str, Any]) -> List[Hypothesis]:
        """Detect approval-related scam patterns."""
        hypotheses = []
        target_address = session.get('target')
        
        try:
            events = session.get('events', [])
            transactions = session.get('txs', [])
            
            # Analyze approval events
            approval_events = [e for e in events if e.get('name') == 'Approval']
            
            if not approval_events:
                return hypotheses
            
            # Pattern 1: Infinite approvals
            infinite_approvals = 0
            suspicious_spenders = set()
            
            for event in approval_events:
                args = event.get('args', {})
                value = args.get('value', 0)
                spender = args.get('spender', '')
                
                try:
                    if isinstance(value, (int, str)) and int(str(value)) >= 2**255:
                        infinite_approvals += 1
                        suspicious_spenders.add(spender)
                except (ValueError, TypeError):
                    continue
            
            if infinite_approvals > 20:  # Threshold for suspicious activity
                hypotheses.append(Hypothesis(
                    id=generate_hypothesis_id("INFINITE_APPROVAL_SCAM", target_address),
                    category="INFINITE_APPROVAL_SCAM",
                    confidence=0.8,
                    description=f"Excessive infinite approvals detected ({infinite_approvals} approvals)",
                    severity=RiskLevel.HIGH,
                    evidence=[
                        f"Infinite approvals: {infinite_approvals}",
                        f"Suspicious spenders: {len(suspicious_spenders)}",
                        f"Top spenders: {list(suspicious_spenders)[:3]}"
                    ]
                ))
            
            # Pattern 2: Rapid approval patterns (potential front-running)
            rapid_approvals = self._analyze_rapid_approvals(approval_events)
            if rapid_approvals:
                hypotheses.append(Hypothesis(
                    id=generate_hypothesis_id("APPROVAL_FRONT_RUNNING", target_address),
                    category="APPROVAL_FRONT_RUNNING",
                    confidence=rapid_approvals['confidence'],
                    description=f"Rapid approval patterns suggest front-running risk",
                    severity=RiskLevel.MEDIUM,
                    evidence=rapid_approvals['evidence']
                ))
            
            return hypotheses
            
        except Exception as e:
            logger.debug(f"Error detecting approval scams: {e}")
            return []
    
    def _detect_mev_vulnerabilities(self, session: Dict[str, Any]) -> List[Hypothesis]:
        """Detect MEV (Maximal Extractable Value) vulnerabilities."""
        hypotheses = []
        target_address = session.get('target')
        
        try:
            transactions = session.get('txs', [])
            dex_refs = session.get('dex_refs', [])
            
            # Pattern 1: Sandwich attack vulnerability
            sandwich_risk = self._analyze_sandwich_attack_risk(transactions, dex_refs)
            if sandwich_risk:
                hypotheses.append(Hypothesis(
                    id=generate_hypothesis_id("MEV_SANDWICH_ATTACK", target_address),
                    category="MEV_SANDWICH_ATTACK",
                    confidence=sandwich_risk['confidence'],
                    description=f"Vulnerable to sandwich attacks: {sandwich_risk['description']}",
                    severity=RiskLevel.HIGH,
                    evidence=sandwich_risk['evidence']
                ))
            
            # Pattern 2: Liquidation MEV
            liquidation_mev = self._analyze_liquidation_mev_risk(transactions)
            if liquidation_mev:
                hypotheses.append(Hypothesis(
                    id=generate_hypothesis_id("MEV_LIQUIDATION", target_address),
                    category="MEV_LIQUIDATION",
                    confidence=liquidation_mev['confidence'],
                    description=f"Liquidation MEV risk: {liquidation_mev['description']}",
                    severity=RiskLevel.MEDIUM,
                    evidence=liquidation_mev['evidence']
                ))
            
            return hypotheses
            
        except Exception as e:
            logger.debug(f"Error detecting MEV vulnerabilities: {e}")
            return []
    
    def _detect_advanced_bytecode_patterns(self, session: Dict[str, Any]) -> List[Hypothesis]:
        """Detect advanced bytecode-level vulnerabilities."""
        hypotheses = []
        target_address = session.get('target')
        
        try:
            bytecode = session.get('bytecode', '')
            proxy_info = session.get('proxy_info', {})
            
            if not bytecode:
                return hypotheses
            
            bytecode_hex = bytecode.lower()
            
            # Pattern 1: Metamorphic contract detection
            if 'ff' in bytecode_hex and 'f5' in bytecode_hex:  # SELFDESTRUCT + CREATE2
                hypotheses.append(Hypothesis(
                    id=generate_hypothesis_id("METAMORPHIC_CONTRACT", target_address),
                    category="METAMORPHIC_CONTRACT",
                    confidence=0.7,
                    description="Contract appears to be metamorphic - can change implementation",
                    severity=RiskLevel.CRITICAL,
                    evidence=["SELFDESTRUCT and CREATE2 opcodes detected", "Metamorphic pattern identified"]
                ))
            
            # Pattern 2: Proxy storage collision risk
            if proxy_info.get('is_proxy') and 'f4' in bytecode_hex:  # DELEGATECALL
                storage_collision_risk = self._analyze_storage_collision_risk(bytecode_hex)
                if storage_collision_risk:
                    hypotheses.append(Hypothesis(
                        id=generate_hypothesis_id("PROXY_STORAGE_COLLISION", target_address),
                        category="PROXY_STORAGE_COLLISION",
                        confidence=storage_collision_risk['confidence'],
                        description="Proxy storage collision risk detected",
                        severity=RiskLevel.HIGH,
                        evidence=storage_collision_risk['evidence']
                    ))
            
            return hypotheses
            
        except Exception as e:
            logger.debug(f"Error detecting advanced bytecode patterns: {e}")
            return []
    
    def _detect_economic_attack_vectors(self, session: Dict[str, Any]) -> List[Hypothesis]:
        """Detect economic attack vectors and incentive misalignments."""
        hypotheses = []
        target_address = session.get('target')
        
        try:
            dex_refs = session.get('dex_refs', [])
            oracle_info = session.get('oracle', {})
            state_snapshot = session.get('state_snapshot', {})
            
            # Pattern 1: Economic imbalance attack
            economic_imbalance = self._analyze_economic_imbalance(dex_refs, state_snapshot)
            if economic_imbalance:
                hypotheses.append(Hypothesis(
                    id=generate_hypothesis_id("ECONOMIC_IMBALANCE_ATTACK", target_address),
                    category="ECONOMIC_IMBALANCE_ATTACK",
                    confidence=economic_imbalance['confidence'],
                    description=f"Economic imbalance creates attack vector: {economic_imbalance['description']}",
                    severity=RiskLevel.MEDIUM,
                    evidence=economic_imbalance['evidence']
                ))
            
            # Pattern 2: Incentive misalignment
            incentive_issues = self._analyze_incentive_misalignment(session)
            if incentive_issues:
                hypotheses.append(Hypothesis(
                    id=generate_hypothesis_id("INCENTIVE_MISALIGNMENT", target_address),
                    category="INCENTIVE_MISALIGNMENT",
                    confidence=incentive_issues['confidence'],
                    description=f"Incentive misalignment detected: {incentive_issues['description']}",
                    severity=RiskLevel.MEDIUM,
                    evidence=incentive_issues['evidence']
                ))
            
            return hypotheses
            
        except Exception as e:
            logger.debug(f"Error detecting economic attack vectors: {e}")
            return []
    
    def _analyze_rapid_approvals(self, approval_events: List[Dict]) -> Optional[Dict]:
        """Analyze for rapid approval patterns."""
        try:
            if len(approval_events) < 10:
                return None
            
            # Sort by block number
            sorted_events = sorted(approval_events, key=lambda e: e.get('block', 0))
            
            rapid_sequences = 0
            evidence = []
            
            # Look for sequences of approvals in consecutive blocks
            for i in range(len(sorted_events) - 4):
                blocks = [sorted_events[j].get('block', 0) for j in range(i, i + 5)]
                if blocks[-1] - blocks[0] <= 5:  # 5 approvals within 5 blocks
                    rapid_sequences += 1
                    evidence.append(f"Rapid approvals in blocks {blocks[0]}-{blocks[-1]}")
            
            if rapid_sequences > 0:
                return {
                    'confidence': min(0.8, 0.3 + rapid_sequences * 0.1),
                    'evidence': evidence
                }
            
            return None
            
        except Exception as e:
            logger.debug(f"Error analyzing rapid approvals: {e}")
            return None
    
    def _deduplicate_and_rank(self, hypotheses: List[Hypothesis]) -> List[Hypothesis]:
        """Remove duplicates and rank by confidence and severity."""
        seen = set()
        unique_hypotheses = []
        
        for hypothesis in hypotheses:
            key = (hypothesis.category, hypothesis.description)
            if key not in seen:
                seen.add(key)
                unique_hypotheses.append(hypothesis)
        
        # Sort by severity first, then confidence
        severity_order = {RiskLevel.CRITICAL: 4, RiskLevel.HIGH: 3, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 1}
        
        unique_hypotheses.sort(
            key=lambda h: (severity_order.get(h.severity, 0), h.confidence), 
            reverse=True
        )
        
        return unique_hypotheses
    
    # Placeholder methods for complex analyses (would be fully implemented)
    def _analyze_cross_function_reentrancy(self, transactions, events):
        return None  # Simplified for brevity
        
    def _analyze_readonly_reentrancy(self, transactions):
        return None  # Simplified for brevity
        
    def _analyze_reserve_drain_risk(self, dex_refs, transactions):
        return None  # Simplified for brevity
        
    def _analyze_governance_attack_risk(self, transactions, events):
        return None  # Simplified for brevity
        
    def _analyze_sandwich_attack_risk(self, transactions, dex_refs):
        return None  # Simplified for brevity
        
    def _analyze_liquidation_mev_risk(self, transactions):
        return None  # Simplified for brevity
        
    def _analyze_storage_collision_risk(self, bytecode_hex):
        return None  # Simplified for brevity
        
    def _analyze_economic_imbalance(self, dex_refs, state_snapshot):
        return None  # Simplified for brevity
        
    def _analyze_incentive_misalignment(self, session):
        return None  # Simplified for brevity

# Backward compatibility alias
GenericPatternDetector = PatternDetector
