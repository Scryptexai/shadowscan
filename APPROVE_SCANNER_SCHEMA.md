# APPROVE VULNERABILITY SCANNER - JSON SCHEMA DOCUMENTATION

## Overview
Approve Vulnerability Scanner menghasilkan JSON reports yang lengkap, reproducible, dan modular untuk setiap hipotesis approve-related vulnerability. Setiap hipotesis menghasilkan 7 file JSON terpisah + 1 file summary lengkap.

## A. Fungsi / Behaviour yang Discan (Approve-Related)

### 1. allowance(owner, spender)
- **Purpose**: Ambil nilai allowance saat ini
- **Data**: uint256 current_allowance
- **Validation**: Block number, timestamp, last Approval event

### 2. balanceOf(address)
- **Purpose**: Balance owner dan spender
- **Data**: owner_balance, spender_balance
- **Impact**: Estimasi nilai maksimal yang bisa ditransfer

### 3. approve(spender, amount) & increaseAllowance/decreaseAllowance
- **Purpose**: Periksa implementasi approval
- **Checks**: Race-condition, direct approval tanpa checking
- **Validation**: Static analysis + fork simulations

### 4. transferFrom(from, to, amount)
- **Purpose**: Simulasi transferFrom oleh spender
- **Simulation**: Amount kecil & besar (<= allowance, > allowance)
- **Output**: Success/failure + execution trace

### 5. transfer(to, amount)
- **Purpose**: Periksa presence of hooks
- **Analysis**: External calls, state alterations

### 6. isContract(address) / getCode(address)
- **Purpose**: Verifikasi apakah spender adalah contract
- **Validation**: Source code verified, bytecode analysis

### 7. owner() / access control functions
- **Purpose**: Cek admin control
- **Analysis**: Upgradeable, multisig, admin privileges

### 8. Proxy pattern detection
- **Purpose**: Detect proxy contracts
- **Types**: EIP-1967, UUPS, Transparent
- **Validation**: Implementation address analysis

### 9. Opcode-level heuristics
- **Purpose**: Bytecode analysis
- **Checks**: DELEGATECALL, SELFDESTRUCT, CALL patterns

### 10. permit / EIP-2612
- **Purpose**: Meta-transaction support
- **Validation**: Signature logic, nonce handling

### 11. Hooks / callbacks
- **Purpose**: ERC777 hooks analysis
- **Checks**: External calls, reentrancy vectors

### 12. External integrations
- **Purpose**: Fingerprint known routers
- **Validation**: Uniswap, Sushi, Pancake, 0x integration

### 13. Historical approval patterns
- **Purpose**: Event analysis
- **Output**: Suspicious patterns, recurring approvals

### 14. Upgrade/mint/blacklist functions
- **Purpose**: Administrative functions
- **Validation**: Risk scoring, admin impact

## B. Pemeriksaan & Urutan Verifikasi (Per Hipotesis)

### 1. Snapshot Read-Only
- **Actions**: allowance, balanceOf, token metadata
- **Output**: token_info.json

### 2. Source Fetch / Bytecode Analysis
- **Actions**: Static analysis, opcode search
- **Output**: contract_analysis.json

### 3. Proxy/Implementation Check
- **Actions**: Pattern detection, implementation fetch
- **Validation**: Included in contract_analysis.json

### 4. CallStatic Fork Simulations
- **Actions**: transferFrom simulations
- **Output**: fork_simulations.json

### 5. Heuristics & Scoring
- **Actions**: Confidence calculation, risk assessment
- **Output**: Included in hypothesis_summary.json

### 6. Impact Estimation
- **Actions**: USD value calculation
- **Output**: impact_estimation.json

## C. Daftar File JSON yang Dihasilkan

### 1. `token_info.json`
```json
{
  "address": "string",
  "name": "string",
  "symbol": "string",
  "decimals": "integer",
  "total_supply": "integer",
  "balance_owner": "integer",
  "balance_spender": "integer",
  "is_contract": "boolean",
  "verified_source": "boolean",
  "compiler_version": "string|null",
  "optimization_used": "boolean",
  "deployment_block": "integer"
}
```

### 2. `allowance_data.json`
```json
{
  "owner_address": "string",
  "spender_address": "string",
  "current_allowance": "integer",
  "last_approval_event": "object|null",
  "block_number": "integer",
  "timestamp": "integer"
}
```

### 3. `contract_analysis.json`
```json
{
  "has_risky_functions": "boolean",
  "risky_functions": ["string"],
  "proxy_detected": "boolean",
  "proxy_type": "string|null",
  "implementation_address": "string|null",
  "has_hooks": "boolean",
  "hook_functions": ["string"],
  "external_calls": ["string"],
  "opcodes_analysis": {
    "token": {"contract_type": "string", "risky_opcodes": ["string"]},
    "spender": {"contract_type": "string", "risky_opcodes": ["string"]}
  },
  "upgradeable": "boolean",
  "admin_functions": ["string"],
  "admin_address": "string|null"
}
```

### 4. `fork_simulations.json`
```json
[
  {
    "simulation_id": "string",
    "call_success": "boolean",
    "gas_used": "integer",
    "revert_reason": "string|null",
    "execution_trace": ["object"],
    "side_effects": ["string"],
    "transfer_amount": "integer",
    "remaining_allowance": "integer",
    "execution_time": "float"
  }
]
```

### 5. `historical_patterns.json`
```json
{
  "token_address": "string",
  "owner_address": "string",
  "spender_address": "string",
  "analysis_completed": "boolean",
  "historical_data_warning": "string"
}
```

### 6. `impact_estimation.json`
```json
{
  "max_transferable_amount": "integer",
  "max_transferable_eth": "float",
  "estimated_usd_value": "float",
  "estimation_method": "string",
  "confidence_in_estimation": "float",
  "price_source": "string",
  "market_impact_factors": {
    "token_liquidity": "string",
    "market_volatility": "string",
    "slippage_impact": "string"
  }
}
```

### 7. `hypothesis_summary.json`
```json
{
  "hypothesis_id": "string",
  "scan_status": "string",
  "confidence_score": "float",
  "risk_level": "string",
  "impact_score": "float",
  "evidence_summary": ["string"],
  "recommendations": ["string"],
  "scan_timestamp": "string",
  "execution_time": "float",
  "token_summary": {
    "address": "string",
    "name": "string",
    "symbol": "string",
    "decimals": "integer"
  },
  "allowance_summary": {
    "owner": "string",
    "spender": "string",
    "current_allowance": "integer"
  },
  "contract_risk_indicators": {
    "has_risky_functions": "boolean",
    "proxy_detected": "boolean",
    "has_hooks": "boolean",
    "upgradeable": "boolean"
  },
  "simulation_summary": {
    "total_simulations": "integer",
    "successful_simulations": "integer",
    "average_gas_used": "float"
  }
}
```

### 8. `approve_scan_complete_[timestamp].json` (Complete Scan Summary)
```json
{
  "scan_metadata": {
    "timestamp": "string",
    "total_hypotheses": "integer",
    "completed_hypotheses": "integer",
    "failed_hypotheses": "integer",
    "average_confidence": "float",
    "critical_hypotheses": "integer",
    "high_hypotheses": "integer",
    "medium_hypotheses": "integer",
    "low_hypotheses": "integer"
  },
  "hypotheses": [
    {
      "hypothesis_id": "string",
      "status": "string",
      "confidence_score": "float",
      "risk_level": "string",
      "impact_score": "float",
      "token_address": "string",
      "owner_address": "string",
      "spender_address": "string",
      "scan_timestamp": "string",
      "execution_time": "float",
      "json_files_generated": ["string"]
    }
  ],
  "risk_distribution": {
    "CRITICAL": "integer",
    "HIGH": "integer",
    "MEDIUM": "integer",
    "LOW": "integer"
  },
  "summary_recommendations": ["string"]
}
```

## D. Contoh Nama File & Content Penting

### Example File Names:
```
hypothesis_reports/HYPOTHESIS_0001_0X95AD_0XF39F_0X7A25_1758326631/
├── token_info.json
├── allowance_data.json
├── contract_analysis.json
├── fork_simulations.json
├── historical_patterns.json
├── impact_estimation.json
└── hypothesis_summary.json

approve_scan_complete_20250920_000351.json
```

### Key Fields for Automation:
1. **hypothesis_id**: Unique identifier for tracking
2. **risk_level**: CRITICAL/HIGH/MEDIUM/LOW
3. **confidence_score**: 0.0-1.0 confidence metric
4. **status**: PENDING/COMPLETED/FAILED/SKIPPED
5. **json_files_generated**: List of generated files for verification
6. **execution_time**: Performance benchmarking
7. **recommendations**: Actionable security recommendations

## E. Usage untuk Automation

### Verifier Pattern:
```python
import json
import os

def verify_hypothesis(hypothesis_id):
    """Verify hypothesis completeness"""
    report_dir = f"hypothesis_reports/{hypothesis_id}"
    required_files = [
        "token_info.json",
        "allowance_data.json",
        "contract_analysis.json",
        "fork_simulations.json",
        "historical_patterns.json",
        "impact_estimation.json",
        "hypothesis_summary.json"
    ]

    verification = {
        "hypothesis_id": hypothesis_id,
        "files_present": [],
        "files_missing": [],
        "verification_complete": False
    }

    for file in required_files:
        file_path = os.path.join(report_dir, file)
        if os.path.exists(file_path):
            verification["files_present"].append(file)
        else:
            verification["files_missing"].append(file)

    verification["verification_complete"] = len(verification["files_missing"]) == 0
    return verification
```

### Aggregator Pattern:
```python
def aggregate_all_hypotheses():
    """Aggregate all hypothesis results"""
    all_hypotheses = []

    for hypothesis_dir in os.listdir("hypothesis_reports"):
        summary_file = f"hypothesis_reports/{hypothesis_dir}/hypothesis_summary.json"
        if os.path.exists(summary_file):
            with open(summary_file, 'r') as f:
                summary = json.load(f)
                all_hypotheses.append(summary)

    return {
        "total_hypotheses": len(all_hypotheses),
        "risk_distribution": calculate_risk_distribution(all_hypotheses),
        "average_confidence": calculate_average_confidence(all_hypotheses),
        "critical_findings": get_critical_hypotheses(all_hypotheses)
    }
```

## F. Technical Implementation Notes

### Reproducibility:
- **Deterministic ID**: timestamp + address prefixes
- **Immutable Data**: All blockchain data captured at scan time
- **Version Control**: Scanner version included in metadata
- **Timestamp Precision**: Microsecond accuracy for ordering

### Modularity:
- **Independent Files**: Each JSON file self-contained
- **Clear Schema**: Well-defined structure for each file type
- **API Compatibility**: JSON format compatible with automation tools

### Performance:
- **Parallel Processing**: Hypotheses can be scanned in parallel
- **Memory Efficient**: Streaming JSON generation
- **Benchmarking**: Execution time tracking per hypothesis

This schema provides comprehensive, reproducible, and modular reporting for approve-related vulnerability scanning with full automation support.