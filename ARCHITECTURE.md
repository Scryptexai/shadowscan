# ShadowScan Architecture Documentation

## Overview

ShadowScan is a comprehensive security scanning platform for blockchain, web applications, and network infrastructure. It implements a two-stage screening pipeline with modular vulnerability detection and verification capabilities.

## ASCII Architecture Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER INTERFACE                           │
└─────────────────────────┬───────────────────────────────────────┘
                         │
┌─────────────────────────▼───────────────────────────────────────┐
│                      CLI Interface                              │
│  shadowscan [command] [options]                                 │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐                │
│  │ screen  │ │ verify  │ │ attack  │ │ report  │                │
│  │   (s)   │ │         │ │         │ │         │                │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘                │
└─────────────────────────┬───────────────────────────────────────┘
                         │
┌─────────────────────────▼───────────────────────────────────────┐
│                 Screening Engine (orchestrator)                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   SESSION MANAGEMENT                    │   │
│  │  • Discovery Phase (shallow: 500 blocks)                │   │
│  │  • Detailed Phase (full: 2000 blocks)                   │   │
│  │  • ContractRegistry persistence                          │   │
│  │  • Error handling & partial results                     │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────────────┘
                         │
    ┌─────────────────────▼─────────────────────┐
    │              DATA COLLECTION              │
    │  ┌─────────────┐ ┌─────────────┐ ┌───────┐│
    │  │ abi_fetcher │ │ tx_fetcher  │ │ dex_  ││
    │  │             │ │ (chunked)   │ │ disco ││
    │  └─────────────┘ └─────────────┘ │ very  ││
    │  ┌─────────────┐ ┌─────────────┐ └───────┘│
    │  │ oracle_    │ │ state_      │          │
    │  │ intel       │ │ fetcher     │          │
    │  └─────────────┘ └─────────────┘          │
    └─────────────────────┬─────────────────────┘
                         │
    ┌─────────────────────▼─────────────────────┐
    │            CONTRACT REGISTRY               │
    │  • Thread-safe persistent storage          │
    │  • Discovered contracts metadata          │
    │  • Target-chain-address mapping           │
    │  • File-based atomic writes               │
    └─────────────────────┬─────────────────────┘
                         │
    ┌─────────────────────▼─────────────────────┐
    │              DETECTION PHASE              │
    │  ┌─────────────────────────────────────┐  │
    │  │           20 DETECTORS             │  │
    │  │ ┌─────────────┐ ┌───────────────┐  │  │
    │  │ │reentrancy   │ │flashloan     │  │  │
    │  │ │             │ │manipulation │  │  │
    │  │ ├─────────────┤ ├───────────────┤  │  │
    │  │ │proxy_       │ │admin_access  │  │  │
    │  │ │misuse       │ │control       │  │  │
    │  │ ├─────────────┤ ├───────────────┤  │  │
    │  │ │delegatecall  │ │integer_      │  │  │
    │  │ │             │ │overflow      │  │  │
    │  │ └─────────────┘ └───────────────┘  │  │
    │  │         ... 16 more detectors     │  │
    │  └─────────────────────────────────────┘  │
    └─────────────────────┬─────────────────────┘
                         │
    ┌─────────────────────▼─────────────────────┐
    │            VERIFICATION PHASE             │
    │  ┌─────────────────────────────────────┐  │
    │  │           VERIFIERS                 │  │
    │  │ • Fork simulation (Tenderly/Anvil)   │  │
    │  │ • PoC execution in sandbox         │  │
    │  │ • Vulnerability confirmation        │  │
    │  └─────────────────────────────────────┘  │
    └─────────────────────┬─────────────────────┘
                         │
┌─────────────────────────▼───────────────────────────────────────┐
│                      OUTPUT & REPORTING                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                │
│  │ findings/   │ │ reports/    │ │ logs/       │                │
│  │ HYP-*.json  │ │ *.html      │ │ session.log │                │
│  └─────────────┘ └─────────────┘ └─────────────┘                │
└─────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

### CLI Layer (`shadowscan/cli.py`, `shadowscan/commands/`)
- **Entry Point**: `shadowscan` command with subcommands
- **Screen Command**: `shadowscan s -t <target> -c <chain> -d <depth>`
- **Verify Command**: `shadowscan verify --hyp HYP-xxxx --sim tenderly`
- **User Interface**: Rich console output with progress bars and animations

### Screening Engine (`shadowscan/core/pipeline/screening_engine.py`)
- **Orchestrator**: Controls entire screening lifecycle
- **Session Management**: Handles discovery → detailed scan phases
- **Error Handling**: Graceful degradation, partial results
- **ContractRegistry Integration**: Persistent contract discovery storage

### Data Collection (`shadowscan/collectors/evm/`)
- **ABI Fetcher**: Contract ABI retrieval with caching and fallbacks
- **Transaction Fetcher**: Chunked, concurrent transaction scanning with retries
- **DEX Discovery**: Factory log scanning, pair identification
- **Oracle Intelligence**: Oracle source detection and analysis
- **State Fetcher**: Contract state snapshots

### ContractRegistry (`shadowscan/data/contracts.py`)
- **Storage**: Thread-safe persistent contract metadata
- **Discovery Tracking**: Target-chain-address mapping
- **Atomic Operations**: File-based writes with locking
- **API Methods**: `load()`, `add_contract()`, `get_contracts_for_target()`, `save()`

### Detection System (`shadowscan/detectors/evm/`)
- **20 Vulnerability Detectors**: Each implements `detect_<vuln_name>()`
- **Hypothesis Generation**: Structured findings with confidence levels
- **Pattern Recognition**: Heuristic-based vulnerability identification
- **Multi-category**: Reentrancy, Flashloan, Proxy, Access Control, etc.

### Verification System (`shadowscan/verifiers/evm/`)
- **Simulation**: Fork-based PoC execution (Tenderly/Anvil)
- **Sandbox**: Safe exploit testing without mainnet impact
- **Confirmation**: VERIFIED/INCONCLUSIVE results

### Adapters (`shadowscan/adapters/evm/`)
- **Provider**: RPC endpoint management with failover
- **Simulator**: Fork creation and transaction simulation

### Data Flow

1. **Discovery Phase**: 
   - Fetch ABI, recent transactions (500 blocks)
   - Discover related contracts via DEX pairs
   - Store in ContractRegistry

2. **Detailed Phase**:
   - Fetch full transaction history (2000 blocks)
   - Run all 20 detectors on discovered contracts
   - Generate hypotheses with evidence

3. **Verification**:
   - Simulate high-confidence hypotheses in fork
   - Confirm exploitability

4. **Output**:
   - Persist session data (session_*.json)
   - Export interaction graph (graph_*.json)
   - Save hypotheses (HYP-*.json)
   - Generate structured logs

## Entry Points

### Primary CLI Commands
- `shadowscan s -t <address> -c <chain> -d shallow --dex` (Screen alias)
- `shadowscan screen -t <address> -c <chain> -d full --no-dex`
- `shadowscan verify --hyp HYP-xxxx --sim tenderly`
- `shadowscan attack --hyp HYP-xxxx --mode simulation`

### Key Functions
- `ScreeningEngine.run_screening()` - Main orchestrator
- `ContractRegistry.add_contract()` - Persistent storage
- `TxFetcher.fetch_recent_txs()` - Chunked transaction scanning
- `detect_<vuln_name>()` - Vulnerability detection (20 functions)
- `verify_<vuln_name>()` - Exploit simulation

## File Structure Summary

```
shadowscan/
├── cli.py                           # Main CLI entry point
├── commands/
│   ├── screen.py                    # Screen command (alias 's')
│   ├── verify.py                    # Verification command
│   └── attack.py                    # Attack simulation command
├── core/pipeline/
│   └── screening_engine.py          # Main orchestrator
├── collectors/evm/
│   ├── abi_fetcher.py              # ABI fetching with caching
│   ├── tx_fetcher.py               # Transaction fetching (chunked)
│   ├── dex_discovery.py            # DEX pair discovery
│   ├── oracle_intel.py             # Oracle analysis
│   └── state_fetcher.py            # State snapshots
├── data/
│   └── contracts.py                # ContractRegistry (TO BE IMPLEMENTED)
├── detectors/evm/
│   ├── generic_patterns.py         # Pattern detector (needs detect_generic_patterns)
│   ├── oracle_manipulation.py      # Oracle manipulation detector
│   └── [18 more detectors needed]   # Reentrancy, flashloan, etc.
├── verifiers/evm/
│   └── oracle_manipulation_verify.py # Oracle verification
│   └── [more verifiers needed]     # PoC simulation for each vuln
├── adapters/evm/
│   ├── provider.py                 # RPC management with failover
│   └── simulator.py                # Fork simulation
├── trackers/
│   └── graph_builder.py            # Interaction graph building
└── utils/
    ├── schema.py                   # Data models
    └── helpers.py                  # Utility functions

tests/                              # TO BE CREATED
logs/                               # TO BE CREATED
reports/findings/                   # Output directory
├── session_*.json                  # Session data
├── graph_*.json                    # Interaction graphs
└── HYP-*.json                      # Hypotheses findings
```

## Current Implementation Status

**✅ COMPLETE**: Core infrastructure exists
**🔄 NEEDS UPDATE**: ContractRegistry, tx_fetcher robustness, CLI aliases
**❌ MISSING**: 18/20 detectors, tests, logging structure, most verifiers