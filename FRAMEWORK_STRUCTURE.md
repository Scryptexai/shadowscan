# 🏗️ ShadowScan Modular System - Framework Structure Documentation

## 📁 Directory Structure Overview

```
shadowscan/
├── 🎯 CORE FRAMEWORK
│   ├── modular_system/              # Modular system architecture
│   │   ├── core/                   # Core components
│   │   ├── scanners/               # Scanning modules
│   │   ├── phases/                 # Phase runners
│   │   └── system_controller.py     # Main system controller
│   ├── config.yaml                 # System configuration
│   ├── run_modular_system.py       # Main entry point
│   └── run_phase3.py              # Phase 3 entry point
│
├── 🗄️ DATABASE SYSTEMS
│   ├── defi_protocol_database.json     # Phase 1: Protocol definitions
│   ├── contract_intelligence_db.json   # Phase 3: Contract intelligence
│   ├── vulnerability_screening_db.json # Phase 5: Vulnerability screening
│   ├── confirmed_vulnerabilities_db.json # Phase 6: Confirmed vulnerabilities
│   └── sqlite_export/               # SQLite database exports
│
├── 📚 REFERENCE DATABASES
│   ├── comprehensive_vulnerability_database.json  # All vulnerability types
│   ├── exploit_database.json                    # Exploit techniques
│   ├── pattern_database.json                    # Attack patterns
│   ├── chain_reference.json                     # Blockchain configurations
│   └── api_endpoints.json                       # Explorer APIs
│
├── 📊 OUTPUT & REPORTS
│   ├── reports/                         # Generated reports
│   ├── intelligence_databases/          # Phase 4: Protocol docs
│   ├── logs/                           # System logs
│   └── exports/                        # Data exports
│
├── 🔧 SUPPORTING FILES
│   ├── ROADMAP.md                      # Development roadmap
│   ├── FRAMEWORK_STRUCTURE.md         # This document
│   ├── DEVELOPMENT.md                 # Development guide
│   ├── VULNERABILITY_GUIDE.md        # Vulnerability reference
│   └── EXPLOIT_GUIDE.md              # Exploit technique reference
│
├── 🗑️ ARCHIVE
│   ├── old_scripts_backup/             # Legacy scripts
│   └── experimental/                  # Experimental code
│
└── 📋 DATA
    ├── data/                          # Data storage
    └── samples/                       # Sample data
```

## 🎯 Core Framework Components

### **1. Modular System Architecture**

#### **File**: `modular_system/core/base_manager.py`
**Purpose**: Foundation class for all modular components
**Key Features**:
- Centralized error handling and recovery
- Performance tracking and metrics
- Logging system with multiple handlers
- Abstract base class implementation
- Thread-safe operation management

**Usage**:
```python
from modular_system.core import BaseManager

class MyScanner(BaseManager):
    def __init__(self, config=None):
        super().__init__("MyScanner", config)

    def run(self):
        with self.diagnostic.trace_operation("MyScanner", "main_operation"):
            # Main scanning logic
            pass
```

#### **File**: `modular_system/core/error_handler.py`
**Purpose**: Centralized error handling with auto-recovery
**Key Features**:
- Error severity classification (CRITICAL, HIGH, MEDIUM, LOW)
- Error pattern detection and alerting
- Auto-recovery strategies
- Comprehensive error context tracking
- Performance impact monitoring

**Error Categories**:
- `NETWORK`: Connection errors, timeouts, API failures
- `DATABASE`: Data integrity, query errors, storage issues
- `VALIDATION`: Input validation, data format errors
- `AUTHENTICATION`: API keys, authentication failures
- `CONFIGURATION`: Configuration file errors, invalid settings
- `BUSINESS_LOGIC`: Protocol-specific business rule violations
- `SECURITY`: Security vulnerabilities, permission issues

#### **File**: `modular_system/core/config_manager.py`
**Purpose**: Configuration management with validation
**Key Features**:
- YAML/JSON configuration support
- Environment-specific configurations
- Configuration validation and schema
- Hot-reload capability
- Environment variable mapping

**Configuration Structure**:
```yaml
system:
  name: "ShadowScan Modular System"
  version: "1.0.0"
  environment: "development"
  debug_mode: true

database:
  type: "sqlite"
  path: "./data/scanning.db"
  backup_enabled: true

scanning:
  phase_1:
    enabled: true
    max_protocols: 1000
  phase_3:
    enabled: true
    max_contracts: 5000
```

#### **File**: `modular_system/core/diagnostic_tools.py`
**Purpose**: Performance monitoring and diagnostics
**Key Features**:
- Real-time performance metrics collection
- Memory usage tracking
- System health monitoring
- Operation tracing and timing
- Debug report generation

**Metrics Tracked**:
- Operation duration and success rates
- Memory and CPU usage
- Thread and connection counts
- Error rates and patterns
- Component health status

### **2. Scanning Modules**

#### **File**: `modular_system/scanners/contract_scanner.py`
**Purpose**: Advanced contract analysis and intelligence gathering
**Key Features**:
- Multi-chain blockchain integration
- Contract type classification
- Function and signature analysis
- Security scoring and audit status
- Confidence level calculation

**Contract Intelligence Structure**:
```python
@dataclass
class ContractIntelligence:
    protocol_name: str
    contract_address: str
    contract_type: str  # DEX_ROUTER, LENDING, STAKING, BRIDGE
    chain_id: int
    chain_name: str

    abi: List[Dict[str, Any]]
    source_code: str
    bytecode: str
    function_signatures: List[str]
    event_signatures: List[str]

    security_score: int
    audit_status: str
    confidence_level: float
```

### **3. Phase Runners**

#### **File**: `modular_system/phases/phase_3_runner.py`
**Purpose**: Phase 3 coordination and execution
**Key Features**:
- Contract scanning coordination
- Result processing and validation
- Database integration
- Report generation
- Statistics compilation

**Execution Flow**:
1. Validate prerequisites
2. Execute contract scanner
3. Process results
4. Generate intelligence database
5. Export to SQLite
6. Create summary reports

### **4. System Controller**

#### **File**: `system_controller.py`
**Purpose**: Central coordination of all system components
**Key Features**:
- Phase lifecycle management
- Thread-based execution
- Status monitoring
- Component initialization
- System diagnostics

**System States**:
- `INITIALIZING`: System startup and setup
- `READY`: Operational and ready for tasks
- `RUNNING`: Executing phases
- `PAUSED`: Temporarily stopped
- `ERROR`: Error state
- `SHUTDOWN`: System shutdown

## 🗄️ Database System Architecture

### **Phase 1: DEFI Protocol Database**
**File**: `defi_protocol_database.json`
**Purpose**: Store discovered DEFI/DEX protocols
**Structure**:
```json
{
  "database_metadata": {
    "created_date": "2025-09-22T...",
    "total_protocols": 100,
    "schema_version": "1.0.0"
  },
  "protocols": [
    {
      "protocol_name": "story_protocol_router",
      "blockchain": "Story Protocol",
      "chain_id": 1514,
      "category": "DEX",
      "risk_level": "MEDIUM",
      "website": "https://...",
      "contract_addresses": {...},
      "audit_status": "UNKNOWN"
    }
  ],
  "categories_summary": {...},
  "risk_distribution": {...}
}
```

### **Phase 3: Contract Intelligence Database**
**File**: `contract_intelligence_db.json`
**Purpose**: Detailed contract analysis results
**Structure**:
```json
{
  "metadata": {
    "phase": "Phase 3",
    "total_contracts": 500,
    "average_confidence": 0.85
  },
  "contract_intelligence": {
    "protocol_name": [
      {
        "contract_address": "0x...",
        "contract_type": "DEX_ROUTER",
        "security_score": 85,
        "functions": [...],
        "events": [...],
        "confidence_level": 0.92
      }
    ]
  }
}
```

### **Phase 6: Confirmed Vulnerabilities Database**
**File**: `confirmed_vulnerabilities_db.json`
**Purpose**: Store confirmed vulnerabilities with attack vectors
**Structure**:
```json
{
  "confirmed_metadata": {
    "total_confirmed": 25,
    "confirmation_date": "2025-12-01"
  },
  "confirmed_vulnerabilities": [
    {
      "vulnerability_id": "CV-2025-001",
      "protocol_name": "Story Protocol Router",
      "component": "Swap Function",
      "vulnerability_type": "Reentrancy",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "attack_vector": {
        "exploit_steps": [...],
        "required_tools": ["Brownie", "Web3.js"],
        "success_probability": 0.8
      },
      "mitigation": "Implement reentrancy guard"
    }
  ]
}
```

## 📚 Reference Databases

### **Comprehensive Vulnerability Database**
**File**: `references/comprehensive_vulnerability_database.json`
**Purpose**: Complete reference of all vulnerability types
**Categories**:
1. **Blockchain Vulnerabilities** (35 types)
2. **Blockchain Exploits** (11 types)
3. **Web Vulnerabilities** (traditional web security)
4. **Web Exploits** (web-based attacks)

### **Exploit Database**
**File**: `references/exploit_database.json`
**Purpose**: Detailed exploit techniques and methodologies
**Structure**:
```json
{
  "exploits": [
    {
      "id": "EXP-001",
      "name": "Reentrancy Attack",
      "target": "Smart Contracts",
      "confidence_level": "HIGH",
      "technical_details": {
        "prerequisites": ["External contract calls", "Unprotected state updates"],
        "attack_steps": [...],
        "indicators": [...],
        "mitigations": [...]
      },
      "tools_required": ["Brownie", "Web3.js", "Hardhat"],
      "success_probability": 0.7,
      "potential_profit": "$100K - $1M"
    }
  ]
}
```

### **Pattern Database**
**File**: `references/pattern_database.json`
**Purpose**: Common attack patterns and detection methods
**Pattern Types**:
- Reentrancy patterns
- Oracle manipulation
- Front-running detection
- Token approval abuse
- Liquidity pool exploits

### **Chain Reference Database**
**File**: `references/chain_reference.json`
**Purpose**: Blockchain-specific configurations and APIs
**Structure**:
```json
{
  "chains": {
    "story_protocol": {
      "chain_id": 1514,
      "rpc_url": "https://story-rpc.publicnode.com",
      "explorer_url": "https://storyscan.io",
      "native_token": "NTR",
      "risk_level": "HIGH"
    },
    "berachain": {
      "chain_id": 80085,
      "rpc_url": "https://bera.rpc.publicnode.com",
      "explorer_url": "https://berascan.io",
      "native_token": "BERA",
      "risk_level": "CRITICAL"
    }
  }
}
```

## 🔧 Configuration System

### **Main Configuration File**: `config.yaml`
**Purpose**: System-wide configuration settings
**Sections**:
- `system`: Basic system information
- `database`: Database configuration
- `network`: Network and API settings
- `scanning`: Scanning phase configurations
- `error_handling`: Error handling policies
- `logging`: Logging configuration

### **Environment-Specific Configurations**
- **Development**: Debug mode, local databases, verbose logging
- **Testing**: Limited scope, test data, mock APIs
- **Production**: Optimized settings, external APIs, monitoring

## 📊 Output and Reporting

### **Generated Reports**
**Directory**: `reports/`
**Types**:
- Phase execution summaries
- Vulnerability reports
- Performance analytics
- System health reports
- Statistical analysis

### **Intelligence Databases**
**Directory**: `intelligence_databases/`
**Content**:
- Individual protocol documentation
- Contract analysis results
- Relationship mappings
- Security assessments

### **Data Exports**
**Directory**: `exports/`
**Formats**:
- SQLite databases
- CSV reports
- JSON exports
- PDF summaries

## 🔧 Development and Maintenance

### **Code Organization Principles**
1. **Single Responsibility**: Each file has one clear purpose
2. **Separation of Concerns**: Clear boundaries between components
3. **Dependency Injection**: Components receive dependencies externally
4. **Interface Segregation**: Minimal interfaces, focused contracts
5. **Don't Repeat Yourself**: Common functionality abstracted to base classes

### **Error Handling Strategy**
1. **Centralized Error Management**: Single point for error handling
2. **Graceful Degradation**: System continues despite non-critical errors
3. **Error Recovery**: Automatic recovery strategies for common errors
4. **Comprehensive Logging**: Complete error context for debugging
5. **User-Friendly Messages**: Clear error messages for different stakeholders

### **Performance Considerations**
1. **Asynchronous Operations**: I/O-bound operations use async
2. **Database Optimization**: Proper indexing and query optimization
3. **Memory Management**: Efficient data structures and cleanup
4. **Caching**: Strategic caching for frequently accessed data
5. **Connection Pooling**: Efficient connection reuse

### **Security Considerations**
1. **Input Validation**: All inputs validated and sanitized
2. **Secure Storage**: Sensitive data encrypted at rest
3. **API Security**: Rate limiting and authentication
4. **Audit Trail**: Complete operation logging
5. **Principle of Least Privilege**: Minimal required permissions

---

**Framework Version**: 1.0.0
**Last Updated**: September 22, 2025
**Architecture Lead**: ShadowScan Development Team