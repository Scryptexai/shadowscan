#!/usr/bin/env python3
"""
Simulate New DEFI/DEX Scan
Demonstrates the discovery scanner with realistic vulnerability patterns
"""

import json
import time
from datetime import datetime
from core.database import database
from defi_discovery_scanner import DEFIDiscoveryScanner

def simulate_realistic_defi_contracts():
    """Simulate discovering new DEFI/DEX contracts with realistic vulnerability patterns"""
    print("🚀 Simulating New DEFI/DEX Discovery Scan")
    print("="*60)
    print("🎯 Focus: Router and LP contracts with vulnerability targeting")

    # Initialize scanner
    scanner = DEFIDiscoveryScanner()

    # Simulate realistic DEFI contracts with known vulnerability patterns
    simulated_contracts = [
        {
            'address': '0x1234567890123456789012345678901234567890',
            'name': 'NewSwapRouter_v2',
            'description': 'New DEX router with advanced trading features',
            'is_verified': True,
            'discovery_category': 'router',
            'discovery_keyword': 'router_v2',
            'chain_name': 'polygon_mainnet',
            'chain_id': 137,
            'category': 'router',
            'functions_count': 25,
            'risk_score': 12,
            'risk_level': 'CRITICAL',
            'risk_factors': [
                'Router pattern detected: router_v2',
                'Vulnerability pattern: reentrancy',
                'Vulnerability pattern: unchecked_call',
                'Control function detected: onlyowner'
            ],
            'transaction_data': {
                'total_transfers': 5000,
                'unique_addresses': 1200,
                'unique_from_addresses': 800,
                'activity_score': 5.0,
                'days_analyzed': 30
            },
            'discovered_at': datetime.now().isoformat(),
            'source_code': '''
// Contract with multiple vulnerability patterns
contract NewSwapRouter_v2 {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;

    // Router pattern with reentrancy vulnerability
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts) {
        require(amountOutMin > 0, "ZERO_AMOUNT");

        // REENTRANCY VULNERABILITY
        balances[msg.sender] -= amountIn;
        amounts = getAmountsOut(amountIn, path);
        balances[to] += amounts[amounts.length - 1];

        // Transfer tokens - potential reentrancy point
        IERC20(path[0]).transferFrom(msg.sender, address(this), amountIn);
        IERC20(path[path.length - 1]).transfer(to, amounts[amounts.length - 1]);
    }

    // VULNERABILITY: Access control issues
    function setEmergencyMode(bool emergency) external {
        require(msg.sender == owner, "Not owner");
        isEmergency = emergency; // No timelock
    }

    // VULNERABILITY: Unchecked return value
    function flashLoan(address receiver, uint256 amount) external {
        (bool success, ) = receiver.call{value: amount}("");
        // No return value check
        require(success, "Transfer failed");
    }
}'''
        },
        {
            'address': '0x2345678901234567890123456789012345678901',
            'name': 'LiquidityPool_V3',
            'description': 'Advanced liquidity pool with concentrated liquidity',
            'is_verified': True,
            'discovery_category': 'lp_pool',
            'discovery_keyword': 'v3',
            'chain_name': 'polygon_mainnet',
            'chain_id': 137,
            'category': 'lp_pool',
            'functions_count': 35,
            'risk_score': 15,
            'risk_level': 'CRITICAL',
            'risk_factors': [
                'Liquidity pool detected: v3',
                'Vulnerability pattern: reentrancy',
                'Vulnerability pattern: flash_loan',
                'Vulnerability pattern: oracle_manipulation'
            ],
            'transaction_data': {
                'total_transfers': 15000,
                'unique_addresses': 3500,
                'unique_from_addresses': 2800,
                'activity_score': 8.5,
                'days_analyzed': 30
            },
            'discovered_at': datetime.now().isoformat(),
            'source_code': '''
// High-risk liquidity pool contract
contract LiquidityPool_V3 {
    mapping(address => uint256) public userBalances;
    mapping(address => uint256) public oraclePrices;

    // VULNERABILITY: Oracle manipulation
    function updatePrice(uint256 newPrice) external {
        oraclePrices[token] = newPrice; // No validation
    }

    function addLiquidity(uint256 amount) external payable {
        userBalances[msg.sender] += amount;
        // Flash loan manipulation vulnerability
        if (amount > 1000 ether) {
            executeFlashLoan(amount);
        }
    }

    function executeFlashLoan(uint256 amount) internal {
        // VULNERABILITY: Flash loan manipulation
        uint256 currentPrice = oraclePrices[token];
        uint256 profit = amount * currentPrice * 105 / 100;

        // Manipulate oracle price
        oraclePrices[token] = currentPrice * 2;

        // Execute profitable arbitrage
        userBalances[msg.sender] += profit;
    }

    // VULNERABILITY: Reentrancy in withdraw
    function withdraw(uint256 amount) external {
        require(userBalances[msg.sender] >= amount, "Insufficient balance");

        // State change before external call
        userBalances[msg.sender] -= amount;

        // Reentrancy vulnerability
        payable(msg.sender).transfer(amount);
    }
}'''
        },
        {
            'address': '0x3456789012345678901234545678901234567890',
            'name': 'ControlManager',
            'description': 'Protocol control and governance contract',
            'is_verified': False,
            'discovery_category': 'control',
            'discovery_keyword': 'controller',
            'chain_name': 'polygon_mainnet',
            'chain_id': 137,
            'category': 'control',
            'functions_count': 15,
            'risk_score': 18,
            'risk_level': 'CRITICAL',
            'risk_factors': [
                'Control function detected: controller',
                'Vulnerability pattern: access_control',
                'Vulnerability pattern: governance_takeover',
                'Vulnerability pattern: onlyowner'
            ],
            'transaction_data': {
                'total_transfers': 2000,
                'unique_addresses': 500,
                'unique_from_addresses': 450,
                'activity_score': 2.0,
                'days_analyzed': 30
            },
            'discovered_at': datetime.now().isoformat(),
            'source_code': '''
// Highly vulnerable control contract
contract ControlManager {
    address public owner;
    mapping(address => bool) public admins;

    // VULNERABILITY: Governance takeover
    function upgradeProtocol(address newImplementation) external {
        require(msg.sender == owner, "Not owner");
        // No timelock, instant upgrade
        implementation = newImplementation;
    }

    // VULNERABILITY: Access control bypass
    function addAdmin(address admin) external {
        require(msg.sender == owner, "Not owner");
        admins[admin] = true;
    }

    function emergencyPause() external {
        require(msg.sender == owner, "Not owner");
        isPaused = true; // No multisig approval
    }

    // VULNERABILITY: Uninitialized proxy pattern
    function initialize() external {
        if (initialized) revert();
        owner = msg.sender;
        // No protection against re-initialization
        initialized = true;
    }
}'''
        },
        {
            'address': '0x456789012345678901234567890123456787890',
            'name': 'ArbitrageDEX_v2',
            'description': 'DEX specialized in arbitrage trading',
            'is_verified': True,
            'discovery_category': 'router',
            'discovery_keyword': 'arbitrage',
            'chain_name': 'arbitrum_one',
            'chain_id': 42161,
            'category': 'router',
            'functions_count': 40,
            'risk_score': 20,
            'risk_level': 'CRITICAL',
            'risk_factors': [
                'Router pattern detected: arbitrage',
                'Vulnerability pattern: flash_loan',
                'Vulnerability pattern: oracle_manipulation',
                'Vulnerability pattern: front_running',
                'Vulnerability pattern: reentrancy'
            ],
            'transaction_data': {
                'total_transfers': 25000,
                'unique_addresses': 8000,
                'unique_from_addresses': 6500,
                'activity_score': 9.5,
                'days_analyzed': 30
            },
            'discovered_at': datetime.now().isoformat(),
            'source_code': '''
// Highly vulnerable arbitrage DEX
contract ArbitrageDEX_v2 {
    mapping(address => uint256) public prices;
    mapping(address => uint256) public userBalances;

    // VULNERABILITY: Front-running
    function executeArbitrage(
        address[] memory path,
        uint256 amountIn,
        uint256 minProfit
    ) external returns (uint256 profit) {
        // Transaction can be front-run
        uint256 currentPrice = getPrice(path[0]);
        uint256 estimatedProfit = calculateProfit(path, amountIn);

        require(estimatedProfit >= minProfit, "Insufficient profit");

        // Execute trade without slippage protection
        profit = executeTrade(path, amountIn);
    }

    function getPrice(address token) public view returns (uint256) {
        // VULNERABILITY: Oracle manipulation
        return block.timestamp * 1e18; // Uses timestamp
    }

    // VULNERABILITY: Flash loan manipulation
    function flashLoanArbitrage(address provider, uint256 amount) external {
        IFlashLoanProvider(provider).flashLoan(amount);

        // Price manipulation after flash loan
        prices[token] = prices[token] * 110 / 100;

        // Execute profitable arbitrage
        uint256 profit = amount * 15 / 100;
        payable(msg.sender).transfer(profit);
    }

    function executeTrade(address[] memory path, uint256 amountIn) internal returns (uint256) {
        // VULNERABILITY: Reentrancy
        userBalances[path[0]] -= amountIn;

        // Trade execution
        uint256 amountOut = amountIn * 98 / 100; // 2% fee
        userBalances[path[path.length - 1]] += amountOut;

        return amountOut;
    }
}'''
        },
        {
            'address': '0x5678901234567890123456789012345678901234',
            'name': 'YieldOptimizer_V3',
            'description': 'Advanced yield optimization protocol',
            'is_verified': True,
            'discovery_category': 'lp_pool',
            'discovery_keyword': 'optimization',
            'chain_name': 'optimism',
            'chain_id': 10,
            'category': 'lp_pool',
            'functions_count': 30,
            'risk_score': 14,
            'risk_level': 'HIGH',
            'risk_factors': [
                'Liquidity pool detected: optimization',
                'Vulnerability pattern: flash_loan',
                'Vulnerability pattern: access_control',
                'Vulnerability pattern: time_dependence'
            ],
            'transaction_data': {
                'total_transfers': 8000,
                'unique_addresses': 2000,
                'unique_from_addresses': 1800,
                'activity_score': 4.5,
                'days_analyzed': 30
            },
            'discovered_at': datetime.now().isoformat(),
            'source_code': '''
// Medium-high risk yield optimizer
contract YieldOptimizer_V3 {
    mapping(address => uint256) public userDeposits;
    mapping(address => uint256) public apy;

    // VULNERABILITY: Time dependence
    function calculateReturns(address user) public view returns (uint256) {
        uint256 depositAmount = userDeposits[user];
        uint256 timePassed = block.timestamp - depositTime[user];
        uint256 rate = apy[user] / (365 days);
        return depositAmount * rate * timePassed / 1e18;
    }

    // VULNERABILITY: Access control
    function setAPY(address user, uint256 newAPY) external {
        require(msg.sender == owner, "Not owner");
        apy[user] = newAPY; // No validation
    }

    function harvest() external {
        uint256 returns = calculateReturns(msg.sender);
        userDeposits[msg.sender] += returns;

        // Flash loan opportunity
        if (returns > 100 ether) {
            flashLoanForOptimization(returns);
        }
    }

    function flashLoanForOptimization(uint256 amount) internal {
        // VULNERABILITY: Flash loan for optimization
        // Can be exploited for arbitrage
        executeOptimizationStrategy(amount);
    }
}'''
        }
    ]

    print(f"📋 Simulating {len(simulated_contracts)} new DEFI/DEX contracts")

    # Save contracts to database
    total_saved = 0
    for contract in simulated_contracts:
        try:
            # Prepare contract data
            contract_data = {
                'address': contract['address'],
                'name': contract['name'],
                'description': contract['description'],
                'category': contract['category'],
                'chain_id': contract['chain_id'],
                'chain_name': contract['chain_name'],
                'is_verified': contract['is_verified'],
                'functions_count': contract['functions_count'],
                'discovery_keyword': contract['discovery_keyword'],
                'discovery_category': contract['discovery_category'],
                'activity_score': contract['transaction_data']['activity_score'],
                'total_transfers': contract['transaction_data']['total_transfers'],
                'unique_addresses': contract['transaction_data']['unique_addresses'],
                'risk_score': contract['risk_score'],
                'risk_level': contract['risk_level'],
                'risk_factors': contract['risk_factors'],
                'discovered_at': contract['discovered_at'],
                'scan_type': 'SIMULATED_DISCOVERY',
                'last_updated': datetime.now().isoformat()
            }

            # Add to database
            database.add_contract(contract_data)
            total_saved += 1

            print(f"💾 Saved: {contract['name']} ({contract['risk_level']})")

        except Exception as e:
            print(f"❌ Error saving contract: {e}")

    print(f"\n✅ Successfully saved {total_saved} new contracts to database")

    # Scan for vulnerabilities in the new contracts
    from vulnerability_scanner import VulnerabilityScanner
    scanner = VulnerabilityScanner()

    print(f"\n🔍 Scanning new contracts for vulnerabilities...")

    vulnerability_count = 0
    for contract in simulated_contracts:
        try:
            vulnerabilities = scanner.scan_contract_vulnerabilities(contract)
            for vuln in vulnerabilities:
                database.add_vulnerability(vuln)
                vulnerability_count += 1
        except Exception as e:
            print(f"❌ Error scanning {contract['name']}: {e}")

    print(f"✅ Found and saved {vulnerability_count} vulnerabilities")

    # Show summary
    show_discovery_summary()

def show_discovery_summary():
    """Show discovery summary with statistics"""
    print("\n📊 DISCOVERY SUMMARY")
    print("="*60)

    try:
        # Get database statistics
        stats = database.get_statistics()

        print("🏗️  Database Statistics:")
        print(f"   Total Contracts: {stats['contracts']['total']}")
        print(f"   Total Vulnerabilities: {stats['vulnerabilities']['total']}")

        print(f"\n🔗 Contracts by Chain:")
        for chain, count in stats['contracts']['by_chain'].items():
            print(f"   {chain}: {count} contracts")

        print(f"\n⚠️  Vulnerabilities by Severity:")
        for severity, count in stats['vulnerabilities']['by_severity'].items():
            print(f"   {severity}: {count}")

        # Show high-risk contracts
        contracts = database.get_contracts()
        high_risk = [c for c in contracts if c.get('risk_level') in ['CRITICAL', 'HIGH']]

        print(f"\n🚨 High-Risk Contracts Found: {len(high_risk)}")

        for contract in high_risk[:3]:  # Show top 3
            print(f"   • {contract['name']} ({contract['risk_level']})")
            print(f"     Address: {contract['address']}")
            print(f"     Chain: {contract['chain_name']}")
            print(f"     Risk Score: {contract['risk_score']}")

    except Exception as e:
        print(f"❌ Error showing summary: {e}")

if __name__ == "__main__":
    simulate_realistic_defi_contracts()