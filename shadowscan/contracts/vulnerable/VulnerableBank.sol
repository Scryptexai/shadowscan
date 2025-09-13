// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title VulnerableBank
 * @dev Simple vulnerable bank contract for demonstration purposes
 * This contract contains reentrancy vulnerability for testing
 */
contract VulnerableBank is Ownable {
    using SafeERC20 for IERC20;
    
    mapping(address => uint256) public balances;
    IERC20 public token;
    
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    
    constructor(address _token) {
        token = IERC20(_token);
    }
    
    function deposit(uint256 amount) external {
        require(amount > 0, "Amount must be > 0");
        balances[msg.sender] += amount;
        token.safeTransferFrom(msg.sender, address(this), amount);
        emit Deposited(msg.sender, amount);
    }
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // VULNERABILITY: External call before state update
        token.safeTransfer(msg.sender, amount);
        
        balances[msg.sender] -= amount;
        emit Withdrawn(msg.sender, amount);
    }
    
    function getBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }
    
    function getUserBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}