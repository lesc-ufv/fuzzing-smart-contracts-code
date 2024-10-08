// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract EtherStore {
    mapping(address => uint256) public balances;

    // Evento para rastrear depósitos
    event Deposit(address indexed sender, uint256 amount);

    // Evento para rastrear retiradas
    event Withdraw(address indexed receiver, uint256 amount);

    // Função para depositar Ether no contrato
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // Função para retirar Ether do contrato
    function withdraw(uint256 _amount) external {
        require(balances[msg.sender] >= _amount, "Saldo insuficiente");
        balances[msg.sender] -= _amount;
        payable(msg.sender).transfer(_amount);
        emit Withdraw(msg.sender, _amount);
    }

    // Função para obter o saldo do contrato
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
