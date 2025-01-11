# Importando funções e classes dos módulos específicos
from compiler.compile_smartcontract import compile_smartcontract
from blockchain.connection import connect_in_blockchain
from blockchain.connection import deploy_smartcontract
from fuzzer.genetic_fuzzer import genetic_fuzzer
from fuzzer.simulate_transaction import simulate_transaction
from contracts.source_map import SourceMap
from utils.low_level_calls import save_lowlevelcalls
from utils.random_inputs import generate_random_inputs
from contracts.source_map import save_source_map
from web3 import Web3
import random
import pprint
import json


if __name__ == "__main__":
    blockhain_url = "http://127.0.0.1:8545"
    contract_filename = "contracts/EtherStorev2.sol"
    contract_name = "EtherStore"
    solc_version = "0.8.24"

    sloads = dict()
    calls = set()

    with open(contract_filename, 'r') as file:
        source_code = file.read()
    
    compiler_output = compile_smartcontract(solc_version, contract_filename, source_code)
    
    # Smart contract information
    contract_interface = compiler_output['contracts'][contract_filename][contract_name]
    abi = contract_interface['abi']
    bytecode = contract_interface['evm']['bytecode']['object']
    deployed_bytecode = contract_interface['evm']['deployedBytecode']['object']
    
    # Connection and deploy
    w3_conn = connect_in_blockchain(blockhain_url)
    if w3_conn is not None:
        ether_store_contract = deploy_smartcontract(w3_conn, abi, bytecode)
    
    # Optional step, just for checking
    print("Depositing 1 Ether...")
    tx_receipt = simulate_transaction(w3=w3_conn, contract=ether_store_contract, function_name='deposit', value=Web3.to_wei(1, 'ether'))

    source_map = SourceMap(f"{contract_filename}:{contract_name}", compiler_output)
    save_source_map(compiler_output, contract_filename, contract_name, 'source_map.json')
    if tx_receipt is not None:
        print("Contract balance: {}".format(ether_store_contract.functions.getBalance().call()))
        genetic_fuzzer(w3_conn, abi, ether_store_contract, sloads, calls,source_map) # Init Fuzzing proccess
       
