import solcx
from web3 import Web3
import random, pprint
import json

def compile_smartcontract(compiler_version, contract_filename, source_code):
    if compiler_version not in solcx.get_installed_solc_versions():
        solcx.install_solc(compiler_version)
    solcx.set_solc_version(solc_version, True)

    compiler_output = solcx.compile_standard({
        'language': 'Solidity',
        'sources': {contract_filename: {'content': source_code}},
        'settings': {
            "optimizer": {"enabled": True, "runs": 200},
            "evmVersion": "cancun",
            "outputSelection": {
                contract_filename: {
                    "*": [
                        "abi",
                        "evm.deployedBytecode",
                        "evm.bytecode.object",
                        "evm.legacyAssembly",
                    ],
                }
            }
        }
    }, allow_paths='.')
    print("Smart contract compiled!")

    return compiler_output

def connect_in_blockchain(url):
    w3 = Web3(Web3.HTTPProvider(url))
    if w3.is_connected():
        print("Blockchain connected succesfully!")
        w3.eth.default_account = w3.eth.accounts[0]
        return w3
    
    print("Error during the connection with the blockchain!")
    return None

def deploy_smartcontract(w3, abi, bytecode):
    smart_contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = smart_contract.constructor().transact()
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = tx_receipt.contractAddress
    print(f"Contract Address: {contract_address}")
    
    return w3.eth.contract(address=contract_address, abi=abi)

def get_pcs_and_jumpis(bytecode):
    pcs = [i for i in range(len(bytecode))]
    jumpis = [i for i in range(len(bytecode)) if bytecode[i:i+2] == '56']  # Example: '56' is JUMPI opcode
    return pcs, jumpis
def convert_stack_value_to_int(stack_value):
    if stack_value[0] == int:
        return stack_value[1]
    elif stack_value[0] == bytes:
        return int.from_bytes(stack_value[1], "big")

def reentrancy_detector(contract_instance, tainted_record,current_instruction,transaction_index,sloads_instructions,calls_instructions):
    #Monitorar sloads
    if current_instruction["op"]=="SLOAD":
        storage_index = convert_stack_value_to_int(current_instruction["stack"][-1])
        sloads_instructions[storage_index] = current_instruction["pc"],transaction_index
    #Monitorar calls, com valores com mais de 2300 de gas
    #mais de 2300 gas significa que a chamada tem gas suficiente para realizar operações mais complexas, como reentrar no contrato ou modificar o estado do contrato

    elif current_instruction["op"]=="CALL" and sloads_instructions:
        gas = convert_stack_value_to_int(current_instruction["stack"][-1])
        value = convert_stack_value_to_int(current_instruction["stack"][-3])
        if gas>2300 and(value>0 or tainted_record and tainted_record.stack and tainted_record.stack[-3]):
            calls_instructions.add(current_instruction["pc"],transaction_index)
        if gas>2300 and tainted_record and tainted_record.stack() and tainted_record.stack[-2]:
            calls_instructions.add(current_instruction["pc"],transaction_index)
            for pc,index in sloads_instructions.values():
                if pc<current_instruction["pc"]:
                    return current_instruction["pc"], index
    elif current_instruction["op"] == "SSTORE" and calls_instructions:
            if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                storage_index = convert_stack_value_to_int(current_instruction["stack"][-1])
                if storage_index in sloads_instructions:
                    for pc, index in calls_instructions:
                        if pc < current_instruction["pc"]:
                            return pc, index



def simulate_transaction(w3, contract, function_name, inputs=None, value=0):
    try:
        if inputs:
            # Sorting inputs accordingly with function parameters
            sorted_inputs = [inputs[param['name']] for param in contract.functions[function_name].abi['inputs']]
            txn = getattr(contract.functions, function_name)(*sorted_inputs).transact({'value': value})
        else:
            txn = getattr(contract.functions, function_name)().transact({'value': value})
        tx_receipt = w3.eth.wait_for_transaction_receipt(txn)
        #print(f"Transaction '{function_name}' executed successfully: {tx_receipt.transactionHash.hex()}")
        
        # Analisar a transação para buscar vulnerabilidades de reentrância
        tainted_record = {'stack': set(), 'storage': set()}
        sloads_instructions = {}
        calls_instructions = {}

        # using the debug trace trabsaction to get the low level instructions
        trace = w3.manager.request_blocking('debug_traceTransaction', [tx_receipt.transactionHash.hex()])
        
        for log in trace['structLogs']:
            print(log) 
             # Check the instructions

        
        # iterate for the instructions to detect reentrancy
        for idx, log in enumerate(trace["structLogs"]):
            reentrancy_result = reentrancy_detector(contract, tainted_record, log, idx, sloads_instructions, calls_instructions)
            if reentrancy_result:
                pc, index = reentrancy_result
                print(f"Reentrancy detected at pc: {pc}, in transaction index: {index}")
        
        return tx_receipt
    except Exception as e:
        print(f"Error during transaction '{function_name}' execution: {e}")
        return None


def generate_random_inputs(abi):
    inputs = []
    
    for item in abi:
        if item['type'] == 'function' and item['name'] != 'balances': # Only for EtherStore!
            function_inputs = dict()
            for input_param in item.get('inputs', []):
                param_type = input_param['type']
                if param_type == 'uint256':
                    value = random.randint(0, 2**256 - 1)
                elif param_type == 'address':
                    value = '0x' + ''.join(random.choices('0123456789abcdef', k=40))
                elif param_type == 'string':
                    value = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=random.randint(5, 15)))
                elif param_type == 'bool':
                    value = random.choice([True, False])
                elif param_type.startswith('bytes'):
                    size = int(param_type.replace('bytes', '')) if len(param_type) > 5 else random.randint(1, 32)
                    value = '0x' + ''.join(random.choices('0123456789abcdef', k=size*2))
                else:
                    value = None # Non-supported types can be ignored or treated as needed
                if value is not None:
                    function_inputs[input_param['name']] = value
            inputs.append({
                'stateMutability': item["stateMutability"],
                'name': item['name'],
                'inputs': function_inputs
            })

    return inputs

def genetic_fuzzer(w3, abi, contract_instance, generations=10, population_size=5, mutation_rate=0.1):
    population = [generate_random_inputs(abi) for _ in range(population_size)]
 
    for generation in range(generations):
        print(f"\nGeneration {generation}...")
        for inputs in population:
            for func in inputs:
                func_name = func['name']
                func_inputs = func['inputs'] if len(func['inputs']) > 0 else None # Always empty for EtherStore!
                func_state = func['stateMutability']
                value = 0
                
                if func_state == 'payable':
                    value = random.randint(1, 10**18)  # Deposit between 1 wei and 1 ether
                    print(f"Transaction `{func_name}` received random input value: {value}")
                tx_receipt = simulate_transaction(w3, contract_instance, func_name, func_inputs, value)
        
        # Mutation
      #  new_population = []
      #  for _ in range(population_size):
      #      mutated = mutate_inputs(random.choice(population))
      #      new_population.append(mutated)
      #   population = new_population

def mutate_inputs(inputs):
    mutated_inputs = []
    for func in inputs:
        new_func = {'name': func['name'], 'inputs': {}}
        for key, value in func['inputs'].items():
                    if isinstance(value, int):
                        new_value = random.randint(0, 2**256 - 1)
                    elif isinstance(value, str) and value.startswith('0x'):
                        new_value = '0x' + ''.join(random.choices('0123456789abcdef', k=len(value) - 2))
                    elif isinstance(value, str):
                        new_value = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=random.randint(5, 15)))
                    elif isinstance(value, bool):
                        new_value = not value
                    else:
                        new_value = value  # Para tipos não suportados
                    new_func['inputs'][key] = new_value
                    mutated_inputs.append(new_func)
    return mutated_inputs


if __name__ == "__main__":
    blockhain_url = "http://127.0.0.1:8545"
    contract_filename = "EtherStore.sol"
    contract_name = "EtherStore"
    solc_version = "0.8.24"

    with open(contract_filename, 'r') as file:
        source_code = file.read()
    
    compiler_output = compile_smartcontract(solc_version, contract_filename, source_code)
    
    # Smart contract information
    contract_interface = compiler_output['contracts'][contract_filename][contract_name]
    abi = contract_interface['abi']
    bytecode = contract_interface['evm']['bytecode']['object']
    
    w3_conn = connect_in_blockchain(blockhain_url)
    if w3_conn is not None:
        ether_store_contract = deploy_smartcontract(w3_conn, abi, bytecode)
    
    # Optional step, just for checking
    print("Depositing 1 Ether...")
    tx_receipt = simulate_transaction(w3=w3_conn, contract=ether_store_contract, function_name='deposit', value=Web3.to_wei(1, 'ether'))
    
    if tx_receipt is not None:
        print("Contract balance: {}".format(ether_store_contract.functions.getBalance().call()))
        genetic_fuzzer(w3_conn, abi, ether_store_contract) # Init Fuzzing proccess
    # Getting low-level calls information
    result = w3_conn.manager.request_blocking('debug_traceTransaction', [f"0x{tx_receipt.transactionHash.hex()}"])
    result = dict(result)

    # Formatting output
    temp_logs = []
    for log in result["structLogs"]:
        temp_log = dict(log)
        temp_log["storage"] = dict(temp_log["storage"])
        temp_logs.append(temp_log)
    result["structLogs"] = temp_logs
    
    # Saving low-level calls to .json
    with open('result.json', 'w') as fp:
        json.dump(result, fp)
    #print("Low-level calls saved to .json file!")
    
