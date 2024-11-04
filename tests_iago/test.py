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
# Classe que carrega o conteúdo do código fonte Solidity
class Source:
    def __init__(self, filename):
        self.filename = filename
        self.content = self._load_content()
        self.line_break_positions = self._load_line_break_positions()

    def _load_content(self):
        with open(self.filename, 'r') as f:
            content = f.read()
        return content

    def _load_line_break_positions(self):
        return [i for i, letter in enumerate(self.content) if letter == '\n']

# Classe que mapeia as posições das instruções do bytecode com o código fonte Solidity
class SourceMap:
    position_groups = {}
    sources = {}
    compiler_output = None

    def __init__(self, cname, compiler_output):
        self.cname = cname
        SourceMap.compiler_output = compiler_output
        SourceMap.position_groups = self._load_position_groups_standard_json()
        self.source = self._get_source()
        self.positions = self._get_positions()
        self.instr_positions = self._get_instr_positions()

    def _get_instr_positions(self):
        instr_positions = {}
        try:
            filename, contract_name = self.cname.split(":")
            bytecode = self.compiler_output['contracts'][filename][contract_name]["evm"]["deployedBytecode"]["object"]
            pcs, jumpis = get_pcs_and_jumpis(bytecode)
            for j, pc in enumerate(pcs):
                if j < len(self.positions) and self.positions[j]:
                    instr_positions[pc] = self.positions[j]
            return instr_positions
        except Exception as e:
            print(f"Erro ao mapear instruções: {e}")
            return instr_positions

    @classmethod
    def _load_position_groups_standard_json(cls):
        return cls.compiler_output["contracts"]

    def _get_positions(self):
        filename, contract_name = self.cname.split(":")
        asm = SourceMap.position_groups[filename][contract_name]['evm']['legacyAssembly']['.data']['0']
        positions = asm['.code']
        while True:
            try:
                positions.append(None)
                positions += asm['.data']['0']['.code']
                asm = asm['.data']['0']
            except KeyError:
                break
        return positions

    def _get_source(self):
        fname = self.get_filename()
        if fname not in SourceMap.sources:
            SourceMap.sources[fname] = Source(fname)
        return SourceMap.sources[fname]

    def get_filename(self):
        return self.cname.split(":")[0]

    def get_buggy_line(self, pc):
        try:
            pos = self.instr_positions[pc]
        except KeyError:
            return ""
        begin = pos['begin']
        end = pos['end']
        return self.source.content[begin:end]

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

#code coverage
def code_coverage(logs):
    """ Track PCs hit during transaction for code coverage analysis. """
    covered_pcs = set()
    for log in logs:
        if "pc" in log:
            covered_pcs.add(log["pc"])
    return covered_pcs

def update_coverage(coverage_map, new_coverage):
    """ Update the coverage map with new transaction coverage """
    for pc in new_coverage:
        if pc not in coverage_map:
            coverage_map[pc] = 1
        else:
            coverage_map[pc] += 1
    return coverage_map

def calculate_coverage(coverage_map, total_pcs):
    """ Calculate percentage of code covered based on unique PCs """
    unique_pcs_covered = len(coverage_map.keys())
    coverage_percentage = (unique_pcs_covered / total_pcs) * 100
    print(f"Current Code Coverage: {coverage_percentage:.2f}%")
    return coverage_percentage

    

def simulate_transaction(w3, contract, function_name, inputs=None, value=0):
    try:
        if inputs:
            # Sorting inputs accordingly with function parameters
            sorted_inputs = [inputs[param['name']] for param in contract.functions[function_name].abi['inputs']]
            txn = getattr(contract.functions, function_name)(*sorted_inputs).transact({'value': value})
        else:
            txn = getattr(contract.functions, function_name)().transact({'value': value})
        tx_receipt = w3.eth.wait_for_transaction_receipt(txn)
        print(f"Transaction '{function_name}' executed successfully: {tx_receipt.transactionHash.hex()}")
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

def save_lowlevelcalls(result, out_filename):
    result = dict(result)
    # Formatting output
    temp_logs = []
    for log in result["structLogs"]:
        temp_log = dict(log)
        temp_log["storage"] = dict(temp_log["storage"])
        temp_logs.append(temp_log)
    result["structLogs"] = temp_logs
    # Saving low-level calls to .json
    with open(out_filename, 'w') as fp:
        json.dump(result, fp)

def genetic_fuzzer(w3, abi, contract_instance, sloads, calls,source_map, generations=10, population_size=10):
    population = [generate_random_inputs(abi) for _ in range(population_size)]
    coverage_map = {}
    total_pcs = len(source_map.instr_positions)#all contract pcs

 
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
                
                # Check instructions
                result = w3.manager.request_blocking('debug_traceTransaction', [f"0x{tx_receipt.transactionHash.hex()}"])
                logs = result["structLogs"] if "structLogs" in result else []
                new_coverage = code_coverage(logs)
                update_coverage(coverage_map, new_coverage)
                    
                save_lowlevelcalls(result, f"gen{generation}_{func_name}.json")
                if not result.failed:
                    for i, instruction in enumerate(result.structLogs):
                        pc = detect_reentrancy(sloads, calls, instruction)
                        if pc:
                            print(f"Detected reentrancy in {func_name}:", pc)
        #calculate the coverage from all the code
        calculate_coverage(coverage_map, total_pcs)
def detect_reentrancy(sloads, calls, current_instruction):
    # Remember sloads
    if current_instruction["op"] == "SLOAD":
        storage_index = current_instruction["stack"][-1]
        sloads[storage_index] = current_instruction["pc"]
    # Remember calls with more than 2300 gas and where the value is larger than zero/symbolic or where destination is symbolic
    elif current_instruction["op"] == "CALL" and sloads:
        gas = int(current_instruction["stack"][-1], 16) # Gas da instrucao
        value = int(current_instruction["stack"][-3], 16) # Saldo atual do contrato

        if gas > 2300 and value > 0:
            calls.add(current_instruction["pc"])
            for pc in sloads.values():
                if pc < current_instruction["pc"]:
                    return current_instruction["pc"] # ENCONTRA REENTRADA AQUI!
    # Check if this sstore is happening after a call and if it is happening after an sload which shares the same storage index
    elif current_instruction["op"] == "SSTORE" and calls:
        storage_index = current_instruction["stack"][-1]
        if storage_index in sloads:
            for pc in calls:
                if pc < current_instruction["pc"]:
                    return pc # ENCONTRA REENTRADA AQUI!
    # Clear sloads and calls from previous transactions
    elif current_instruction["op"] in ["STOP", "RETURN", "REVERT", "ASSERTFAIL", "INVALID", "SUICIDE", "SELFDESTRUCT"]:
        sloads = dict()
        calls = set()
    return None # NÃO FOI ENCONTRADA REENTRADA!

def save_source_map(compiler_output, contract_filename, contract_name, out_filename):
    source_map = compiler_output['contracts'][contract_filename][contract_name]['evm']['deployedBytecode'].get('sourceMap', '')
    
    # saves the sourcemap in a json file
    with open(out_filename, 'w') as file:
        json.dump({"sourceMap": source_map}, file, indent=4)

if __name__ == "__main__":
    blockhain_url = "http://127.0.0.1:8545"
    contract_filename = "EtherStore.sol"
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

