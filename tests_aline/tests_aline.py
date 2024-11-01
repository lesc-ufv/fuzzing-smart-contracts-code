import json
import solcx
import random
from web3 import Web3

# Função para obter PCs e instruções de salto no bytecode
def get_pcs_and_jumpis(bytecode):
    pcs = [i for i in range(len(bytecode))]
    jumpis = [i for i in range(len(bytecode)) if bytecode[i:i+2] == '56']  # '56' é um exemplo de opcode JUMPI
    return pcs, jumpis

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

# Função para obter a linha do código-fonte a partir do PC
def get_source_line_from_pc(pc, source_map):
    line = source_map.get_buggy_line(pc) #busca a linha correspondente ao pc dentro de source_map.
    return line.strip() if line else "Linha não encontrada"

# Função para compilar o contrato
def compile_smartcontract(solc_version, filename, source_code):
    if solc_version not in solcx.get_installed_solc_versions():
        solcx.install_solc(solc_version)
    solcx.set_solc_version(solc_version, True)

    return solcx.compile_standard({
        'language': 'Solidity',
        'sources': {filename: {'content': source_code}},
        'settings': {
            "optimizer": {"enabled": True, "runs": 200},
            "evmVersion": "cancun",
            "outputSelection": {
                filename: {
                    "*": [
                        "abi",
                        "evm.deployedBytecode",
                        "evm.bytecode.object",
                        "evm.legacyAssembly",
                    ],
                }
            }
        }
    })

# Função para conectar à blockchain
def connect_in_blockchain(url):
    w3 = Web3(Web3.HTTPProvider(url))
    if w3.is_connected():
                print("Conectado à blockchain.")
                return w3
    else:
        print("Falha na conexão com a blockchain.")
        return None

# Função para implantar o contrato
def deploy_smartcontract(w3, abi, bytecode):
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = contract.constructor().transact()
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Contrato implantado em: {tx_receipt.contractAddress}")
    return contract(tx_receipt.contractAddress)


def detect_reentrancy(sloads, calls, current_instruction, source_map):
    if current_instruction["op"] == "SLOAD":
        storage_index = current_instruction["stack"][-1]
        sloads[storage_index] = current_instruction["pc"]
    elif current_instruction["op"] == "CALL" and sloads:
        gas = int(current_instruction["stack"][-1], 16)
        value = int(current_instruction["stack"][-3], 16)

        if gas > 2300 and value > 0:
            calls.add(current_instruction["pc"])
            for pc in sloads.values():
                if pc < current_instruction["pc"]:
                    # Aqui você pode obter a linha de código correspondente
                    buggy_line = get_source_line_from_pc(pc, source_map)
                    print(f"Reentrância detectada em CALL na linha: {buggy_line.strip()}")
                    return current_instruction["pc"]
    elif current_instruction["op"] == "SSTORE" and calls:
        storage_index = current_instruction["stack"][-1]
        if storage_index in sloads:
            for pc in calls:
                if pc < current_instruction["pc"]:
                    buggy_line = get_source_line_from_pc(pc, source_map)
                    print(f"Reentrância detectada em SSTORE na linha: {buggy_line.strip()}")
                    return pc
    elif current_instruction["op"] in ["STOP", "RETURN", "REVERT", "ASSERTFAIL", "INVALID", "SUICIDE", "SELFDESTRUCT"]:
        sloads.clear()
        calls.clear()
    return None

# Simulação de transação 
def simulate_transaction(w3, contract, function_name, inputs=None, value=0):
    try:
        if inputs:
            sorted_inputs = [inputs[param['name']] for param in contract.functions[function_name].abi['inputs']]
            txn = getattr(contract.functions, function_name)(*sorted_inputs).transact({'value': value})
        else:
            txn = getattr(contract.functions, function_name)().transact({'value': value})

        tx_receipt = w3.eth.wait_for_transaction_receipt(txn)
        print(f"Transaction '{function_name}' executada com sucesso: {tx_receipt.transactionHash.hex()}")
        return tx_receipt
    except Exception as e:
        print(f"Erro durante a execução da transação '{function_name}': {e}")
        return None

# Função para gerar entradas aleatórias para fuzzing
def generate_random_inputs(abi):
    inputs = []
    
    for item in abi:
        if item['type'] == 'function' and item['name'] != 'balances':  # Apenas para EtherStore!
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
                    value = None  # Tipos não suportados podem ser ignorados ou tratados conforme necessário
                if value is not None:
                    function_inputs[input_param['name']] = value
            inputs.append({
                'stateMutability': item["stateMutability"],
                'name': item['name'],
                'inputs': function_inputs
            })

    return inputs

# Função para salvar chamadas de baixo nível em um arquivo JSON
def save_lowlevelcalls(result, out_filename):
    result = dict(result)
    # Formatando saída
    temp_logs = []
    for log in result["structLogs"]:
        temp_log = dict(log)
        temp_log["storage"] = dict(temp_log["storage"])
        temp_logs.append(temp_log)
    result["structLogs"] = temp_logs
    # Salvando chamadas de baixo nível em .json
    with open(out_filename, 'w') as fp:
        json.dump(result, fp)

# Função de fuzzing genético
def genetic_fuzzer(w3, abi, contract_instance, sloads, calls, source_map, generations=1, population_size=1):
    population = [generate_random_inputs(abi) for _ in range(population_size)]
 
    for generation in range(generations):
        print(f"\nGeneration {generation}...")
        for inputs in population:
            for func in inputs:
                func_name = func['name']
                func_inputs = func['inputs'] if len(func['inputs']) > 0 else None  # Sempre vazio para EtherStore!
                func_state = func['stateMutability']
                value = 0
                
                if func_state == 'payable':
                    value = random.randint(1, 10**18)  # Depósito entre 1 wei e 1 ether
                    print(f"Transação `{func_name}` recebeu valor de entrada aleatório: {value}")
                tx_receipt = simulate_transaction(w3, contract_instance, func_name, func_inputs, value)
                
                # Verificar instruções
                result = w3.manager.request_blocking('debug_traceTransaction', [f"0x{tx_receipt.transactionHash.hex()}"])
                save_lowlevelcalls(result, f"gen{generation}_{func_name}.json")
                if not result.failed:
                    for i, instruction in enumerate(result.structLogs):
                        pc = detect_reentrancy(sloads, calls, instruction, source_map)  # Passando source_map
                        if pc:
                            print(f"Reentrância detectada em {func_name}:", pc)
# Função principal
if __name__ == "__main__":
    blockchain_url = "http://127.0.0.1:8545"
    contract_filename = "EtherStorev2.sol"
    contract_name = "EtherStore"
    solc_version = "0.8.24"

    sloads = dict()
    calls = set()

    # Ler o código do contrato
    with open(contract_filename, 'r') as file:
        source_code = file.read()
    
    # Compilar o contrato
    compiler_output = compile_smartcontract(solc_version, contract_filename, source_code)
    
    # Obter informações do contrato
    contract_interface = compiler_output['contracts'][contract_filename][contract_name]
    abi = contract_interface['abi']
    bytecode = contract_interface['evm']['bytecode']['object']
    
    # Conexão com a blockchain e deploy do contrato
    w3_conn = connect_in_blockchain(blockchain_url)
    if w3_conn is not None:
        ether_store_contract = deploy_smartcontract(w3_conn, abi, bytecode)
    
    # Criar uma instância do SourceMap
    source_map = SourceMap(f"{contract_filename}:{contract_name}", compiler_output)

    # Realizar um depósito como exemplo
    print("Depositando 1 Ether...")
    tx_receipt = simulate_transaction(w3=w3_conn, contract=ether_store_contract, function_name='deposit', value=Web3.to_wei(1, 'ether'))
    
    if tx_receipt is not None:
        print("Saldo do contrato: {}".format(ether_store_contract.functions.getBalance().call()))
        
        # Chamada da função genetic_fuzzer com os parâmetros adicionais
        genetic_fuzzer(w3_conn, abi, ether_store_contract, sloads, calls, source_map, generations=1, population_size=1)  # Init Fuzzing process
