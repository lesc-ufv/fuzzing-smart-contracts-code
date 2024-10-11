from web3 import Web3
import json
import solcx
import networkx as nx
import matplotlib.pyplot as plt
import random
from z3 import *


# Conectando ao Hardhat
hardhat_url = "http://127.0.0.1:8545"
w3 = Web3(Web3.HTTPProvider(hardhat_url))

# Verifique a conexão
if w3.is_connected():
    print("Conectado ao Hardhat!")
else:
    print("Falha ao conectar ao Hardhat")

# Usando a primeira conta do Hardhat
w3.eth.default_account = w3.eth.accounts[0]#biblioteca interna eth, ao inves da outra

# Funções para o fuzzing
def get_pcs_and_jumpis(bytecode):
    pcs = [i for i in range(len(bytecode))]
    jumpis = [i for i in range(len(bytecode)) if bytecode[i:i+2] == '56']  # Exemplo: '56' é o opcode JUMPI
    return pcs, jumpis

def build_cfg(pcs, jumpis):
    G = nx.DiGraph()  # Grafo dirigido para o CFG
    for i in range(len(pcs) - 1):
        G.add_node(pcs[i], label=f'PC: {pcs[i]}')
        G.add_edge(pcs[i], pcs[i + 1], label="next")
    for jump in jumpis:
        target_pc = jump + 2 if (jump + 2 < len(pcs)) else jump
        G.add_edge(jump, target_pc, label="jump")
    return G

def plot_cfg(G):
    pos = nx.spring_layout(G)
    labels = nx.get_edge_attributes(G, 'label')
    node_labels = nx.get_node_attributes(G, 'label')
    nx.draw(G, pos, with_labels=True, labels=node_labels, node_size=2000, node_color='lightblue', font_size=10, font_color='black')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels)
    plt.title('Control Flow Graph')
    plt.savefig('grafo_de_controle_de_fluxo.png')
    print("Gráfico gerado: grafo_de_controle_de_fluxo.png")

def generate_random_inputs(abi, contract_instance):
    inputs = []
    for item in abi:
        if item['type'] == 'function':#Le a ABI e procura pelas funcoes
            function_inputs = {}
            for input_param in item.get('inputs', []):
                param_type = input_param['type']
                if param_type == 'uint256':
                    if item['name'] == 'withdraw':
                       # Gera um valor até o saldo disponível para evitar reverts por saldo insuficiente
                        balance = contract_instance.functions.balances(w3.eth.default_account).call()
                        if balance > 0:
                            amount_to_withdraw = random.randint(1, balance)  # Escolhe um valor entre 1 e o saldo
                            function_inputs[input_param['name']] = amount_to_withdraw
                        else:
                            print("Saldo insuficiente para retirar.")
                            continue  # Se não houver saldo, pula para a próxima função
                    else:
                        value = random.randint(0, 2**256 - 1)
                        function_inputs[input_param['name']] = value
                        
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
                'name': item['name'],
                'inputs': function_inputs
            })
    return inputs

def simulate_transaction(contract, function_name, inputs=None, value=0):
    try:
        if inputs:
            # Ordena os inputs de acordo com a ordem dos parâmetros na função
            sorted_inputs = [inputs[param['name']] for param in contract.functions[function_name].abi['inputs']]
            txn = getattr(contract.functions, function_name)(*sorted_inputs).transact({'value': value})
        else:
            txn = getattr(contract.functions, function_name)().transact({'value': value})
        tx_receipt = w3.eth.wait_for_transaction_receipt(txn)
        print(f"Transação {function_name} executada com sucesso: {tx_receipt.transactionHash.hex()}")
        return tx_receipt
    except Exception as e:
        print(f"Erro ao executar a transação {function_name}: {e}")
        return None




def genetic_fuzzer(abi, contract_instance, generations=10, population_size=5, mutation_rate=0.1):
    population = [generate_random_inputs(abi, contract_instance) for _ in range(population_size)]
    for generation in range(generations):
        print(f"\nGeneration {generation}...")
        for inputs in population:
            for func in inputs:
                func_name = func['name']
                func_inputs = func['inputs']
                value = 0
                if func_name == 'deposit':
                    value = random.randint(1, 10**18)  # Deposita entre 1 wei e 1 ether
                tx_receipt = simulate_transaction(contract_instance, func_name, func_inputs, value)
                if tx_receipt:
                    pass
        # Mutação da população
        new_population = []
        for _ in range(population_size):
            mutated = mutate_inputs(random.choice(population))
            new_population.append(mutated)
        population = new_population

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

# Nome do arquivo Solidity a ser compilado
source_code_file = "EtherStore.sol"

# Leitura do código fonte Solidity
with open(source_code_file, 'r') as file:
    source_code = file.read()

# Configurações do compilador Solidity
solc_version = "0.8.24"
if solc_version not in solcx.get_installed_solc_versions():
    solcx.install_solc(solc_version)
solcx.set_solc_version(solc_version, True)

# Compilação do código Solidity
compiler_output = solcx.compile_standard({
    'language': 'Solidity',
    'sources': {source_code_file: {'content': source_code}},
    'settings': {
        "optimizer": {"enabled": True, "runs": 200},
        "evmVersion": "cancun",
        "outputSelection": {
            source_code_file: {
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

# Implementação do contrato
contract_name = "EtherStore"
contract_interface = compiler_output['contracts'][source_code_file][contract_name]
abi = contract_interface['abi']
bytecode = contract_interface['evm']['bytecode']['object']

# Implantando o contrato
transaction = {
    'from': w3.eth.default_account,
    'gas': 2000000,
    'gasPrice': w3.to_wei('50', 'gwei')
}

# Enviando a transação para implantar o contrato
contract = w3.eth.contract(abi=abi, bytecode=bytecode)
tx_hash = contract.constructor().transact(transaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

# Obter o endereço do contrato implantado
contract_address = tx_receipt['contractAddress']
print(f"Contrato implantado em: {contract_address}")
print(f'ABI do contrato {abi}')
# Criando uma instância do contrato implantado
ether_store_contract = w3.eth.contract(address=contract_address, abi=abi)

# Opcional: Realizar um depósito inicial para evitar erros de saldo insuficiente
initial_deposit = 10**18  # 1 Ether
initial_withdraw= 10**2 # menos q 1 ether, so pra testar a tipagem do withdraw e balance
print("Realizando depósito inicial de 1 Ether...")
tx_receipt = simulate_transaction(ether_store_contract, 'deposit', {}, initial_deposit)
if tx_receipt:
    print("Depósito inicial realizado com sucesso.")
tx_receipt2 = simulate_transaction(ether_store_contract, 'withdraw', {}, initial_withdraw)
if tx_receipt2:
    print("Saque inicial realizado com sucesso.")

# Inicia o fuzzing
genetic_fuzzer(abi, ether_store_contract)  # Inicia o processo de fuzzing
