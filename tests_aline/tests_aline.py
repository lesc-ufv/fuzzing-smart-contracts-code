import json
import solcx
import networkx as nx
import matplotlib.pyplot as plt

# Simulação da função do fuzzer para obter PCs e instruções de salto no bytecode
def get_pcs_and_jumpis(bytecode):
    pcs = [i for i in range(len(bytecode))]
    jumpis = [i for i in range(len(bytecode)) if bytecode[i:i+2] == '56']  # '56' é um exemplo de opcode JUMPI
    return pcs, jumpis

# Função para construir o Grafo de Controle de Fluxo (CFG)
def build_cfg(pcs, jumpis):
    G = nx.DiGraph()  # Grafo dirigido para o CFG

    # Adiciona nós e conexões
    for i in range(len(pcs) - 1):
        G.add_node(pcs[i], label=f'PC: {pcs[i]}')
        G.add_edge(pcs[i], pcs[i + 1])  # Conecta cada PC ao próximo

    # Adiciona arestas de salto (jumpis)
    for jump in jumpis:
        if jump + 1 < len(pcs):
            G.add_edge(jump, jump + 1, label="jump")  # Aresta de salto
    
    return G

# Função para visualizar o CFG
def plot_cfg(G):
    pos = nx.spring_layout(G)  # Layout do grafo
    labels = nx.get_edge_attributes(G, 'label')
    nx.draw(G, pos, with_labels=True, node_size=5000, node_color='lightblue', font_size=10)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels)
    plt.savefig('grafo_de_controle_de_fluxo.png')
    print("Grafico gerado no diretorio atual: grafo_de_controle_de_fluxo.png")


# Nome do arquivo Solidity a ser compilado
source_code_file = "EtherStorev2.sol"

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

# Teste da função para obter PCs e jumpis
pcs, jumpis = get_pcs_and_jumpis(compiler_output['contracts'][source_code_file]['EtherStore']['evm']['deployedBytecode']['object'])
print("\nPCs e Jumpis Identificados:")
print(f"PCs: {pcs}")
print(f"Jumpis: {jumpis}")

# Construção e visualização do Grafo de Controle de Fluxo
cfg = build_cfg(pcs, jumpis)
plot_cfg(cfg)
""""Números: Os números exibidos representam identificadores ou endereços de instruções. Eles podem estar relacionados a 
diferentes partes do seu código ou contrato inteligente.
Distribuição: A distribuição dos números pode indicar como as instruções estão agrupadas. Um agrupamento denso pode 
sugerir que essas partes do código estão frequentemente interligadas, enquanto áreas mais dispersas podem indicar seções 
menos conectadas."""
