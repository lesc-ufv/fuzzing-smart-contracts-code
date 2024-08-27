import solcx
import json

def get_pcs_and_jumpis(bytecode):
    return ([i for i in range(len(bytecode))], [])

source_code_file = "EtherStorev2.sol"

with open(source_code_file, 'r') as file:
    source_code = file.read()

solc_version = "0.8.24"
if not solc_version in solcx.get_installed_solc_versions():
    solcx.install_solc(solc_version)
solcx.set_solc_version(solc_version, True)

compiler_output = solcx.compile_standard({
    'language': 'Solidity',
    'sources': {source_code_file: {'content': source_code}},
    'settings': {
        "optimizer": {
            "enabled": True,
            "runs": 200
        },
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

"""objetivo principal mapear as posições do bytecode para as posições correspondentes no código fonte Solidity, 
utilizando informações do assembly gerado pelo compilador. A ideia é ajudar a conectar o código de baixo nível (bytecode) 
com o código fonte original, o que pode ser útil para depuração e análise.
"""
# Definição da classe SourceMap
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

class SourceMap:
    position_groups = {}
    sources = {}
    compiler_output = None

    def __init__(self, cname, compiler_output):
        self.cname = cname
        SourceMap.compiler_output = compiler_output
        SourceMap.position_groups = SourceMap._load_position_groups_standard_json()
        self.source = self._get_source()
        self.positions = self._get_positions()
        self.instr_positions = self._get_instr_positions()

    def _get_instr_positions(self):
        j = 0
        instr_positions = {}
        try:
            filename, contract_name = self.cname.split(":")
            bytecode = self.compiler_output['contracts'][filename][contract_name]["evm"]["deployedBytecode"]["object"]
            pcs = get_pcs_and_jumpis(bytecode)[0]  # Obtém os PCs a partir do bytecode
            for i in range(len(self.positions)):
                if self.positions[i] and self.positions[i]['name'] != 'tag':
                    instr_positions[pcs[j]] = self.positions[i]  # Associa o PC à posição da instrução
                    j += 1
            return instr_positions
        except:
            return instr_positions

    @classmethod
    def _load_position_groups_standard_json(cls):
        return cls.compiler_output["contracts"]

    def _get_positions(self):
        filename, contract_name = self.cname.split(":")
        asm = SourceMap.position_groups[filename][contract_name]['evm']['legacyAssembly']['.data']['0']
        positions = asm['.code']
        while(True):
            try:
                positions.append(None)
                positions += asm['.data']['0']['.code']
                asm = asm['.data']['0']
            except:
                break
        return positions

    def _get_source(self):
        fname = self.get_filename()
        if fname not in SourceMap.sources:
            SourceMap.sources[fname] = Source(fname)
        return SourceMap.sources[fname]

    def get_filename(self):
        return self.cname.split(":")[0]

contract_name = f"{source_code_file}:EtherStore"
source_map = SourceMap(contract_name, compiler_output)

# Testando a função _get_instr_positions
instr_positions = source_map._get_instr_positions()
print("Instr Positions:")
for pc, pos in instr_positions.items():
    print(f"PC: {pc}, Position: {pos}")

#detalhes da saída
""" pc(contador de programa): a posição da instrução no bytecode.
begin: a posição inicial da instrução no código-fonte do Solidity.
end: a posição final da instrução no código-fonte do Solidity.
name: o nome da instrução.
source: o índice do arquivo de origem na saída do compilador.
value: o valor associado à instrução, se houver."""
