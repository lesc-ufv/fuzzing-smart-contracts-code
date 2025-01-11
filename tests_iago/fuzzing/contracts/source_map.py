import json
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
def save_source_map(compiler_output, contract_filename, contract_name, out_filename):
    source_map = compiler_output['contracts'][contract_filename][contract_name]['evm']['deployedBytecode'].get('sourceMap', '')
    
    # saves the sourcemap in a json file
    with open(out_filename, 'w') as file:
        json.dump({"sourceMap": source_map}, file, indent=4)


def get_pcs_and_jumpis(bytecode):
    pcs = [i for i in range(len(bytecode))]
    jumpis = [i for i in range(len(bytecode)) if bytecode[i:i+2] == '56']  # Example: '56' is JUMPI opcode
    return pcs, jumpis
