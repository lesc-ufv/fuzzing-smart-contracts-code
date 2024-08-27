import solcx
import re
import json

source_code_file = "EtherStore.sol"
source_code = ""
with open(source_code_file, 'r') as file:
    source_code = file.read()
solc_version = "0.8.24"
if not solc_version in solcx.get_installed_solc_versions():
    solcx.install_solc(solc_version)
solcx.set_solc_version(solc_version, True)
out = solcx.compile_standard({
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
                "*":
                    [
                        "abi",
                        "evm.deployedBytecode",
                        "evm.bytecode.object",
                        "evm.legacyAssembly",
                    ],
            }
        }
    }
}, allow_paths='.')
#print(json.dumps(out))
for contract_name, contract in out['contracts'][source_code_file].items():
    #print(contract)
    
    if source_code_file and contract_name != source_code_file:
        continue
    # if contract['abi'] and contract['evm']['bytecode']['object'] and contract['evm']['deployedBytecode']['object']:
    #     source_map = SourceMap(':'.join([args.source, contract_name]), compiler_output)
    #     Fuzzer(contract_name, contract["abi"], contract['evm']['bytecode']['object'], contract['evm']['deployedBytecode']['object'], instrumented_evm, blockchain_state, solver, args, seed, source_map).run()


#Source map from utils
#tools to do the sourcemap func

#func tath removes the hash from the bytecode
def remove_swarm_hash(bytecode):
    if isinstance(bytecode, str):
        if bytecode.endswith("0029"):
            bytecode = re.sub(r"a165627a7a72305820\S{64}0029$", "", bytecode)
        if bytecode.endswith("0033"):
            bytecode = re.sub(r"5056fe.*?0033$", "5056", bytecode)
            print(bytecode)
    return bytecode

#func that gets the pcs
def get_pcs_and_jumpis(bytecode):
    bytecode = bytes.fromhex(remove_swarm_hash(bytecode).replace("0x", ""))#gets the bytecode in hex without the hash
    i = 0
    pcs = []
    jumpis = []
    while i < len(bytecode):#travels the bytecode byte per byte
        opcode = bytecode[i]
        pcs.append(i)
        if opcode == 87: # JUMPI
            jumpis.append(hex(i))
        if opcode >= 96 and opcode <= 127: # PUSH
            size = opcode - 96 + 1
            i += size
        i += 1
    if len(pcs) == 0:#if the bytecode has no pcs 
        pcs = [0]
    return (pcs, jumpis)#return a tuple with the pcs and jumpi instructions




#iterate to get the contract
for contract_name, contract in out['contracts'][source_code_file].items():
    #gets the bytecode
    bytecode = contract['evm']['bytecode']['object']
    pcs, jumpis = get_pcs_and_jumpis(bytecode)
    
    #removes the hash
    bytecode_without_hash = remove_swarm_hash(bytecode)    
#print(bytecode_without_hash)
print(f"Contract: {contract_name}")
print(f"Program Counters (pcs): {pcs}")
print(f"JUMPI positions: {jumpis}")