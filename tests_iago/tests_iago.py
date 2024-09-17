import sys
import solcx
import re
import json
from tests import source_map
import logging
import web3
from eth_utils import encode_hex, decode_hex, to_canonical_addres
from web3 import Web3
# Logging level
LOGGING_LEVEL = logging.INFO


def initialize_logger(name):
    logger = logging.getLogger(name)
    logger.title = lambda *a: logger.info(*[bold(x) for x in a])
    logger_error = logger.error
    logger.error = lambda *a: logger_error(*[red(bold(x)) for x in a])
    logger_warning = logger.warning
    logger.warning = lambda *a: logger_warning(*[red(bold(x)) for x in a])
    logger.setLevel(level=LOGGING_LEVEL)
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    return logger
def bold(x):
    return "".join(['\033[1m', x, '\033[0m']) if isinstance(x, str) else x

def red(x):
    return "".join(['\033[91m', x, '\033[0m']) if isinstance(x, str) else x



#store the informations of the fuzzing proccess??
class FuzzingEnvironment:
    def __init__(self,**kwargs) -> None:
        self.nr_of_transactions = 0
        self.unique_individuals = set()
        self.code_coverage = set()
        self.children_code_coverage = dict()
        self.previous_code_coverage_length = 0

        self.visited_branches = dict()

        self.memoized_fitness = dict()
        self.memoized_storage = dict()
        self.memoized_symbolic_execution = dict()

        self.individual_branches = dict()

        self.data_dependencies = dict()

        self.__dict__.update(kwargs)


class Fuzzer:
    def __init__(self, contract_name, abi, deployment_bytecode, runtime_bytecode, test_instrumented_evm, blockchain_state, solver, args, seed, source_map=None):
        global logger
        logger = initialize_logger("Fuzzer: ")
        logger.title("Fuzzing contract %s", contract_name)
        self.contract_name = contract_name
        self.interface = get_interface_from_abi(abi)
        self.deployement_bytecode = deployment_bytecode
        self.blockchain_state = blockchain_state
        self.instrumented_evm = test_instrumented_evm
        self.solver = solver
        self.args = args
        
        
        #get info from the pcs and jumpis from the contract
        self.overall_pcs, self.overall_jumpis = get_pcs_and_jumpis(runtime_bytecode)
        # Initialize results
        self.results = {"errors": {}}
        #define environment from the fuzzer engine "fuzzing enviroment"
        self.env = FuzzingEnvironment(instrumented_evm=self.instrumented_evm,
                                      contract_name=self.contract_name,
                                      solver=self.solver,
                                      results=self.results,
                                      #Analisys tools
                                    #   symbolic_taint_analyzer=SymbolicTaintAnalyzer(),
                                    #   detector_executor=DetectorExecutor(source_map, get_function_signature_mapping(abi)),
                                      interface=self.interface,
                                      overall_pcs=self.overall_pcs,
                                      overall_jumpis=self.overall_jumpis,
                                      len_overall_pcs_with_children=0,
                                      other_contracts = list(),
                                      args=args,
                                      seed=seed,
                                    #   cfg=cfg,  graph
                                      abi=abi)
        def run(self):
            contract_address = None
            self.instrumented_evm.create_fake_accounts()
            if self.args.source:
                for transaction in self.blockchain_state:
                    if transaction['from'].lower() not in self.instrumented_evm_accounts:
                        self.instrumented_evm.accounts.append(self.instrumented_evm.create_fake_account(transaction['from']))
                    if not transaction['to']:#if the contract is on the "to format have to deploy it i think"
                        result = self.instrumented_evm.deploy_contract(transaction['from'],transaction['input'],int(transaction['value']),int(transaction['gas']),int(transaction['gasPrice']))
                        if result.is_error:
                            logger.error("Cannot deploy contract '%s' using account '%s'.Error message given: %s",self.contract_name,transaction['from'],result._error)#_error????
                            sys.exit()
                        else:
                            contract_address = encode_hex(result.msg.storage_address)
                            self.instrumented_evm.accounts.append(contract_address)#in the accounts lists??
                            self.env.nr_of_transactions +=1
                            logger.debug("Contract deployed at %s",contract_address)
                            #dont get that line meaning (95) until the end of the else
                        #now if the transaction is "from" i guess
                        #gets the contract deploy  info normally
                    else:
                        input = {}
                        input["block"] = {}
                        input["transaction"] = {
                            "from": transaction["from"],
                            "to": transaction["to"],
                            "gaslimit": int(transaction["gas"]),
                            "value": int(transaction["value"]),
                            "data": transaction["input"]
                        }
                        input["global_state"] = {}
                        out = self.instrumented_evm.deploy_transaction(input, int(transaction["gasPrice"]))
# # Always deploy the contract (without checking 'to' field)
#     result = self.instrumented_evm.deploy_contract(transaction['from'], transaction['input'], int(transaction['value']), int(transaction['gas']), int(transaction['gasPrice']))
    
#     # Handle errors if deployment fails
#     if result.is_error:
#         logger.error("Problem while deploying contract %s using account %s. Error message: %s", self.contract_name, transaction['from'], result._error)
#         sys.exit(-2)
#     else:
#         contract_address = encode_hex(result.msg.storage_address)
#         self.instrumented_evm.accounts.append(contract_address)
#         self.env.nr_of_transactions += 1
#         logger.debug("Contract deployed at %s", contract_address)

#         # Analyze the bytecode of the deployed contract (pcs and jumpis)
#         cc, _ = get_pcs_and_jumpis(self.instrumented_evm.get_code(to_canonical_address(contract_address)).hex())
#         self.env.len_overall_pcs_with_children += len(cc)

# # Remove constructor check and handle contract address assignment
# result = self.instrumented_evm.deploy_contract(self.instrumented_evm.accounts[0], self.deployement_bytecode)
# if result.is_error:
#     logger.error("Problem while deploying contract %s using account %s. Error message: %s", self.contract_name, self.instrumented_evm.accounts[0], result._error)
#     sys.exit(-2)
# else:
#     contract_address = encode_hex(result.msg.storage_address)
#     self.instrumented_evm.accounts.append(contract_address)
#     self.env.nr_of_transactions += 1
#     logger.debug("Contract deployed at %s", contract_address)
                            
                            
                            
                            
source_code_file = "EtherStore.sol"
source_code = ""
with open(source_code_file, 'r') as file:
    source_code = file.read()

solc_version = "0.8.24"
if solc_version not in solcx.get_installed_solc_versions():
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

#print(json.dumps(out))
for contract_name, contract in out['contracts'][source_code_file].items():
    #print(contract)
    
    if source_code_file and contract_name != source_code_file:
        continue
    if contract['abi'] and contract['evm']['bytecode']['object'] and contract['evm']['deployedBytecode']['object']:
        source_map = source_map.SourceMap(':'.join([source_code_file, contract_name]), out)
        print(source_map)
        
        Fuzzer(contract_name, contract["abi"], contract['evm']['bytecode']['object'], contract['evm']['deployedBytecode']['object'], instrumented_evm, blockchain_state, solver, args, seed, source_map).run()

# Source map from utils
# tools to do the sourcemap func

# func that removes the hash from the bytecode
def remove_swarm_hash(bytecode):
    if isinstance(bytecode, str):
        if bytecode.endswith("0029"):
            bytecode = re.sub(r"a165627a7a72305820\S{64}0029$", "", bytecode)
        if bytecode.endswith("0033"):
            bytecode = re.sub(r"5056fe.*?0033$", "5056", bytecode)
            print(bytecode)
    return bytecode

# func that gets the pcs
def get_pcs_and_jumpis(bytecode):
    bytecode = bytes.fromhex(remove_swarm_hash(bytecode).replace("0x", ""))  # gets the bytecode in hex without the hash
    i = 0
    pcs = []
    jumpis = []
    while i < len(bytecode):  # travels the bytecode byte per byte
        opcode = bytecode[i]
        pcs.append(i)
        if opcode == 87:  # JUMPI
            jumpis.append(hex(i))
        if opcode >= 96 and opcode <= 127:  # PUSH
            size = opcode - 96 + 1
            i += size
        i += 1
    if len(pcs) == 0:  # if the bytecode has no pcs
        pcs = [0]
    return (pcs, jumpis)  # return a tuple with the pcs and jumpi instructions
def get_interface_from_abi(abi):
    interface = {}
    for field in abi:
        if field['type'] == 'function':
            function_name = field['name']
            function_inputs = []
            signature = function_name + '('
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                function_inputs.append(input_type)
                signature += input_type
                if i < len(field['inputs']) - 1:
                    signature += ','
            signature += ')'
            hash = Web3.sha3(text=signature)[0:4].hex()
            interface[hash] = function_inputs
        elif field['type'] == 'constructor':
            function_inputs = []
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                function_inputs.append(input_type)
            interface['constructor'] = function_inputs
    if not "fallback" in interface:
        interface["fallback"] = []
    return interface

# iterate to get the contract
for contract_name, contract in out['contracts'][source_code_file].items():
    # gets the bytecode
    bytecode = contract['evm']['bytecode']['object']
    pcs, jumpis = get_pcs_and_jumpis(bytecode)
    
    # removes the hash
    bytecode_without_hash = remove_swarm_hash(bytecode)
    # print(bytecode_without_hash)
    print(f"Contract: {contract_name}")
    print(f"Program Counters (pcs): {pcs}")
    print(f"JUMPI positions: {jumpis}")

