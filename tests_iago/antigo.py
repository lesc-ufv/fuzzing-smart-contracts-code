import sys
import solcx
import re
import json
import logging
import web3
from web3 import eth as eth
import pickle
from eth_utils import encode_hex, decode_hex, to_canonical_address
from web3 import Web3
from web3 import EthereumTesterProvider
import eth_utils
import collections
import random
import pyethereum





#/////////////////SETTINGS IMPORTS///////////////////////////////

# List of attacker accounts
ATTACKER_ACCOUNTS = ["0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]
# Default account balance
ACCOUNT_BALANCE = 100000000*(10**18)
# Default gas limit for sending transactions
GAS_LIMIT = 4500000


#//////////////FUZZING PROCESS/////////////


#create a 'AMBIENT' to the fuzzing can run
def fuzzing_environment(**kwargs):
    environment = {
        "nr_of_transactions": 0,
        "unique_individuals": set(),
        "code_coverage": set(),
        "children_code_coverage": dict(),
        "previous_code_coverage_length": 0,
        "visited_branches": dict(),
        "memoized_fitness": dict(),
        "memoized_storage": dict(),
        "memoized_symbolic_execution": dict(),
        "individual_branches": dict(),
        "data_dependencies": dict(),
    }

    # Update the environment with any kwargs passed in
    environment.update(kwargs)

    return environment



def initialize_fuzzer(self, contract_name, abi, deployment_bytecode, runtime_bytecode, test_instrumented_evm, blockchain_state, solver, args, seed, source_map=None):
    print("Fuzzer: ")
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
    self.env = fuzzing_environment(instrumented_evm=self.instrumented_evm,
                                    contract_name=self.contract_name,
                                    solver=self.solver,
                                    results=self.results,
                                    interface=self.interface,
                                    overall_pcs=self.overall_pcs,
                                    overall_jumpis=self.overall_jumpis,
                                    len_overall_pcs_with_children=0,
                                    other_contracts = list(),
                                    args=args,
                                    seed=seed,
                                #   cfg=cfg,  graph
                                    abi=abi)
#The FROM contract refers to the address or entity that is initiating the transaction or interaction. 
#This can be an externally owned account (EOA, a user) or another smart contract.
#The TO contract refers to the destination address, typically a smart contract that is receiving the transaction or interaction.


    def running_fuzzer(self):
        contract_address = None
        self.instrumented_evm.create_fake_accounts()
        print("Creating fake accounts for transactions...")
        # Always deploy the contract, ignoring the 'to' field
        for transaction in self.blockchain_state:
            print("Processing transaction from %s...", transaction['from'])

            # Check if the sender account already exists; if not, create a fake account
            if transaction['from'].lower() not in self.instrumented_evm.accounts:
                self.instrumented_evm.accounts.append(self.instrumented_evm.create_fake_account(transaction['from']))
                print("Created fake account for %s", transaction['from'])

            # Always deploy the contract
            print("Deploying contract from %s...", transaction['from'])
            result = self.instrumented_evm.deploy_contract(
                transaction['from'],
                transaction['input'],
                int(transaction['value']),
                int(transaction['gas']),
                int(transaction['gasPrice'])
            )

            # Handle errors if deployment fails
            if result.is_error:
                print("Error deploying contract %s using account %s. Error message: %s",
                            self.contract_name, transaction['from'], result._error)
                sys.exit(-2)
            else:
                contract_address = encode_hex(result.msg.storage_address)
                self.instrumented_evm.accounts.append(contract_address)
                self.env.nr_of_transactions += 1
                print("Contract deployed at %s", contract_address)

                # Analyze the bytecode of the deployed contract (pcs and jumpis)
                print("Analyzing deployed contract bytecode...")
                pcs, jumpis = get_pcs_and_jumpis(
                    self.instrumented_evm.get_code(to_canonical_address(contract_address)).hex()
                )
                print("Program Counters (pcs): %s", pcs)
                print("JUMPI positions: %s", jumpis)

                self.env.overall_pcs.extend(pcs)
                self.env.overall_jumpis.extend(jumpis)

        print("All transactions processed.")
        
        
        

####################################################################################
                            
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
        #print(source_map)
        
        #initialize_fuzzer(contract_name, contract["abi"], contract['evm']['bytecode']['object'], contract['evm']['deployedBytecode']['object'], instrumented_evm, blockchain_state, solver, args, seed, source_map).run()
#################################################################################################3

#///////////////////VIRTUAL MACHINE//////////////////////////////////










#///////////////////////////////////////////////////////////////////////////////

# Source map from utils
# tools to do the sourcemap func

# func that removes the hash from the bytecode
def remove_swarm_hash(bytecode):
    if isinstance(bytecode, str):
        if bytecode.endswith("0029"):
            bytecode = re.sub(r"a165627a7a72305820\S{64}0029$", "", bytecode)
        if bytecode.endswith("0033"):
            bytecode = re.sub(r"5056fe.*?0033$", "5056", bytecode)
            #print(bytecode)
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
    #print(f"Contract: {contract_name}")
    #print(f"Program Counters (pcs): {pcs}")
    #print(f"JUMPI positions: {jumpis}")

#source map



#source code 
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

# Cmaps using the source code in solidity
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
            pcs, jumpis = get_pcs_and_jumpis(bytecode)  # get the instructions pcs and jumpis
            for j, pc in enumerate(pcs):
                if j < len(self.positions) and self.positions[j]:
                    instr_positions[pc] = self.positions[j]  
            return instr_positions
        except Exception as e:
            print(f"Erro ao mapear instruções: {e}")
            return instr_positions

    @classmethod
    def _load_position_groups_standard_json(cls):
        # position groups
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




#//////////////////////////////////Generator////////////////////////////////////////
MAX_RING_BUFFER_LENGTH = 10
#creates a dequeue for the data
class CircularSet:
    def __init__(self,set_size=MAX_RING_BUFFER_LENGTH,initial_set=None):
        self._q =collections.deque(maxlen=set_size)#deque is a data struccture similar to a queue, but with two "heads"
        if initial_set:
            self._q.extend(initial_set)
    def empty(self):
        return len(self._q) == 0

    def add(self, value):
        if value not in self._q:
            self._q.append(value)
        else:
            self._q.remove(value)
            self._q.append(value)

    def head_and_rotate(self):
        value = self._q[-1]
        self._q.rotate(1)
        return value

    def discard(self, value):
        if value in self._q:
            self._q.remove(value)

    def __repr__(self):
        return repr(self._q)



class Generator:
    def __init__(self,interface,bytecode,accounts, contract) -> None:
        self.interface = interface
        self.bytecode = bytecode
        self.accounts = accounts
        self.contract = contract
        
        #pools
        self.function_circular_buffer = CircularSet(set_size=len(self.interface),initial_set=set(self.interface))
        self.accounts_pool = {}
        self.amounts_pool = {}
        self.arguments_pool = {}
        self.timestamp_pool = {}
        self.blocknumber_pool = {}
        self.balance_pool = {}
        self.callresult_pool = {}
        self.gaslimit_pool = {}
        self.extcodesize_pool = {}
        self.returndatasize_pool = {}
        self.argument_array_sizes_pool = {}
        self.strings_pool = CircularSet()
        self.bytes_pool = CircularSet()
        
        
        
        #gives us a tuple with transactions, one for constructor and one for de fun call
        
    def generate_random_individual(self):
        individual = [] 
        if "constructor" in self.interface and self.bytecode:
            arguments = ["constructor"]
            for index in range(len(self.interface["constructor"])):
                arguments.append(self.get_random_argument(self.interface["constructor"][index],"constructor", index))
        individual.append({
            
            
            ########TO DO FUNC########
           "account": self.get_random_account("constructor"),
            "contract": self.bytecode,
            "amount": self.get_random_amount("constructor"),
            "arguments": arguments,
            "blocknumber": self.get_random_blocknumber("constructor"),
            "timestamp": self.get_random_timestamp("constructor"),
            "gaslimit": self.get_random_gaslimit("constructor"),
            "returndatasize": dict()
        })
    
        """
        all the functions above just add values to the data of the generators
        one add, remove, get and clear each one of them
        """
    # TIMESTAMP
    

    def add_timestamp_to_pool(self, function, timestamp):
        if not function in self.timestamp_pool:
            self.timestamp_pool[function] = CircularSet()
        self.timestamp_pool[function].add(timestamp)

    def get_random_timestamp(self, function):
        if function in self.timestamp_pool:
            return self.timestamp_pool[function].head_and_rotate()
        return None

    def remove_timestamp_from_pool(self, function, timestamp):
        if function in self.timestamp_pool:
            self.timestamp_pool[function].discard(timestamp)
            if self.timestamp_pool[function].empty:
                del self.timestamp_pool[function]

    
    # BLOCKNUMBER
    

    def add_blocknumber_to_pool(self, function, blocknumber):
        if not function in self.blocknumber_pool:
            self.blocknumber_pool[function] = CircularSet()
        self.blocknumber_pool[function].add(blocknumber)

    def get_random_blocknumber(self, function):
        if function in self.blocknumber_pool:
            return self.blocknumber_pool[function].head_and_rotate()
        return None

    def remove_blocknumber_from_pool(self, function, blocknumber):
        if function in self.blocknumber_pool:
            self.blocknumber_pool[function].discard(blocknumber)
            if self.blocknumber_pool[function].empty:
                del self.blocknumber_pool[function]

    
    # BALANCE
    

    def add_balance_to_pool(self, function, balance):
        if not function in self.balance_pool:
            self.balance_pool[function] = CircularSet()
        self.balance_pool[function].add(balance)

    def get_random_balance(self, function):
        if function in self.balance_pool:
            return self.balance_pool[function].head_and_rotate()
        return None

    
    # CALL RESULT
    

    def add_callresult_to_pool(self, function, address, result):
        if not function in self.callresult_pool:
            self.callresult_pool[function] = dict()
        if not address in self.callresult_pool[function]:
            self.callresult_pool[function][address] = CircularSet()
        self.callresult_pool[function][address].add(result)

    def get_random_callresult_and_address(self, function):
        if function in self.callresult_pool:
            address = random.choice(list(self.callresult_pool[function].keys()))
            value = self.callresult_pool[function][address].head_and_rotate()
            return address, value
        return None, None

    def get_random_callresult(self, function, address):
        if function in self.callresult_pool:
            if address in self.callresult_pool[function]:
                value = self.callresult_pool[function][address].head_and_rotate()
                return value
        return None

    def remove_callresult_from_pool(self, function, address, result):
        if function in self.callresult_pool and address in self.callresult_pool[function]:
            self.callresult_pool[function][address].discard(result)
            if self.callresult_pool[function][address].empty:
                del self.callresult_pool[function][address]
                if len(self.callresult_pool[function]) == 0:
                    del self.callresult_pool[function]

    
    # EXTCODESIZE
    

    def add_extcodesize_to_pool(self, function, address, size):
        if not function in self.extcodesize_pool:
            self.extcodesize_pool[function] = dict()
        if not address in self.extcodesize_pool[function]:
            self.extcodesize_pool[function][address] = CircularSet()
        self.extcodesize_pool[function][address].add(size)

    def get_random_extcodesize_and_address(self, function):
        if function in self.extcodesize_pool:
            address = random.choice(list(self.extcodesize_pool[function].keys()))
            return address, self.extcodesize_pool[function][address].head_and_rotate()
        return None, None

    def get_random_extcodesize(self, function, address):
        if function in self.extcodesize_pool:
            if address in self.extcodesize_pool[function]:
                return self.extcodesize_pool[function][address].head_and_rotate()
        return None

    def remove_extcodesize_from_pool(self, function, address, size):
        if function in self.extcodesize_pool and address in self.extcodesize_pool[function]:
            self.extcodesize_pool[function][address].discard(size)
            if self.extcodesize_pool[function][address].empty:
                del self.extcodesize_pool[function][address]
                if len(self.extcodesize_pool[function]) == 0:
                    del self.extcodesize_pool[function]

    
    # RETURNDATASIZE
    
    def add_returndatasize_to_pool(self, function, address, size):
        if not function in self.returndatasize_pool:
            self.returndatasize_pool[function] = dict()
        if not address in self.returndatasize_pool[function]:
            self.returndatasize_pool[function][address] = CircularSet()
        self.returndatasize_pool[function][address].add(size)

    def get_random_returndatasize_and_address(self, function):
        if function in self.returndatasize_pool:
            address = random.choice(list(self.returndatasize_pool[function].keys()))
            return address, self.returndatasize_pool[function][address].head_and_rotate()
        return None, None

    def get_random_returndatasize(self, function, address):
        if function in self.returndatasize_pool:
            if address in self.returndatasize_pool[function]:
                return self.returndatasize_pool[function][address].head_and_rotate()
        return None

    def remove_returndatasize_from_pool(self, function, address, size):
        if function in self.returndatasize_pool and address in self.returndatasize_pool[function]:
            self.returndatasize_pool[function][address].discard(size)
            if self.returndatasize_pool[function][address].empty:
                del self.returndatasize_pool[function][address]
                if len(self.returndatasize_pool[function]) == 0:
                    del self.returndatasize_pool[function]

    
    # GASLIMIT
    

    def add_gaslimit_to_pool(self, function, gaslimit):
        if not function in self.gaslimit_pool:
            self.gaslimit_pool[function] = CircularSet()
        self.gaslimit_pool[function].add(gaslimit)

    def remove_gaslimit_from_pool(self, function, gaslimit):
        if function in self.gaslimit_pool:
            self.gaslimit_pool[function].discard(gaslimit)
            if self.gaslimit_pool[function].empty:
                del self.gaslimit_pool[function]

    def clear_gaslimits_in_pool(self, function):
        if function in self.gaslimit_pool:
            del self.gaslimit_pool[function]

    def get_random_gaslimit(self, function):
        if function in self.gaslimit_pool:
            return self.gaslimit_pool[function].head_and_rotate()
        return GAS_LIMIT

    
    # ACCOUNTS
    

    def add_account_to_pool(self, function, account):
        if not function in self.accounts_pool:
            self.accounts_pool[function] = CircularSet()
        self.accounts_pool[function].add(account)

    def remove_account_from_pool(self, function, account):
        if function in self.accounts_pool:
            self.accounts_pool[function].discard(account)
            if self.accounts_pool[function].empty:
                del self.accounts_pool[function]

    def clear_accounts_in_pool(self, function):
        if function in self.accounts_pool:
            self.accounts_pool[function] = CircularSet()

    def get_random_account_from_pool(self, function):
        return self.accounts_pool[function].head_and_rotate()

    def get_random_account(self, function):
        if function in self.accounts_pool:
            return self.get_random_account_from_pool(function)
        else:
            return random.choice(self.accounts)

    
    # AMOUNTS
    

    def add_amount_to_pool(self, function, amount):
        if not function in self.amounts_pool:
            self.amounts_pool[function] = CircularSet()
        self.amounts_pool[function].add(amount)

    def remove_amount_from_pool(self, function, amount):
        if function in self.amounts_pool:
            self.amounts_pool[function].discard(amount)
            if self.amounts_pool[function].empty:
                del self.amounts_pool[function]

    def get_random_amount_from_pool(self, function):
        return self.amounts_pool[function].head_and_rotate()

    def get_random_amount(self, function):
        if function in self.amounts_pool:
            amount = self.get_random_amount_from_pool(function)
        else:
            amount = random.randint(0, 1)
            self.add_amount_to_pool(function, amount)
            self.add_amount_to_pool(function, 1 - amount)
        return amount

    
    # STRINGS
    

    def add_string_to_pool(self, string):
        self.strings_pool.add(string)


    def get_random_string_from_pool(self):
        return self.strings_pool.head_and_rotate()

    
    # BYTES
    

    def add_bytes_to_pool(self, string):
        self.bytes_pool.add(string)


    def get_random_bytes_from_pool(self):
        return self.bytes_pool.head_and_rotate()
            

    
