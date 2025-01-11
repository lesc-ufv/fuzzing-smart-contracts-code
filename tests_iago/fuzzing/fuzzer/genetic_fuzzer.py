
from utils.random_inputs import generate_random_inputs
from fuzzer.simulate_transaction import *
from code_coverage.code_coverage import *
from detector.reentrancy import *
import random

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
                    
                # save_lowlevelcalls(result, f"gen{generation}_{func_name}.json")
                if not result.failed:
                    for i, instruction in enumerate(result.structLogs):
                        pc = detect_reentrancy(sloads, calls, instruction)
                        if pc:
                            print(f"Detected reentrancy in {func_name}:", pc)
        #calculate the coverage from all the code
        calculate_coverage(coverage_map, total_pcs)
