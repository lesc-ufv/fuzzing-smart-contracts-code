import solcx
from compiler.instrumentation import *

def compile_smartcontract(compiler_version, contract_filename, source_code):

    if compiler_version not in solcx.get_installed_solc_versions():
        solcx.install_solc(compiler_version)
    solcx.set_solc_version(compiler_version, True)

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

    # Generate and modify the AST (add verification code)
    ast_json = generate_ast(compiler_output)
    modified_ast_json = modify_AST(ast_json)
    
    # After modifying the AST, generate the IR with the instrumented code
    ir_code = generate_ir_from_ast(modified_ast_json, contract_filename)
    
    print("Modified AST and IR generated")
    return compiler_output
