import solcx
import json

source_code_file = "EtherStorev2.sol"

with open(source_code_file, 'r') as file:
    source_code = file.read()

file.close()

# print(source_code)


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

print(json.dumps(out))
