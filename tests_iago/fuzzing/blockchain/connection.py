from web3 import Web3

def connect_in_blockchain(url):
    w3 = Web3(Web3.HTTPProvider(url))
    if w3.is_connected():
        print("Blockchain connected successfully!")
        w3.eth.default_account = w3.eth.accounts[0]
        return w3
    print("Error during the connection with the blockchain!")
    return None

def deploy_smartcontract(w3, abi, bytecode):
    smart_contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = smart_contract.constructor().transact()
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = tx_receipt.contractAddress
    print(f"Contract Address: {contract_address}")
    return w3.eth.contract(address=contract_address, abi=abi)
