def simulate_transaction(w3, contract, function_name, inputs=None, value=0):
    try:
        if inputs:
            # Sorting inputs accordingly with function parameters
            sorted_inputs = [inputs[param['name']] for param in contract.functions[function_name].abi['inputs']]
            txn = getattr(contract.functions, function_name)(*sorted_inputs).transact({'value': value})
        else:
            txn = getattr(contract.functions, function_name)().transact({'value': value})
        tx_receipt = w3.eth.wait_for_transaction_receipt(txn)
        print(f"Transaction '{function_name}' executed successfully: {tx_receipt.transactionHash.hex()}")
        return tx_receipt
    except Exception as e:
        print(f"Error during transaction '{function_name}' execution: {e}")
        return None
