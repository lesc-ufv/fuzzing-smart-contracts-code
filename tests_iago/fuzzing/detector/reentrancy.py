def detect_reentrancy(sloads, calls, current_instruction):
    # Remember sloads
    if current_instruction["op"] == "SLOAD":
        storage_index = current_instruction["stack"][-1]
        sloads[storage_index] = current_instruction["pc"]
    # Remember calls with more than 2300 gas and where the value is larger than zero/symbolic or where destination is symbolic
    elif current_instruction["op"] == "CALL" and sloads:
        gas = int(current_instruction["stack"][-1], 16) # Gas da instrucao
        value = int(current_instruction["stack"][-3], 16) # Saldo atual do contrato

        if gas > 2300 and value > 0:
            calls.add(current_instruction["pc"])
            for pc in sloads.values():
                if pc < current_instruction["pc"]:
                    return current_instruction["pc"] # ENCONTRA REENTRADA AQUI!
    # Check if this sstore is happening after a call and if it is happening after an sload which shares the same storage index
    elif current_instruction["op"] == "SSTORE" and calls:
        storage_index = current_instruction["stack"][-1]
        if storage_index in sloads:
            for pc in calls:
                if pc < current_instruction["pc"]:
                    return pc # ENCONTRA REENTRADA AQUI!
    # Clear sloads and calls from previous transactions
    elif current_instruction["op"] in ["STOP", "RETURN", "REVERT", "ASSERTFAIL", "INVALID", "SUICIDE", "SELFDESTRUCT"]:
        sloads = dict()
        calls = set()
    return None # NÃO FOI ENCONTRADA REENTRADA!
