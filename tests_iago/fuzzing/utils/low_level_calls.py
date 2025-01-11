import json

def save_lowlevelcalls(result, out_filename):
    result = dict(result)
    # Formatting output
    temp_logs = []
    for log in result["structLogs"]:
        temp_log = dict(log)
        temp_log["storage"] = dict(temp_log["storage"])
        temp_logs.append(temp_log)
    result["structLogs"] = temp_logs
    # Saving low-level calls to .json
    with open(out_filename, 'w') as fp:
        json.dump(result, fp)