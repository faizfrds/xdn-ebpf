import os

iden = 0

def parse_log(log_file):
    actions = []
    # Read line by line of the logs
    with open(log_file, "r") as f:
        for line in f:
            parts = line.strip().split(" ", 1)  # Splits it into 2 parts: action and params
            if len(parts) != 2:
                continue
            action, params = parts  # Assigns first part to action, second to params
            actions.append((action, params))  # Actions stores series of action, params
    return actions

def execute_actions(actions):
    global iden
    fd_map = {}  # Mapping to store file descriptors
    for action, params in actions:
        if action == "OPENTER":
            filename = params
            fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            iden += 1
            fd_map[iden] = fd
        elif action == "WRITE":
            count, offset, buffer = params.split(" ", 2)
            count = int(count)
            offset = int(offset)
            buffer = buffer.encode('utf-8')

            recent_id = max(fd_map.keys())
            os.lseek(fd_map[recent_id], offset, os.SEEK_SET)  # Use the most recent id
            os.write(fd_map[recent_id], buffer[:count])

log_file = "/tmp/statediff"
actions = parse_log(log_file)
execute_actions(actions)

