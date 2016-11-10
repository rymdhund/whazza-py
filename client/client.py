import yaml
import sys
import zmq
import json
import fileinput
from datetime import datetime
import humanize

config = {}
try:
    with open("config.yml", 'r') as stream:
        config = yaml.safe_load(stream)
except FileNotFoundError:
    print("INFO: No config file found, running with defaults")
except yaml.scanner.ScannerError:
    print("ERROR: Couldn't parse config file")
    sys.exit(1)

config.setdefault('server_host', 'localhost')
config.setdefault('server_port', 5556)


def send_msg(socket, msg):
    socket.send(json.dumps(msg).encode())
    res = json.loads(socket.recv().decode())
    return res


def status(socket):
    res = send_msg(socket, {'cmd': "status"})
    if res['status'] == 'ok':
        print("Status:")
        print("=======")
        for row in res['data']:
            message = row['message'].replace("\n", " ")
            if len(message) > 43:
                message = message[:40] + "..."
            times = humanize.naturaltime(datetime.fromtimestamp(row['time']), "%Y-%m-%d %H:%M")
            print("{:30s}   {:15s}   {:20s}   {}".format(row['key'], row['status'], times, message))
    else:
        print("Error: {}".format(res['message']))


def dump_rules(socket):
    res = send_msg(socket, {'cmd': 'dump-rules'})
    if res['status'] == 'ok':
        print(json.dumps(res['data'], sort_keys=True, indent=2))
    else:
        print("Error: {}".format(res['message']))


def set_rules(socket, filename):
    inp = ""
    for line in fileinput.input(filename):
        inp += line

    rules = json.loads(inp)

    res = send_msg(socket, {'cmd': 'set-rules', 'data': {'rules': rules}})
    if res['status'] == 'ok':
        print("updated")
    else:
        print("Error: {}".format(res['message']))


def usage(ret):
    print("usage: {} <cmd>".format(sys.argv[0]))
    print("where cmd is:")
    print("  status")
    print("  dump-rules")
    print("  set-rules <filename>")
    sys.exit(ret)


def main():
    if len(sys.argv) < 2:
        usage(1)

    context = zmq.Context(1)
    socket = context.socket(zmq.REQ)
    host = "tcp://{}:{}".format(config['server_host'], config['server_port'])
    socket.connect(host)

    cmd = sys.argv[1]
    if cmd == "status":
        status(socket)
    elif cmd == "dump-rules":
        dump_rules(socket)
    elif cmd == "set-rules":
        if len(sys.argv) != 3:
            usage(1)
        set_rules(socket, sys.argv[2])
    else:
        usage(1)

if __name__ == '__main__':
    main()
