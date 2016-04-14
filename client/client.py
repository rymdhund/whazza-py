import yaml
import sys
import zmq
import json
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
            times = humanize.naturaltime(datetime.fromtimestamp(row['time']), "%Y-%m-%d %H:%M")
            print("{:20s}   {:5s}   {}   {}".format(row['key'], row['status'], times, row['message']))
    else:
        print("Error: {}".format(res['message']))

def main():
    context = zmq.Context(1)
    socket = context.socket(zmq.REQ)
    host = "tcp://{}:{}".format(config['server_host'], config['server_port'])
    print("connecting to host {}".format(host))
    socket.connect(host)

    status(socket)

if __name__ == '__main__':
    main()
