import requests
import yaml
import sys
import subprocess
import zmq
import json
from git import Repo

import commands

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
config.setdefault('server_port', 5555)
#config.setdefault('status_resource', '/incoming')
config.setdefault('rules', [])


def send_msg(socket, msg):
    print("  sending message")
    socket.send(json.dumps(msg).encode())
    #  Get the reply.
    print("  waiting for reply")
    res = socket.recv()
    print("  Received reply {}".format(res))


def main():
    context = zmq.Context(1)
    socket = context.socket(zmq.REQ)
    host = "tcp://{}:{}".format(config['server_host'], config['server_port'])
    print("connecting to host {}".format(host))
    socket.connect(host)

    cmds = {
        'debian_update':    commands.check_debian_update,
        'debian_update2':   commands.check_debian_update2,
        'portscan':         commands.port_scan,
        'git_status':       commands.check_git_status,
        'test_command':     commands.test_command
    }

    for rule in config['rules']:
        print("running {}".format(rule['name']))
        if rule['command'] in cmds:
            cmd = cmds[rule['command']]
            status, message = cmd(rule['params'])
            print("  result: {}".format((status, message)))
            result_msg = {'key': rule['key'], 'status': status, 'message': message}
            send_msg(socket, result_msg)
        else:
            print("ERROR: Couldn't find command '{}'".format(rule['command']))

if __name__ == '__main__':
    main()
