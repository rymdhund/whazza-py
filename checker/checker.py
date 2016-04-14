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

check_in_key = 'checkers/{}/check-in'.format(config['checker_id'])
rules = {check_in_key: {'type': 'check-in', 'key': check_in_key, 'valid_period': 15*60, 'check_interval': 5*60, 'params': {}, 'checker': config['checker_id'], 'update_id': 0}}

def send_msg(socket, msg):
    socket.send(json.dumps(msg).encode())
    res = json.loads(socket.recv().decode())
    return res

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
        'test_command':     commands.test_command,
        'check-in':         commands.test_command
    }

    for rule in rules.values():
        print("running {}".format(rule['type']))
        if rule['type'] in cmds:
            cmd = cmds[rule['type']]
            status, message = cmd(rule['params'])
            result_msg = {'key': rule['key'], 'status': status, 'msg': message, 'checker_id': config['checker_id']}
            response = send_msg(socket, result_msg)
            rule_config = response.get('rule-config', [])
            if rule_config != []:
                print("Info: updating config")
                for rule_row in rule_config:
                    print("Info: setting rule '{}'".format(rule_row['key']))
                    rules[rule_row['key']] = rule_row
        else:
            print("ERROR: Couldn't find command '{}'".format(rule['command']))

if __name__ == '__main__':
    main()
