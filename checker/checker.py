import requests
import yaml
import sys
import subprocess
import zmq
import json
import time
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


def send_msg(socket, msg):
    socket.send(json.dumps(msg).encode())
    res = json.loads(socket.recv().decode())
    return res

def now():
    return time.time()

def main():
    context = zmq.Context(1)
    socket = context.socket(zmq.REQ)
    host = "tcp://{}:{}".format(config['server_host'], config['server_port'])
    print("connecting to host {}".format(host))
    socket.connect(host)

    check_in_key = 'checkers/{}/check-in'.format(config['checker_id'])
    rules = [{'type': 'check-in', 'key': check_in_key, 'valid_period': 15*60, 'check_interval': 5*60, 'params': {}, 'checker': config['checker_id'], 'update_id': 0}]
    last_run = {}

    while(1):
        cmds = {
            'debian_update':    commands.check_debian_update,
            'debian_update2':   commands.check_debian_update2,
            'portscan':         commands.port_scan,
            'git_status':       commands.check_git_status,
            'test':             commands.test_command,
            'check-in':         commands.test_command
        }


        new_rules = None
        print("Checking for something to do")
        for rule in rules:
            if now() - last_run.get(rule['key'], 0) >= rule['check_interval']:
                print("running {}".format(rule['type']))
                if rule['type'] in cmds:
                    cmd = cmds[rule['type']]
                    status, message = cmd(rule['params'])
                    result_msg = {'key': rule['key'], 'status': status, 'msg': message, 'checker_id': config['checker_id']}
                    response = send_msg(socket, result_msg)
                    rule_config = response.get('rule-config', [])
                    if rule_config != []:
                        print("Info: updating config")
                        new_rules = rule_config
                else:
                    print("ERROR: Couldn't find command '{}'".format(rule['command']))

                last_run[rule['key']] = now()

        if new_rules != None:
            rules = new_rules
            print("new rules: {}".format(rules))

        time.sleep(10)

if __name__ == '__main__':
    main()
