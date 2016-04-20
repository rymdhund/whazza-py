#import requests
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


class Rules:
    def __init__(self):
        self.rules = []

    def add(self, rule):
        if self.has_key(rule['key']):
            self.rm(rule['key'])
        self.rules.append(rule)

    def has_key(self, key):
        for r in self.rules:
            if key == r['key']:
                return True
        return False

    def rm(self, key):
        for r in self.rules:
            if key == r['key']:
                self.rules.remove(r)


def main():
    context = zmq.Context(1)
    socket = context.socket(zmq.REQ)
    host = "tcp://{}:{}".format(config['server_host'], config['server_port'])
    print("connecting to host {}".format(host))
    socket.connect(host)

    # check-in every 5 min by default
    check_in_key = 'checkers/{}/check-in'.format(config['checker_id'])
    rules = Rules()
    rules.add({'type': 'check-in', 'key': check_in_key, 'valid_period': 15*60, 'check_interval': 5*60, 'params': {}, 'checker': config['checker_id'], 'update_id': 0})

    # keep track of when the checks were run
    last_run = {}
    max_update_id = 0

    while(1):
        cmds = {
            'debian-update':        commands.check_debian_update,
            'portscan':             commands.port_scan,
            'git-status':           commands.check_git_status,
            'test':                 commands.test_command,
            'check-in':             commands.test_command,
            'process-running':      commands.process_running,
            'container-running':    commands.container_running
        }

        new_rules = None
        print("Checking for something to do")
        for rule in rules.rules:
            if now() - last_run.get(rule['key'], 0) >= rule['check_interval']:
                print("running {}".format(rule['type']))
                if rule['type'] in cmds:
                    cmd = cmds[rule['type']]
                    try:
                        status, message = cmd(rule['params'])
                    except Exception as e:
                        print("WARNING: caught exception during check, {}".format(e))
                        status, message = 'fail', "Exception during check: {}".format(str(e))
                    result_msg = {'key': rule['key'], 'status': status, 'msg': message, 'checker_id': config['checker_id']}
                else:
                    print("WARNING: Couldn't find command for type '{}'".format(rule['type']))
                    # maybe add a special status (panic?) for these "meta" fails?
                    result_msg = {'key': rule['key'], 'status': 'fail', 'msg': "Couldn't find command for type '{}'".format(rule['type']), 'checker_id': config['checker_id']}
                msg = result_msg
                msg['max_update_id'] = max_update_id
                response = send_msg(socket, msg)
                rule_config = response.get('rule-config', [])
                if rule_config != []:
                    print("Info: updating config")
                    new_rules = rule_config

                last_run[rule['key']] = now()

        if new_rules != None:
            for rule in new_rules:
                rules.add(rule)
                print("INFO: Updated rule {}".format(rule['key']))
                if rule['update_id'] > max_update_id:
                    max_update_id = rule['update_id']
        else:
            time.sleep(10)

if __name__ == '__main__':
    main()
