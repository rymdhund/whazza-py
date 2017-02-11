import zmq
import time
import os
import logging

from datetime import datetime
from .commands import commands, ssl_status, domain
from .base import Check
from .config import read_config

config = read_config()
config.setdefault('keys_dir', 'whazza_checker_keys')
config.setdefault('server_host', 'localhost')
config.setdefault('server_port', 5555)
config.setdefault('checker_id', 'default')


def send_msg(socket, msg):
    socket.send_json(msg)
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)
    if poller.poll(10 * 1000):  # 10s timeout in milliseconds
        response = socket.recv_json()
        logging.debug("Got response: {}".format(response))
        return response
    else:
        raise IOError("Timeout sending message")


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


def init_cert():
    ''' Generate certificate files if they don't exist '''
    from zmq import auth

    key_filename = "checker_{}".format(config['checker_id'])
    key_path = os.path.join(config['keys_dir'], key_filename)
    config['keyfile'] = keyfile = "{}.key_secret".format(key_path)

    if not (os.path.exists(keyfile)):
        logging.info("No client certificate found, generating")
        keys_dir = config['keys_dir']
        try:
            os.mkdir(keys_dir)
        except FileExistsError as e:
            pass

        # create new keys in certificates dir
        auth.create_certificates(keys_dir, key_filename)


def main():
    logging.basicConfig(level=logging.DEBUG)
    logging.info("starting")

    init_cert()

    # setup certificates
    client_public, client_secret = zmq.auth.load_certificate(config['keyfile'])
    server_public_file = os.path.join(config['keys_dir'], "server.key")
    server_public, _ = zmq.auth.load_certificate(server_public_file)

    # setup socket
    context = zmq.Context(1)
    socket = context.socket(zmq.REQ)
    socket.zap_domain = b"checker"
    socket.curve_secretkey = client_secret
    socket.curve_publickey = client_public
    socket.curve_serverkey = server_public

    # connect
    host = "tcp://{}:{}".format(config['server_host'], config['server_port'])
    logging.info("connecting to host {}".format(host))
    socket.connect(host)

    # check-in every 5 min by default
    check_in_key = 'checkers/{}/check-in'.format(config['checker_id'])
    rules = Rules()
    rules.add({'type': 'check-in', 'key': check_in_key, 'check_interval': 5 * 60, 'params': {}, 'checker': config['checker_id'], 'update_id': 0})

    # keep track of when the checks were run
    last_run = {}
    max_update_id = 0

    while(1):
        cmds = {
            'debian-up-to-date': commands.debian_up_to_date,
            'port-scan': commands.port_scan,
            'git-clean': commands.git_clean,
            'test': commands.test,
            'check-in': commands.test,
            'process-running': commands.process_running,
            'container-running': commands.container_running,
            'host-is-up': commands.host_is_up,
            'ssl-status': ssl_status.ssl_status,
            'domain-status': domain.domain_status,
        }

        new_rules = None
        logging.debug("Checking for something to do")
        for rule in rules.rules:
            if now() - last_run.get(rule['key'], 0) >= rule['check_interval']:
                logging.debug("running {}".format(rule['type']))
                if rule['type'] in cmds:
                    cmd = cmds[rule['type']]
                    try:
                        status, message = cmd(rule['params'])
                    except Exception as e:
                        logging.warn("Caught exception during check, {}".format(e))
                        status, message = 'fail', "Exception during check: {}".format(str(e))
                    check = Check(rule['key'], status, message, datetime.now())
                else:
                    logging.warn("Couldn't find command for type '{}'".format(rule['type']))
                    # maybe add a special status (panic?) for these "meta" fails?
                    check = Check(rule['key'], 'fail', "Couldn't find command for type '{}'", datetime.now())
                msg = {
                    'check': check.dict(),
                    'checker_id': config['checker_id'],
                    'max_update_id': max_update_id,
                }
                response = send_msg(socket, msg)
                rule_config = response.get('rule-config', [])
                if rule_config != []:
                    logging.debug("Info: updating config")
                    new_rules = rule_config

                last_run[rule['key']] = now()

        if new_rules is not None:
            for rule in new_rules:
                if rule['type'] == 'none':
                    rules.rm(rule['key'])
                    logging.info("Removed rule {}".format(rule['key']))
                else:
                    rules.add(rule)
                    logging.info("Updated rule {}".format(rule['key']))
                    if rule['update_id'] > max_update_id:
                        max_update_id = rule['update_id']
        else:
            time.sleep(10)

if __name__ == '__main__':
    if zmq.zmq_version_info() < (4, 0):
        raise RuntimeError("Security is not supported in libzmq version < 4.0. libzmq version {0}".format(zmq.zmq_version()))
    main()
