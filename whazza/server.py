import zmq
import threading
import os
import jsonschema
import logging
import requests
import time

from typing import Any, Dict, Tuple, List
from zmq.auth.thread import ThreadAuthenticator

from .config import read_config
from .core import Rule, Check
from .database import Database


config = read_config()
config.setdefault('keys_dir', 'whazza_server_keys')
config.setdefault('database', 'db.sqlite3')
config.setdefault('check_timeout', 300)  # 5 minute timeout by default


class ValidationError(Exception):
    pass


def setup_socket(auth_keys_dir: str, bind: str) -> zmq.Socket:
    # New context, to be able to do different auth
    ctx = zmq.Context()
    auth = ThreadAuthenticator(ctx)
    auth.start()

    # Setup auth
    auth.configure_curve(domain='*', location=auth_keys_dir)
    keyfile = os.path.join(config['keys_dir'], "server.key_secret")
    server_public, server_secret = zmq.auth.load_certificate(keyfile)

    # Configure and bind socket
    socket = ctx.socket(zmq.REP)
    socket.curve_secretkey = server_secret
    socket.curve_publickey = server_public
    socket.curve_server = True
    socket.bind(bind)

    return socket, auth


def notify(msg: str) -> None:
    if 'notification_url' in config:
        logging.info("Notify: {}".format(msg))

        if 'notification_base_msg' in config:
            payload = config['notification_base_msg']
        else:
            payload = {}
        payload['message'] = msg

        try:
            requests.post(config['notification_url'], data=payload)
        except Exception as e:
            logging.warn("Exception sending notification: {}".format(e))


def checker_listener(db: Database):
    logging.info("Starting checker listener")

    auth_keys_dir = os.path.join(config['keys_dir'], 'authorized_checkers')
    socket, auth = setup_socket(auth_keys_dir, "tcp://*:5555")

    while True:
        try:
            data = socket.recv_json()
            logging.debug("checker_listener: Got data: {}".format(data))
            check, checker, max_update_id = (
                Check.from_dict(data['check']),
                str(data['checker_id']),
                int(data['max_update_id'])
            )
        except Exception as e:
            logging.warning("Couldn't parse message", e)
            socket.send_json({"status": "fail"})
            continue

        try:
            rule = db.get_rule(check.rule_key)
            if rule is not None:
                logging.debug("checker_listener: Updating check".format(check.rule_key))

                # Notify if the status changed
                if check.status != db.get_notified_status(check.rule_key):
                    db.set_notification(check.rule_key, check.status)
                    msg = "Check {}. status '{}'".format(check.rule_key, check.status)
                    notify(msg)

                db.add_check(check)
            else:
                # Unknown check
                key_parts = check.rule_key.split('/')
                if len(key_parts) == 3 and key_parts[0] == 'checkers' and key_parts[-1] == 'check-in':
                    # A checker can do a check-in without being prompted
                    if key_parts[1] == checker:
                        logging.debug("checker_listener: First check-in from {}, creating rule".format(checker))
                        rule = Rule('check-in', check.rule_key, 5 * 60, {}, checker, -1)
                        db.add_rule(rule)
                        db.add_check(check)
                    else:
                        logging.warn("checker '{}' tried to check-in with {}", (checker, key_parts[1]))
                else:
                    logging.warn("unknown check for '{}'".format(check.rule_key))

            #  Send reply back to client
            new_rules = [rule.dict() for rule in db.get_new_rules(checker, max_update_id)]
            logging.debug("checker_listener: Responding")
            socket.send_json({'rule-config': new_rules})
        except Exception as e:
            logging.warning("Exception in checker_listener", e)


class ClientListener:
    def __init__(self, db: Database) -> None:
        self.db = db

    def run(self) -> None:
        logging.info("Starting client listener")
        auth_keys_dir = os.path.join(config['keys_dir'], 'authorized_clients')
        self.socket, auth = setup_socket(auth_keys_dir, "tcp://*:5556")

        while True:
            try:
                data = self.socket.recv_json()
                logging.debug("client_listener: Got data {}".format(data))
                cmd, data = self.parse_input(data)
            except Exception as e:
                logging.warning("client_listener: Couldn't parse message", e)
                self.socket.send_json({"status": "error", "message": "bad input"})
                continue
            try:
                msg = self.process_command(cmd, data)
                self.socket.send_json(msg)
            except Exception as e:
                logging.warning("client_listener: Couldn't process message", e)
                self.socket.send_json({"status": "error", "message": "bad input"})

    def process_command(self, cmd: str, data: Any) -> Dict[str, Any]:
        logging.debug("client_listener: handling message: {}".format(cmd))
        if cmd == 'status':
            logging.debug("client_listener: status")
            data = [s.dict() for s in self.db.get_statuses()]
            return {'status': 'ok', 'data': data}
        elif cmd == 'dump-rules':
            return {
                'status': 'ok',
                'data': [r.dict() for r in self.db.get_rules()]
            }
        elif cmd == 'set-rules':
            try:
                rules = self.parse_set_rules_data(data)
                self.db.update_rules(rules)
                return {'status': 'ok'}
            except Exception as e:
                logging.warn("client_listener: Error setting rules {}".format(e))
                return {'status': 'error', 'message': str(e)}
        return {"status": "error", "message": "Unknown command"}

    def parse_input(self, data: Dict[str, Any]) -> Tuple[str, Any]:
        schema = {
            "type": "object",
            "properties": {
                "cmd": {"type": "string"},
                "data": {"type": "object"},
            },
            "required": ["cmd"],
            "additionalProperties": False,
        }
        try:
            jsonschema.validate(data, schema)
            return data['cmd'], data.get('data', {})
        except jsonschema.ValidationError as e:
            logging.warn("Json doesn't follow schema: {}".format(str(e)))
            raise ValidationError("Error validating data: json doesn't follow schema")

    def parse_set_rules_data(self, data: Dict[str, Any]) -> List[Rule]:
        schema = {
            "type": "object",
            "properties": {
                "rules": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string"},
                            "key": {"type": "string"},
                            "check_interval": {
                                "type": "integer",
                                "minimum": 1,
                            },
                            "params": {"type": "object"},
                            "checker": {"type": "string"},
                        },
                    },
                },
            },
            "required": ["rules"],
            "additionalProperties": False,
        }
        rules = []
        try:
            jsonschema.validate(data, schema)
            for rule in data['rules']:
                rules.append(Rule(
                    rule['type'],
                    rule['key'],
                    rule['check_interval'],
                    rule['params'],
                    rule['checker'], -1))
        except jsonschema.ValidationError as e:
            logging.warn("In data from client, json doesn't follow schema: {}".format(str(e)))
            raise ValidationError("Error validating data: json doesn't follow schema")
        return rules


def init_cert() -> None:
    ''' Generate certificate files'''
    keys_dir = config['keys_dir']
    auth_checkers_dir = os.path.join(keys_dir, 'authorized_checkers')
    auth_clients_dir = os.path.join(keys_dir, 'authorized_clients')

    keyfile = os.path.join(keys_dir, "server.key_secret")

    if not (os.path.exists(keyfile)):
        logging.info("No server certificate found, generating")

        try:
            os.mkdir(keys_dir)
        except FileExistsError as e:
            pass

        try:
            os.mkdir(auth_checkers_dir)
        except FileExistsError as e:
            pass

        try:
            os.mkdir(auth_clients_dir)
        except FileExistsError as e:
            pass

        # create new keys in certificates dir
        zmq.auth.create_certificates(keys_dir, "server")


def expired_checker(db: Database) -> None:
    # check every minute for expired stuff
    # start by waiting 1m to give checkers time to check in when we're first starting
    while True:
        time.sleep(60)
        statuses = db.get_statuses()
        for s in statuses:
            if s.status == 'expired' and db.get_notified_status(s.rule_key) != 'expired':
                db.set_notification(s.rule_key, s.status)
                msg = "Check {}. status '{}'".format(s.rule_key, s.status)
                notify(msg)


########
# Main #
########

def main() -> None:
    logging.basicConfig(level=logging.DEBUG)

    init_cert()

    db = Database(config['database'], config)

    checker_thread = threading.Thread(target=checker_listener, args=(db,))
    checker_thread.start()

    client = ClientListener(db)
    client_thread = threading.Thread(target=client.run)
    client_thread.start()

    expired_thread = threading.Thread(target=expired_checker, args=(db,))
    expired_thread.start()


if __name__ == '__main__':
    main()
