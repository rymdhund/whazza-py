import zmq
import json
import datetime
import threading
import sqlite3
import os
import jsonschema
import yaml
import sys
import logging
import requests
import time

from contextlib import closing
from zmq.auth.thread import ThreadAuthenticator

config = {}
try:
    configfile = os.environ.get('WHAZZA_CONFIG_FILE', "config.yml")
    with open(configfile, 'r') as stream:
        config = yaml.safe_load(stream)
except FileNotFoundError:
    print("INFO: No config file found, running with defaults")
except yaml.scanner.ScannerError:
    print("ERROR: Couldn't parse config file")
    sys.exit(1)

config.setdefault('database', 'db.sqlite3')
config.setdefault('keys_dir', 'keys')


class ValidationError(Exception):
    pass


def now():
    return datetime.datetime.now()


def parse_check_input(data):
    schema = {
        "type": "object",
        "properties": {
            "checker_id": {"type": "string"},
            "key": {"type": "string"},
            "status": {"enum": ["good", "fail"]},
            "msg": {"type": "string"},
            "max_update_id": {"type": "number"},
        },
        "required": ["checker_id", "key", "status", "msg", "max_update_id"],
        "additionalProperties": False,
    }
    try:
        jsonschema.validate(data, schema)
        return (data['key'],
                data['status'],
                data['msg'],
                data['checker_id'],
                data['max_update_id'])
    except jsonschema.ValidationError as e:
        logging.warn("Json doesn't follow schema: {}".format(str(e)))
        raise ValidationError("Error validating data: json doesn't follow schema")


def setup_socket(auth_keys_dir, bind):
    # New context, to be able to do different auth
    ctx = zmq.Context()
    auth = ThreadAuthenticator(ctx)
    auth.start()

    # Setup auth
    auth.configure_curve(domain='*', location=auth_keys_dir)
    server_public, server_secret = zmq.auth.load_certificate(config['keyfile'])

    # Configure and bind socket
    socket = ctx.socket(zmq.REP)
    socket.curve_secretkey = server_secret
    socket.curve_publickey = server_public
    socket.curve_server = True
    socket.bind(bind)

    return socket


def notify(msg):
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


def checker_listener(db):
    auth_keys_dir = os.path.join(config['keys_dir'], 'authorized_checkers')
    socket = setup_socket(auth_keys_dir, "tcp://*:5555")

    logging.info("Starting checker listener")
    while True:
        try:
            data = socket.recv_json()
            logging.debug("checker_listener: Got data: {}".format(data))
            key, status, msg, checker, max_update_id = parse_check_input(data)
        except Exception as e:
            logging.warn("Couldn't parse message")
            socket.send_json({"status": "fail"})
            continue

        check = Check(key, status, msg, now())

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
                    rule = Rule('check-in', check.rule_key, 15 * 60, 5 * 60, {}, checker, -1)
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


class ClientListener:
    def __init__(self, db):
        self.db = db

    def run(self):
        auth_keys_dir = os.path.join(config['keys_dir'], 'authorized_clients')
        self.socket = setup_socket(auth_keys_dir, "tcp://*:5556")

        logging.info("Starting client listener")
        while True:
            try:
                data = self.socket.recv_json()
                logging.debug("client_listener: Got data {}".format(data))
                cmd, data = self.parse_input(data)
            except Exception as e:
                logging.warn("client_listener: Couldn't parse message")
                self.socket.send_json({"status": "error", "message": "bad input"})
                continue
            try:
                msg = self.process_command(cmd, data)
                self.socket.send_json(msg)
            except Exception as e:
                logging.warn("client_listener: Couldn't parse message")
                self.socket.send_json({"status": "error", "message": "bad input"})

    def process_command(self, cmd, data):
        logging.debug("client_listener: handling message: {}".format(cmd))
        if cmd == 'status':
            logging.debug("client_listener: status")
            return {'status': 'ok', 'data': self.db.status_data()}
        elif cmd == 'dump-rules':
            return {'status': 'ok', 'data': self.db.rule_config_data()}
        elif cmd == 'set-rules':
            try:
                rules = self.parse_set_rules_data(data)
                self.db.update_rules(rules)
                return {'status': 'ok'}
            except Exception as e:
                logging.warn("client_listener: Error setting rules {}".format(e))
                return {'status': 'error', 'message': str(e)}
        return {"status": "error", "message": "Unknown command"}

    def parse_input(self, data):
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

    def parse_set_rules_data(self, data):
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
                    rule['check_interval'] * 3,
                    rule['check_interval'],
                    rule['params'],
                    rule['checker'], -1))
        except jsonschema.ValidationError as e:
            logging.warn("In data from client, json doesn't follow schema: {}".format(str(e)))
            raise ValidationError("Error validating data: json doesn't follow schema")
        return rules


class Rule:
    def __init__(self, type, key, valid_period, check_interval, params, checker, update_id):
        self.type = type
        self.key = key
        self.valid_period = valid_period
        self.check_interval = check_interval
        self.params = params
        self.checker = checker
        self.update_id = update_id

    def dict(self):
        return {'type': self.type, 'key': self.key, 'valid_period': self.valid_period, 'check_interval': self.check_interval,
                'params': self.params, 'checker': self.checker, 'update_id': self.update_id}

    def client_dict(self):
        return {'type': self.type, 'key': self.key, 'check_interval': self.check_interval, 'params': self.params, 'checker': self.checker}


class Check:
    def __init__(self, rule_key, status, msg, time):
        self.rule_key = rule_key
        self.status = status
        self.msg = msg
        self.time = time


############
# Database #
############

class Database:
    def __init__(self, filename):
        self.filename = filename

        self.status_to_int = {'good': 1, 'fail': 2, 'expired': 3}
        self.int_to_status = {1: 'good', 2: 'fail', 3: 'expired'}

        if not os.path.isfile(filename):
            logging.info("Creating database {}".format(filename))
            self._init_db()

    def _row_to_rule(self, row):
        params = json.loads(row[4])
        return Rule(row[0], row[1], row[2], row[3], params, row[5], row[6])

    def _get_rule(self, key, db):
        cur = db.execute("select type, key, valid_period, check_interval, params, checker, update_id from rules where key = ?", (key,))
        res = cur.fetchone()
        if res is not None:
            return self._row_to_rule(res)
        return None

    def get_rule(self, key):
        with closing(self._connect_db()) as db:
            return self._get_rule(key, db)

    def get_rules(self):
        with closing(self._connect_db()) as db:
            cur = db.execute("select type, key, valid_period, check_interval, params, checker, update_id from rules")
            return [self._row_to_rule(row) for row in cur.fetchall()]

    def _add_rule(self, rule, db):
        db.execute("""
        insert into rules (type, key, valid_period, check_interval, params, checker, update_id)
        values (?, ?, ?, ?, ?, ?, (select ifnull(max(update_id), 0)+1 from rules))
        """, (rule.type, rule.key, rule.valid_period, rule.check_interval, json.dumps(rule.params), rule.checker))

    def add_rule(self, rule):
        with closing(self._connect_db()) as db:
            self._add_rule(rule, db)
            db.commit()

    def get_new_rules(self, checker, update_id):
        with closing(self._connect_db()) as db:
            cur = db.execute("select type, key, valid_period, check_interval, params, checker, update_id from rules where checker=? and update_id > ?", (checker, update_id))
            return [self._row_to_rule(row) for row in cur.fetchall()]

    def _update_rule(self, rule, db):
        db.execute("""
        update rules set type=?, valid_period=?, check_interval=?, params=?, checker=?, update_id=(select ifnull(max(update_id), 0)+1 from rules)
        where key=?
        """, (rule.type, rule.valid_period, rule.check_interval, json.dumps(rule.params), rule.checker, rule.key))

    def update_rules(self, rules):
        with closing(self._connect_db()) as db:
            # remove all rules
            db.execute("""
            update rules set type='none', update_id=(select ifnull(max(update_id), 0)+1 from rules)
            """)

            for rule in rules:
                r = self._get_rule(rule.key, db)
                if r is None:
                    self._add_rule(rule, db)
                else:
                    self._update_rule(rule, db)
            db.commit()

    def add_check(self, check):
        with closing(self._connect_db()) as db:

            db.execute("""
            insert into checks (rule_key, time, status, msg) values (?, ?, ?, ?)
            """, (check.rule_key, check.time, self.status_to_int[check.status], check.msg))
            db.commit()

    def set_notification(self, key, status):
        with closing(self._connect_db()) as db:
            db.execute("delete from notifications where rule_key = ?", (key,))

            # dont save anything on "good" status
            if status != 'good':
                db.execute("insert into notifications (rule_key, status) values (?, ?)", (key, self.status_to_int[status]))
            db.commit()

    def get_notified_status(self, key):
        """ Returns 'good' if we haven't sent any notifications
        """
        with closing(self._connect_db()) as db:
            cur = db.execute("select status from notifications where rule_key = ?", (key,))
            row = cur.fetchone()
            if row:
                return self.int_to_status[row[0]]
            else:
                return 'good'

    def status_data(self):
        with closing(self._connect_db()) as db:
            # Find last successful check for each rule
            cur = db.execute("""
                select c1.rule_key, c1.time
                from (select * from checks where status = 1) c1
                left join checks c2
                on (c1.rule_key = c2.rule_key and c1.time < c2.time and c2.status = 1)
                where c2.id is null
            """)
            last_successful = {}
            for row in cur.fetchall():
                last_successful[row[0]] = row[1].timestamp()
            cur.close()

            # Find last check for each rule
            cur = db.execute("""
                select c1.rule_key, c1.status, c1.msg, c1.time
                from checks c1
                left join checks c2
                on (c1.rule_key = c2.rule_key and c1.time < c2.time)
                left join rules r
                on (c1.rule_key = r.key)
                where c2.id is null and r.type != 'none'
            """)
            ret = []
            for row in cur.fetchall():
                key, status, time, message = row[0], self.int_to_status[row[1]], row[3], row[2]
                rule = self.get_rule(key)
                if now() - time > datetime.timedelta(0, rule.valid_period):
                    status = 'expired'
                    message = ""

                ret.append({'key': key, 'status': status, 'message': message, 'time': time.timestamp(), 'last_successful': last_successful.get(key, None)})

            # append rules that don't have any check data yet
            cur = db.execute("""
                select r.key from rules r
                left join checks c
                on (r.key = c.rule_key)
                where c.id is null and r.type != 'none'
            """)
            for row in cur.fetchall():
                key = row[0]
                ret.append({'key': key, 'status': 'nodata', 'message': "No data on this rule yet", 'time': now().timestamp(), 'last_successful': None})
            return ret

    def rule_config_data(self):
        rules = self.get_rules()
        return [rule.client_dict() for rule in rules if rule.type != 'none']

    def _connect_db(self):
        return sqlite3.connect(self.filename, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)

    def _init_db(self):
        with closing(self._connect_db()) as db:
            with open('schema.sql', mode='r') as f:
                db.cursor().executescript(f.read())
            db.commit()


def init_cert():
    ''' Generate certificate files'''
    keys_dir = config['keys_dir']
    auth_checkers_dir = os.path.join(keys_dir, 'authorized_checkers')
    auth_clients_dir = os.path.join(keys_dir, 'authorized_clients')

    config['keyfile'] = keyfile = os.path.join(keys_dir, "server.key_secret")

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


def expired_checker(db):
    # check every minute for expired stuff
    # start by waiting 1m to give checkers time to check in when we're first starting
    while True:
        time.sleep(60)
        statuses = db.status_data()
        for s in statuses:
            if s['status'] == 'expired' and db.get_notified_status(s['key']) != 'expired':
                db.set_notification(s['key'], s['status'])
                msg = "Check {}. status '{}'".format(s['key'], s['status'])
                notify(msg)


########
# Main #
########

def main():
    logging.basicConfig(level=logging.DEBUG)

    init_cert()

    db = Database(config['database'])

    checker_thread = threading.Thread(target=checker_listener, args=(db,))
    checker_thread.start()

    client = ClientListener(db)
    client_thread = threading.Thread(target=client.run)
    client_thread.start()

    expired_thread = threading.Thread(target=expired_checker, args=(db,))
    expired_thread.start()


if __name__ == '__main__':
    main()
