import time
import zmq
import json
import datetime
import threading
import copy
import sqlite3
import os
from contextlib import closing

config = {}
try:
    with open("config.yml", 'r') as stream:
        config = yaml.safe_load(stream)
except FileNotFoundError:
    print("INFO: No config file found, running with defaults")
except yaml.scanner.ScannerError:
    print("ERROR: Couldn't parse config file")
    sys.exit(1)

config.setdefault('database', 'db.sqlite3')

def now():
    return datetime.datetime.now()


def checker_listener(socket, db):
    while True:
        message = socket.recv().decode()
        print("Received checker request: %s" % message)

        data = json.loads(message)

        check = Check(data['key'], data['status'], data['msg'], now())
        checker = data['checker_id']

        rule = db.get_rule(check.rule_key)
        if rule != None:
            db.add_check(check)
        else:
            key_parts = check.rule_key.split('/')
            if len(key_parts) == 3 and key_parts[0] == 'checkers' and key_parts[-1] == 'check-in':
                if key_parts[1] == checker:
                    print("First check-in from {}, creating rule".format(checker))
                    rule = Rule('check-in', check.rule_key, 15*60, 5*60, {}, checker, -1)
                    db.add_rule(rule)
                    db.add_check(check)
                else:
                    print("Warning: checker '{}' tried to check-in with {}", (checker, key_parts[1]))
            else:
                print("Warning: unknown check for '{}'".format(check.rule_key))

        #  Send reply back to client
        new_rules = [rule.dict() for rule in db.get_new_rules(checker, 0)] # TODO: get last update id from client
        socket.send(json.dumps({'rule-config': new_rules}).encode())

def client_listener(socket, db):
    while True:
        message = socket.recv().decode()
        print("Received client request: %s" % message)

        data = json.loads(message)

        if data['cmd'] == 'status':
            msg = {'status': 'ok', 'data': db.status_data()}
            socket.send(json.dumps(msg).encode())
        elif data['cmd'] == 'dump-rules':
            msg = {'status': 'ok', 'data': db.rule_config_data()}
            socket.send(json.dumps(msg).encode())
        elif data['cmd'] == 'set-rules':
            for rule in data['data']:
                print("setting rule {}".format(rule))
                db.set_rule(Rule(rule['type'], rule['key'], rule['valid_period'], rule['check_interval'], rule['params'], rule['checker'], -1))
            msg = {'status': 'ok', 'data': db.rule_config_data()}
            socket.send(json.dumps(msg).encode())
        else:
            msg = {"status": "error", "message": "Unknown command"}
            socket.send(json.dumps(msg).encode())

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

        self.status_to_int = {'good': 1, 'fail': 2}
        self.int_to_status = {1: 'good', 2: 'fail'}

        if not os.path.isfile(filename):
            print("Creating database")
            self._init_db()

    def _row_to_rule(self, row):
        params = json.loads(row[4])
        return Rule(row[0], row[1], row[2], row[3], params, row[5], row[6])

    def get_rule(self, key):
        with closing(self._connect_db()) as db:
            cur = db.execute("select type, key, valid_period, check_interval, params, checker, update_id from rules where key = ?", (key,))
            res = cur.fetchone()
            if res != None:
                return self._row_to_rule(res)
            return None

    def get_rules(self):
        with closing(self._connect_db()) as db:
            cur = db.execute("select type, key, valid_period, check_interval, params, checker, update_id from rules")
            return [self._row_to_rule(row) for row in cur.fetchall()]

    def add_rule(self, rule):
        with closing(self._connect_db()) as db:
            db.execute("""
            insert into rules (type, key, valid_period, check_interval, params, checker, update_id)
            values (?, ?, ?, ?, ?, ?, (select ifnull(max(update_id), 0)+1 from rules))
            """, (rule.type, rule.key, rule.valid_period, rule.check_interval, json.dumps(rule.params), rule.checker))
            db.commit()

    def get_new_rules(self, checker, update_id):
        with closing(self._connect_db()) as db:
            cur = db.execute("select type, key, valid_period, check_interval, params, checker, update_id from rules where checker=? and update_id > ?", (checker, update_id))
            return [self._row_to_rule(row) for row in cur.fetchall()]

    def set_rule(self, rule):
        r = self.get_rule(rule.key)
        if r == None:
            self.add_rule(rule)
        else:
            with closing(self._connect_db()) as db:
                db.execute("""
                update rules set type=?, valid_period=?, check_interval=?, params=?, checker=?, update_id=(select ifnull(max(update_id), 0)+1 from rules)
                where key=?
                """, (rule.type, rule.valid_period, rule.check_interval, json.dumps(rule.params), rule.checker, rule.key))
                db.commit()

    def add_check(self, check):
        with closing(self._connect_db()) as db:

            db.execute("""
            insert into checks (rule_key, time, status, msg) values (?, ?, ?, ?)
            """, (check.rule_key, check.time, self.status_to_int[check.status], check.msg))
            db.commit()

    def status_data(self):
        with closing(self._connect_db()) as db:
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

            cur = db.execute("""
                select c1.rule_key, c1.status, c1.msg, c1.time
                from checks c1
                left join checks c2
                on (c1.rule_key = c2.rule_key and c1.time < c2.time)
                where c2.id is null
            """)
            ret = []
            for row in cur.fetchall():
                key, status, time = row[0], self.int_to_status[row[1]], row[3]
                print("getting rule {}".format(key))
                rule = self.get_rule(key)
                print("{}".format(time))
                print("{}".format(type(time)))
                if now() - time > datetime.timedelta(0, rule.valid_period):
                    status = 'expired'

                ret.append({'key': key, 'status': status, 'message': row[2], 'time': time.timestamp(), 'last_successful': last_successful.get(key, None)})


            # append rules that don't have any data yet
            cur = db.execute("""
                select r.key from rules r
                left join checks c
                on (r.key = c.rule_key)
                where c.id is null
            """)
            for row in cur.fetchall():
                key = row[0]
                ret.append({'key': key, 'status': 'nodata', 'message': "No data on this rule yet", 'time': now().timestamp(), 'last_successful': None})
            return ret

    def rule_config_data(self):
        rules = self.get_rules()
        return [rule.dict() for rule in rules]

    def _connect_db(self):
        return sqlite3.connect(self.filename, detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)

    def _init_db(self):
        with closing(self._connect_db()) as db:
            with open('schema.sql', mode='r') as f:
                db.cursor().executescript(f.read())
            db.commit()

########
# Main #
########
def main():
    context = zmq.Context()
    socket_checker = context.socket(zmq.REP)
    socket_checker.bind("tcp://*:5555")

    socket_client = context.socket(zmq.REP)
    socket_client.bind("tcp://*:5556")

    db = Database(config['database'])

    checker_thread = threading.Thread(target=checker_listener, args=(socket_checker, db))
    checker_thread.start()

    client_thread = threading.Thread(target=client_listener, args=(socket_client, db))
    client_thread.start()


if __name__ == '__main__':
    main()
