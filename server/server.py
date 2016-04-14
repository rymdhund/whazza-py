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
        # add new config
        socket.send(json.dumps({}).encode())

def client_listener(socket, db):
    while True:
        message = socket.recv().decode()
        print("Received client request: %s" % message)

        data = json.loads(message)

        if data['cmd'] == 'status':
            msg = {'status': 'ok', 'data': db.status()}
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


    def get_rule(self, key):
        with closing(self._connect_db()) as db:
            cur = db.execute("select type, key, valid_period, check_interval, params, checker, update_id from rules where key = ?", (key,))
            res = cur.fetchone()
            if res:
                params = json.loads(res[4])
                return Rule(res[0], res[1], res[2], res[3], params, res[5], res[6])
            return None

    def add_rule(self, rule):
        with closing(self._connect_db()) as db:
            db.execute("""
            insert into rules (type, key, valid_period, check_interval, params, checker, update_id)
            values (?, ?, ?, ?, ?, ?, (select ifnull(max(update_id), 0)+1 from rules))
            """, (rule.type, rule.key, rule.valid_period, rule.check_interval, json.dumps(rule.params), rule.checker))
            db.commit()

    def add_check(self, check):
        with closing(self._connect_db()) as db:

            db.execute("""
            insert into checks (rule_key, time, status, msg) values (?, ?, ?, ?)
            """, (check.rule_key, check.time, self.status_to_int[check.status], check.msg))
            db.commit()

    def _get_checks(self):
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
                rule = self.get_rule(key)
                print("{}".format(time))
                print("{}".format(type(time)))
                if now() - time > datetime.timedelta(rule.valid_period):
                    status = 'unknown'

                ret.append({'key': row[0], 'status': status, 'message': row[2], 'time': time.timestamp(), 'last_successful': last_successful.get(key, None)})
            return ret

    def status(self):
        checks = self._get_checks()
        for check in checks:
            print(check)
        return checks

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
