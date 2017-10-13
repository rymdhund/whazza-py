import os
import logging
import json
import sqlite3

from contextlib import closing
from typing import List, Any, Dict, Optional
from pkg_resources import resource_string
from .core import Rule, Check, Status


class Database:
    def __init__(self, filename: str, config: Dict[str, Any]) -> None:
        self.filename = filename
        self.config = config

        self.status_to_int = {'good': 1, 'fail': 2, 'expired': 3}
        self.int_to_status = {1: 'good', 2: 'fail', 3: 'expired'}

        if not os.path.isfile(filename):
            logging.info("Creating database {}".format(filename))
            self._init_db()

    def _row_to_rule(self, row: List[Any]) -> Rule:
        params = json.loads(row[3])
        return Rule(row[0], row[1], row[2], params, row[4], row[5])

    def _get_rule(self, key: str, db) -> Optional[Rule]:
        cur = db.execute("select type, key, check_interval, params, checker, update_id from rules where key = ?", (key,))
        res = cur.fetchone()
        if res is None:
            return None
        return self._row_to_rule(res)

    def get_rule(self, key: str) -> Optional[Rule]:
        with closing(self._connect_db()) as db:
            r = self._get_rule(key, db)
            return r

    def get_rules(self) -> List[Rule]:
        with closing(self._connect_db()) as db:
            cur = db.execute("select type, key, check_interval, params, checker, update_id from rules where type != 'none'")
            return [self._row_to_rule(row) for row in cur.fetchall()]

    def get_check(self, key: str) -> Optional[Check]:
        with closing(self._connect_db()) as db:
            cur = db.execute("select status, msg, time from checks where rule_key = ? limit 1", (key,))

            row = cur.fetch_one()
            if row:
                return Check(key, row[0], row[1], row[2])
            else:
                return None

    def _add_rule(self, rule: Rule, db) -> None:
        db.execute("""
        insert into rules (type, key, check_interval, params, checker, update_id)
        values (?, ?, ?, ?, ?, (select ifnull(max(update_id), 0)+1 from rules))
        """, (rule.type, rule.key, rule.check_interval, json.dumps(rule.params), rule.checker))

    def add_rule(self, rule: Rule) -> None:
        with closing(self._connect_db()) as db:
            self._add_rule(rule, db)
            db.commit()

    def get_new_rules(self, checker: str, update_id: int) -> List[Rule]:
        with closing(self._connect_db()) as db:
            cur = db.execute("select type, key, check_interval, params, checker, update_id from rules where checker=? and update_id > ?", (checker, update_id))
            return [self._row_to_rule(row) for row in cur.fetchall()]

    def _update_rule(self, rule: Rule, db) -> None:
        db.execute("""
        update rules set type=?, check_interval=?, params=?, checker=?, update_id=(select ifnull(max(update_id), 0)+1 from rules)
        where key=?
        """, (rule.type, rule.check_interval, json.dumps(rule.params), rule.checker, rule.key))

    def update_rules(self, rules: List[Rule]) -> None:
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

    def add_check(self, check: Check) -> None:
        with closing(self._connect_db()) as db:

            db.execute("""
            insert into checks (rule_key, time, status, msg) values (?, ?, ?, ?)
            """, (check.rule_key, check.time, self.status_to_int[check.status], check.msg))
            db.commit()

    def set_notification(self, key: str, status: str) -> None:
        with closing(self._connect_db()) as db:
            db.execute("delete from notifications where rule_key = ?", (key,))

            # dont save anything on "good" status
            if status != 'good':
                db.execute("insert into notifications (rule_key, status) values (?, ?)", (key, self.status_to_int[status]))
            db.commit()

    def get_notified_status(self, key: str) -> str:
        """ Returns 'good' if we haven't sent any notifications
        """
        with closing(self._connect_db()) as db:
            cur = db.execute("select status from notifications where rule_key = ?", (key,))
            row = cur.fetchone()
            if row:
                return self.int_to_status[row[0]]
            else:
                return 'good'

    def get_statuses(self) -> List[Status]:
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
                last_successful[row[0]] = row[1]
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
                check = Check(row[0], self.int_to_status[row[1]], row[2], row[3])
                rule = self.get_rule(row[0])
                assert(rule is not None)
                ret.append(Status.from_rule_check(
                    rule,
                    check,
                    last_successful.get(row[0], None),
                    self.config['check_timeout']))

            # append rules that don't have any check data yet
            cur = db.execute("""
                select r.type, r.key, r.check_interval, r.params, r.checker, r.update_id key from rules r
                left join checks c
                on (r.key = c.rule_key)
                where c.id is null and r.type != 'none'
            """)
            for row in cur.fetchall():
                rule = self._row_to_rule(row)
                ret.append(Status.from_rule_check(rule, None, None, self.config['check_timeout']))
            return ret

    def _connect_db(self):
        return sqlite3.connect(self.filename, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)

    def _init_db(self) -> None:
        # TODO: Bug in typeshed, wait for mypy update
        schema = resource_string('whazza', "assets/schema.sql").decode()  # type: ignore
        with closing(self._connect_db()) as db:
            db.cursor().executescript(schema)
            db.commit()
