import unittest
from datetime import datetime
from ..base import Rule, Check, Status
from json import dumps, loads


class TestJson(unittest.TestCase):
    def test_rule(self):
        r = Rule("type", "key", 1, {}, "checker", -1)
        self.assertEqual(r, Rule.from_dict(r.dict()))
        self.assertEqual(r, Rule.from_dict(loads(dumps(r.dict()))))

    def test_check(self):
        c = Check("rule", "good", "msg", datetime.now())
        self.assertEqual(c, Check.from_dict(c.dict()))
        self.assertEqual(c, Check.from_dict(loads(dumps(c.dict()))))

    def test_status(self):
        s = Status("rule", datetime.now(), datetime.now(), 'good', 'msg')
        self.assertEqual(s, Status.from_dict(s.dict()))
        self.assertEqual(s, Status.from_dict(loads(dumps(s.dict()))))
