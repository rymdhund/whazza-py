from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone


def _to_ts(dt):
    return dt.replace(tzinfo=timezone.utc).timestamp()


def _from_ts(ts):
    return datetime.utcfromtimestamp(ts)


class Rule:
    def __init__(self, type: str, key: str, check_interval: int,
                 params: Dict[str, Any], checker: str, update_id: int) -> None:
        self.type = type
        self.key = key
        self.check_interval = check_interval
        self.params = params
        self.checker = checker
        self.update_id = update_id

    def dict(self) -> Dict[Any, Any]:
        return self.__dict__

    def client_dict(self) -> Dict[str, Any]:
        return {'type': self.type, 'key': self.key, 'check_interval': self.check_interval,
                'params': self.params, 'checker': self.checker}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'Rule':
        return Rule(d['type'], d['key'], d['check_interval'], d['params'], d['checker'], d['update_id'])

    def __eq__(self, o) -> bool:
        return self.__dict__ == o.__dict__


class Check:
    def __init__(self, rule_key: str, status: str, msg: str, time: datetime) -> None:
        self.rule_key = rule_key
        self.status = status
        self.msg = msg
        self.time = time.replace(microsecond=0)

    def dict(self) -> Dict[str, Any]:
        d = self.__dict__.copy()
        d['time'] = _to_ts(d['time'])
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'Check':
        return Check(d['rule_key'], d['status'], d['msg'], _from_ts(d['time']))

    def __eq__(self, o):
        return self.__dict__ == o.__dict__


class Status:
    def __init__(self, rule_key: str,
                 last_successful: Optional[datetime],
                 last_check: Optional[datetime],
                 status: str,
                 message: str) -> None:
        self.rule_key = rule_key

        if last_successful is not None:
            last_successful = last_successful.replace(microsecond=0)
        self.last_successful = last_successful

        if last_check is not None:
            last_check = last_check.replace(microsecond=0)
        self.last_check = last_check

        self.status = status
        self.message = message

    @classmethod
    def from_rule_check(cls,
                        rule: Rule,
                        check: Optional[Check],
                        last_successful: Optional[datetime],
                        check_timeout: int) -> 'Status':
        last_successful = last_successful

        if check is not None:
            last_check = check.time  # type: Optional[datetime]
            now = datetime.now()
            if now - check.time > timedelta(0, rule.check_interval + check_timeout):
                status = 'expired'
                message = ""
            else:
                status = check.status
                message = check.msg
        else:
            last_check = None
            status = 'nodata'
            message = "No data on this rule yet"

        return Status(rule.key, last_successful, last_check, status, message)

    def dict(self) -> Dict[str, Any]:
        d = self.__dict__.copy()
        d['last_successful'] = _to_ts(d['last_successful'])
        d['last_check'] = _to_ts(d['last_check'])
        return d

    def client_data(self) -> Dict[str, Any]:
        time = self.last_check.timestamp() if self.last_check is not None else None
        succ = self.last_successful.timestamp() if self.last_successful is not None else None
        return {
            'key': self.rule_key,
            'status': self.status,
            'message': self.message,
            'time': time,
            'last_successful': succ,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'Status':
        return Status(d['rule_key'],
                      _from_ts(d['last_successful']),
                      _from_ts(d['last_check']),
                      d['status'],
                      d['message'])

    def __eq__(self, o):
        return self.__dict__ == o.__dict__
