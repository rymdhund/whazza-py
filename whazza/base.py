from datetime import datetime


class Rule:
    def __init__(self, type, key, check_interval, params, checker, update_id):
        self.type = type
        self.key = key
        self.check_interval = check_interval
        self.params = params
        self.checker = checker
        self.update_id = update_id

    def dict(self):
        return self.__dict__

    def client_dict(self):
        return {'type': self.type, 'key': self.key, 'check_interval': self.check_interval,
                'params': self.params, 'checker': self.checker}


class Check:
    def __init__(self, rule_key, status, msg, time):
        self.rule_key = rule_key
        self.status = status
        self.msg = msg
        self.time = time

    def dict(self):
        return self.__dict__


class Status:
    def __init__(self, rule, check, last_successful, check_timeout):
        self.rule_key = rule.key
        self.last_successful = last_successful

        if check is not None:
            self.last_check = check.time
            now = datetime.now()
            if now - check.time > datetime.timedelta(0, rule.check_interval + check_timeout):
                self.status = 'expired'
                self.message = ""
            else:
                self.status = check.status
                self.message = check.msg
        else:
            self.status = 'nodata'
            self.message = "No data on this rule yet"

    def dict(self):
        return self.__dict__

    def client_data(self):
        time = self.last_check.timestamp() if self.last_check is not None else None
        succ = self.last_successful.timestamp() if self.last_successful is not None else None
        return {
            'key': self.rule_key,
            'status': self.status,
            'message': self.message,
            'time': time,
            'last_successful': succ,
        }
