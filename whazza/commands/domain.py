import whois

from datetime import datetime


def domain_status(conf):
    if 'domain' not in conf.keys():
        return ('fail', "check_domain: conf does not contain domain")

    domain = conf['domain']
    min_days = conf.get("min_days", 30)

    w = whois.whois(domain)
    exp_date = w.expiration_date
    if isinstance(exp_date, list):
        exp_date = exp_date[0]
    if exp_date is None:
        return ('fail', "Unknown expration date for domain, is it registered?")
    expire_in = (exp_date - datetime.now()).days

    if expire_in < min_days:
        return ('fail', "Domain {} expires in {} days".format(domain, expire_in))

    return ('good', "")
