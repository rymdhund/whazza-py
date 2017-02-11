import subprocess
import datetime
import logging


# The commands are to be named after what they are asserting
# e.g. the "git_clean" command asserts that a git repo is clean and not dirty

def port_scan(conf):
    import socket

    target_ip = socket.gethostbyname(conf['target'] or 'localhost')
    logging.info("Starting port scan on host {}".format(target_ip))

    ports = []

    for i in range(1, 1025):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        result = s.connect_ex((target_ip, i))

        if(result == 0):
            ports.append(i)
            logging.debug("Port {}: OPEN".format(i))
        s.close()

    return {'open_ports': ports}


def debian_up_to_date(conf):
    output = subprocess.check_output(["/usr/bin/stat", "-c", "%Y", "/var/lib/apt/lists"])
    timestamp = int(output.decode('ascii'))
    now = datetime.datetime.now().timestamp()
    if now - timestamp > 24 * 3600:
        return 'fail', "apt-get update hasn't been run in 24h"

    output = subprocess.check_output(["/usr/bin/apt", "list", "--upgradable"])
    updates = []
    for line in output.decode('ascii').splitlines():
        if line not in ["Listing...", "Done", ""]:
            updates.append(line)
    if len(updates) == 0:
        return 'good', ""
    else:
        return 'fail', "These packages can be updated:\n".join(updates)


def git_clean(conf):
    from git import Repo
    path = conf['path']
    r = Repo(path)
    status = "fail" if r.is_dirty() else "good"
    return (status, r.git.status())


def test(conf):
    return (conf.get('status', "good"), conf.get('message', ""))


def process_running(conf):
    if 'name' not in conf.keys():
        return ('fail', 'Process_running conf does not contain name')
    try:
        cmd = ["/usr/bin/pgrep", "-f", conf['name']]
        subprocess.check_call(cmd)
        return ('good', "")
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            return ('fail', 'No matched process')
        else:
            return ('fail', 'The pgrep command failed with status {}'.format(e.returncode))


def container_running(conf):
    if 'name' not in conf.keys():
        return ('fail', 'Container_running conf does not contain name')
    from docker import Client
    cli = Client(base_url='unix://var/run/docker.sock')
    cnts = cli.containers()
    for cnt in cnts:
        for name in cnt['Names']:
            if name == conf['name']:
                return ('good', "")
            if len(name) > 0 and name[0] == '/' and name[1:] == conf['name']:
                return ('good', "")
    return ('fail', 'No matched container')


def host_is_up(conf):
    if 'type' not in conf.keys():
        return ('fail', "host_is_up: conf does not contain type")
    if 'host' not in conf.keys():
        return ('fail', "host_is_up: conf does not contain host")
    if conf['type'] not in ('http',):
        return ('fail', "host_is_up: unrecognized type: {}".format(conf['type']))

    try:
        import requests
        r = requests.get(conf['host'], timeout=10)
        if r.status_code != 200:
            return ('fail', "Status code {}".format(r.status_code))
        return ('good', "")
    except ConnectionError as e:
        return ('fail', "Connection failed: {}".format(e))
