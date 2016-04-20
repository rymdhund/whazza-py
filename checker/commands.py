import subprocess
import datetime

def port_scan(conf):
    target_ip = gethostbyname(conf['target'] or 'localhost')
    print("Starting scan on host {}".format(target_ip))

    ports = []

    for i in range(1, 1025):
        s = socket(AF_INET, SOCK_STREAM)

        result = s.connect_ex((target_ip, i))

        if(result == 0) :
            ports.append(i)
            print("Port {}: OPEN".format(i))
        s.close()

    return {'open_ports': ports}

def check_debian_update(conf):
    output = subprocess.check_output(["/usr/bin/stat", "-c", "%Y", "/var/lib/apt/lists"])
    timestamp = int(output.decode('ascii'))
    now = datetime.datetime.now().timestamp();
    if now - timestamp > 24*3600:
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

def check_git_status(conf):
    from git import Repo
    path = conf['path']
    r = Repo(path)
    status = "fail" if r.is_dirty() else "good"
    return (status, r.git.status())

def test_command(conf):
    return (conf.get('status', "good"), conf.get('message', ""))

def process_running(conf):
    if not 'name' in conf.keys():
        return ('fail', 'Process_running conf does not contain name')
    try:
        cmd = ["/usr/bin/pgrep", "-f", conf['name']]
        output = subprocess.check_call(cmd)
        return ('good', 'Process is running')
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            return ('fail', 'No matched process')
        else:
            return ('fail', 'The pgrep command failed with status {}'.format(e.returncode))

def container_running(conf):
    if not 'name' in conf.keys():
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
