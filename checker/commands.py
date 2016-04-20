from git import Repo
import subprocess

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
    output = subprocess.check_output("apt-get --dry-run --show-upgraded -V upgrade | sed -n '/The following packages will be upgraded/,/upgraded, [0-9]* newly/p'", shell=True)
    print(output.decode('ascii'))
    return output.decode('ascii')

def check_debian_update2(conf):
    import apt
    import apt.progress
    cache = apt.Cache()
    cache.update()
    cache.open(None)
    print(cache.get_changes())
    return {}

def check_git_status(conf):
    path = conf['path']
    r = Repo(path)
    status = "fail" if r.is_dirty() else "good"
    return (status, r.git.status())

def test_command(conf):
    return (conf.get('status', "good"), conf.get('message', ""))

def process_running(conf):
    if not 'name' in conf.keys():
        return ('fail', 'Check_process conf does not contain name')
    try:
        cmd = ["/usr/bin/pgrep", "-f", conf['name']]
        output = subprocess.check_call(cmd)
        return ('good', 'Process is running')
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            return ('fail', 'No matched process')
        else:
            return ('fail', 'The pgrep command failed with status {}'.format(e.returncode))
