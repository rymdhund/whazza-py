import os
import logging
import yaml
import sys
import zmq
import json
import fileinput
from datetime import datetime
import humanize

config = {}
try:
    with open("config.yml", 'r') as stream:
        config = yaml.safe_load(stream)
except FileNotFoundError:
    print("INFO: No config file found, running with defaults")
except yaml.scanner.ScannerError:
    print("ERROR: Couldn't parse config file")
    sys.exit(1)

config.setdefault('server_host', 'localhost')
config.setdefault('server_port', 5556)
config.setdefault('keys_dir', 'keys')


def send_msg(socket, msg):
    socket.send(json.dumps(msg).encode())
    res = json.loads(socket.recv().decode())
    return res


def status(socket):
    longout = config.get('longout', False)
    res = send_msg(socket, {'cmd': "status"})
    if res['status'] == 'ok':
        print("Status:")
        print("=======")
        for row in res['data']:
            message = row['message'].replace("\n", " ")
            if not longout and len(message) > 43:
                message = message[:40] + "..."
            times = humanize.naturaltime(datetime.fromtimestamp(row['time']), "%Y-%m-%d %H:%M")
            print("{:30s}   {:15s}   {:20s}   {}".format(row['key'], row['status'], times, message))
    else:
        print("Error: {}".format(res['message']))


def dump_rules(socket):
    res = send_msg(socket, {'cmd': 'dump-rules'})
    if res['status'] == 'ok':
        print(json.dumps(res['data'], sort_keys=True, indent=2))
    else:
        print("Error: {}".format(res['message']))


def set_rules(socket, filename):
    inp = ""
    for line in fileinput.input(filename):
        inp += line

    rules = json.loads(inp)

    res = send_msg(socket, {'cmd': 'set-rules', 'data': {'rules': rules}})
    if res['status'] == 'ok':
        print("updated")
    else:
        print("Error: {}".format(res['message']))


def usage(ret):
    print("usage: {} <cmd>".format(sys.argv[0]))
    print("where cmd is:")
    print("  status")
    print("  dump-rules")
    print("  set-rules <filename>")
    sys.exit(ret)


def init_cert():
    ''' Generate certificate files if they don't exist '''
    from zmq import auth

    key_filename = "client"
    key_path = os.path.join(config['keys_dir'], key_filename)
    config['keyfile'] = keyfile = "{}.key_secret".format(key_path)

    if not (os.path.exists(keyfile)):
        logging.info("No client certificate found, generating")
        keys_dir = config['keys_dir']
        try:
            os.mkdir(keys_dir)
        except FileExistsError as e:
            pass

        # create new keys in certificates dir
        auth.create_certificates(keys_dir, key_filename)


def main():
    if len(sys.argv) < 2:
        usage(1)

    logging.basicConfig(level=logging.DEBUG)

    init_cert()

    # setup certificates
    client_public, client_secret = zmq.auth.load_certificate(config['keyfile'])
    server_public_file = os.path.join(config['keys_dir'], "server.key")
    server_public, _ = zmq.auth.load_certificate(server_public_file)

    # setup socket
    context = zmq.Context(1)
    socket = context.socket(zmq.REQ)
    socket.curve_secretkey = client_secret
    socket.curve_publickey = client_public
    socket.curve_serverkey = server_public
    if 'socks5_proxy' in config:
        logging.debug("setting socks5 proxy {}".format(config['socks5_proxy']))
        socket.set_string(zmq.SOCKS_PROXY, config['socks5_proxy'])

    # connect
    host = "tcp://{}:{}".format(config['server_host'], config['server_port'])
    logging.debug("connecting to host {}".format(host))
    socket.connect(host)

    cmd = sys.argv[1]
    try:
        if cmd == "status":
            status(socket)
        elif cmd == "dump-rules":
            dump_rules(socket)
        elif cmd == "set-rules":
            if len(sys.argv) != 3:
                usage(1)
            set_rules(socket, sys.argv[2])
        else:
            usage(1)
    except KeyboardInterrupt:
        print("Interrupted, shutting down...")
    finally:
        socket.close()
        context.term()

if __name__ == '__main__':
    main()
