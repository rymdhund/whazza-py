import os
import logging
import sys
import zmq
import json
import fileinput
import humanize

from typing import Dict, Any
from .core import Status
from .config import client_config

config = client_config()


def send_msg(socket: zmq.Socket, msg: Dict[str, Any]) -> Dict[str, Any]:
    socket.send_json(msg)
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)
    if poller.poll(config['timeout'] * 1000):  # timeout in milliseconds
        return socket.recv_json()
    else:
        raise IOError("Timeout sending message")


def status(socket: zmq.Socket) -> None:
    longout = config['longout']
    res = send_msg(socket, {'cmd': "status"})
    if res['status'] == 'ok':
        print("Status:")
        print("=======")
        for row in res['data']:
            s = Status.from_dict(row)
            message = s.message.replace("\n", " ")
            if not longout and len(message) > 43:
                message = message[:40] + "..."

            if s.last_check is None:
                times = "Never"
            else:
                times = humanize.naturaltime(s.last_check, "%Y-%m-%d %H:%M")
            print("{:30s}   {:15s}   {:20s}   {}".format(s.rule_key, s.status, times, message))
    else:
        print("Error from server: {}".format(res['message']))


def dump_rules(socket: zmq.Socket) -> None:
    res = send_msg(socket, {'cmd': 'dump-rules'})
    if res['status'] == 'ok':
        print(json.dumps(res['data'], sort_keys=True, indent=2))
    else:
        print("Error: {}".format(res['message']))


def set_rules(socket: zmq.Socket, filename: str) -> None:
    inp = ""
    for line in fileinput.input(filename):
        inp += line

    rules = json.loads(inp)

    res = send_msg(socket, {'cmd': 'set-rules', 'data': {'rules': rules}})
    if res['status'] == 'ok':
        print("updated")
    else:
        print("Error: {}".format(res['message']))


def usage(ret: int) -> None:
    print("usage: {} <cmd>".format(sys.argv[0]))
    print("where cmd is:")
    print("  status")
    print("  dump-rules")
    print("  set-rules <filename>")
    sys.exit(ret)


def init_cert() -> None:
    ''' Generate certificate files if they don't exist '''
    from zmq import auth

    keyfile = os.path.join(config['keys_dir'], "client.key_secret")

    if not (os.path.exists(keyfile)):
        logging.info("No client certificate found, generating")
        keys_dir = config['keys_dir']
        try:
            os.mkdir(keys_dir)
        except FileExistsError as e:
            pass

        # create new keys in certificates dir
        auth.create_certificates(keys_dir, "client")


def main() -> None:
    if len(sys.argv) < 2:
        usage(1)

    logging.basicConfig(level=logging.DEBUG)

    init_cert()

    # setup certificates
    keyfile = os.path.join(config['keys_dir'], "client.key_secret")
    client_public, client_secret = zmq.auth.load_certificate(keyfile)
    server_public_file = os.path.join(config['keys_dir'], "server.key")
    server_public, _ = zmq.auth.load_certificate(server_public_file)

    # setup socket
    context = zmq.Context(1)
    socket = context.socket(zmq.REQ)
    socket.setsockopt(zmq.LINGER, 0)
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
