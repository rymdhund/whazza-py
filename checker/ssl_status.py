import ssl
import socket
import datetime
import logging


def days_to_expiration(cert):
    if 'notAfter' not in cert:
        return 0  # no expiration... best to treat it as a fail I guess

    try:
        timestamp = ssl.cert_time_to_seconds("Jan  5 09:34:43 2018 GMT")
        expire_date = datetime.datetime.utcfromtimestamp(timestamp)
        # expire_date = datetime.strptime(cert['notAfter'],
        #                                 "%b %d %H:%M:%S %Y %Z")
    except:
        raise Exception("Certificate date format unknown: {}.".format(cert['notAfter']))

    expire_in = expire_date - datetime.datetime.now()
    return expire_in.days


def ssl_status(conf):
    if 'host' not in conf.keys():
        return ('fail', "ssl_is_valid: conf does not contain host")

    min_days = conf.get("min_days", 30)
    host = conf['host']
    port = 443
    ca_certs = "/etc/ssl/certs/ca-certificates.crt"

    if host.startswith('https://'):
        host = host[8:]

    try:
        socket.getaddrinfo(host, port)[0][4][0]
    except socket.gaierror as e:
        logging.info(str(e))
        return ('fail', "Couldn't resolve {}".format(host))

    # Connect to the host and get the certificate
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # If handled by python SSL library
    try:
        ssl_sock = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED,
                                   ca_certs=ca_certs,
                                   ciphers=("HIGH:-aNULL:-eNULL:"
                                            "-PSK:RC4-SHA:RC4-MD5"))
        cert = ssl_sock.getpeercert()
        days = days_to_expiration(cert)
        if days < 0:
            return ('fail', "Certificate is expired!")
        if days < min_days:
            return ('fail', "Certificate expires in {} days".format(days))

        ssl_sock.shutdown(socket.SHUT_RDWR)
        ssl_sock.close()

    except ssl.SSLError as e:
        return ('fail', "SSL error: {}".format(e))
    except Exception as e:
        print("e: {}".format(e))

    return ('good', "")
