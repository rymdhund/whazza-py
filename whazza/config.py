import os
import yaml


def read_config():
    try:
        configfile = os.environ.get('WHAZZA_CONFIG_FILE', "config.yml")
        with open(configfile, 'r') as stream:
            return yaml.safe_load(stream)
    except FileNotFoundError:
        print("INFO: No config file found, running with defaults")
        return {}


def server_config():
    config = read_config()
    config.setdefault('keys_dir', 'whazza_server_keys')
    config.setdefault('database', 'db.sqlite3')
    config.setdefault('check_timeout', 300)  # 5 minute timeout by default

    config.setdefault('notification_url', None)
    config.setdefault('notification_base_msg', {})
    config.setdefault('notification_mail', None)
    config.setdefault('mail_from', 'whazza@example.com')
    config.setdefault('smtp_host', 'localhost')
    config.setdefault('smtp_user', None)
    config.setdefault('smtp_password', '')

    return config


def client_config():
    config = read_config()
    config.setdefault('keys_dir', 'whazza_client_keys')
    config.setdefault('server_host', 'localhost')
    config.setdefault('server_port', 5556)
    config.setdefault('longout', False)
    return config


def checker_config():
    config = read_config()
    config.setdefault('keys_dir', 'whazza_checker_keys')
    config.setdefault('server_host', 'localhost')
    config.setdefault('server_port', 5555)
    config.setdefault('checker_id', 'default')
    return config
