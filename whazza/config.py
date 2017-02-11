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
