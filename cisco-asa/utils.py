""" Copyright start
  Copyright (C) 2008 - 2025 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """


def _check_and_convert_params(params):
    convert_params = dict()
    if params:
        for k, v in params.items():
            if type(v) == bytes:
                convert_params[k] = str(v, 'utf-8')
            else:
                convert_params[k] = v
    return convert_params


def block_ip_command():
    return ['show running-config access-group',
            'configure terminal',
            'terminal width 511',
            ]


def update_group_command():
    return [
        'configure terminal',
        'terminal width 511',
        'object-group network {group_name}',
        'network-object host {ip}',
        'end',
        'wr'
    ]


def check_config_url(config):
    if config.get('server_url').startswith('https://'):
        config['server_url'] = config.get('server_url')[8:]
    elif config.get('server_url').startswith('http://'):
        config['server_url'] = config.get('server_url')[7:]
    return config
