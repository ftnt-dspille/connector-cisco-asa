""" Copyright start
  Copyright (C) 2008 - 2025 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import json
from urllib.parse import unquote, urlparse

from connectors.core.connector import ConnectorError


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


def safe_endpoint(endpoint):
    """A path on the configured ASA, or an error.

    A full URL, a `//host` start, a `..` segment (also percent-encoded, up to
    three layers) or a backslash is refused, so the credentials can never be
    sent to another host.
    """
    endpoint = str(endpoint or '').strip()
    if not endpoint:
        raise ConnectorError('Endpoint is required')
    parsed = urlparse(endpoint)
    path = endpoint.split('?')[0]
    for _ in range(3):
        path = unquote(path)
    if (parsed.scheme or parsed.netloc or endpoint.startswith('//')
            or '..' in path.split('/') or '\\' in path):
        raise ConnectorError('Endpoint must be a path on the configured server, '
                             'for example /api/monitoring/serialnumber - not a full URL')
    return endpoint if endpoint.startswith('/') else '/' + endpoint


def json_object(value, name):
    """A JSON object from a dict or a JSON string; blank means none."""
    if value in (None, '', {}):
        return None
    if isinstance(value, (str, bytes)):
        try:
            value = json.loads(value)
        except ValueError:
            raise ConnectorError('{0} must be valid JSON'.format(name))
    if not isinstance(value, dict):
        raise ConnectorError('{0} must be a JSON object'.format(name))
    return value
