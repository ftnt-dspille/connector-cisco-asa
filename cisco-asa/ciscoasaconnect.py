""" Copyright start
  Copyright (C) 2008 - 2025 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import paramiko
import requests
import socket
import sys
from connectors.core.connector import get_logger, ConnectorError
from .const import *
from .utils import safe_endpoint

logger = get_logger('ciscoasa')


class CiscoASAConnect():
    def __init__(self):
        self._ssh_client = None
        self._shell_channel = None
        return

    def _delay_for_data(self, size):
        """
        Waits till we have some data
        """
        self._shell_channel.settimeout(RECEIVE_FIRST_DATA_TIMEOUT)
        output = ''
        while True:
            try:
                data = self._shell_channel.recv(size)
                data = data.decode('utf-8')
                output += data
                self._shell_channel.settimeout(RECEIVE_SECOND_DATA_TIMEOUT)
            except socket.timeout:
                break
            except:
                return (False, None, sys.exc_info()[0])
        return (True, output, None)

    def _connect(self, config):
        if self._shell_channel is not None:
            return True
        else:
            status_code = self._start_connection(config)
            if not status_code:
                return status_code
            cmd_list = [
                'enable',
                config.get('password'),
                'terminal pager 0'
            ]
            if config.get('context_mode', '') == 'Multi Context' and config.get('context_name'):
                cmd_list.append('changeto context {context_name}'.format(context_name=config.get('context_name')))
            for cmd in cmd_list:
                try:
                    cmd_output = self._execute_command(cmd)
                    logger.info('Output of Command {}'.format(cmd_output))
                    if 'error' in cmd_output.lower():
                        msg = 'For command {} error occured: {}'.format(cmd, cmd_output)
                        raise ConnectorError(
                            'Context mode disable or invalid context name.' if 'changeto context' in cmd else msg)
                except Exception as e:
                    logger.info("Exception Occured {0}".format(e))
                    logger.info("Exception Occured in command {0}".format(cmd))
                    raise ConnectorError(str(e))
            return True

    def _start_connection(self, config):
        """
        Starts the shell
        """
        server = config.get('server_url').strip('/')
        user = config.get('username')
        password = config.get('password')
        self._ssh_client = paramiko.SSHClient()
        self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self._ssh_client.connect(hostname=server, username=user, password=password, allow_agent=False,
                                     look_for_keys=False)
        except Exception as e:
            raise ConnectorError(ERROR_SSH_CONNECTION_FAILED)
        try:
            self._shell_channel = self._ssh_client.invoke_shell()
        except Exception as e:
            self._ssh_client.close()
            raise ConnectorError(ERROR_SSH_CONNECTION_FAILED)
        ret_code, output, exc = self._delay_for_data(MAX_SIZE_FOR_OUTPUT)
        if not ret_code:
            raise ConnectorError('Read from device failed')
        return True

    def _execute_command(self, command):
        """
        Send a command to the server on the provided channel
        Args:
            The command to send
        Return:
            The recieved data
        """
        size = MAX_SIZE_FOR_OUTPUT
        self._shell_channel.settimeout(RECEIVE_SECOND_DATA_TIMEOUT)
        try:
            self._shell_channel.send(command + '\n')
        except Exception as e:
            logger.exception("On device execution of command '{}' failed".format(command))
            raise ConnectorError("On device execution of command '{}' failed".format(command))
        ret_code, output, exc = self._delay_for_data(size)
        if not ret_code:
            logger.exception('Read from device failed')
            raise ConnectorError('Read from device failed')
        return output

    def _reformat_cmd_output(self, cmd_output, rem_command=True, to_list=True):
        if cmd_output is None:
            return
        else:
            try:
                data_lines = cmd_output.splitlines()
                data_lines.pop()
                if rem_command:
                    del data_lines[0]
                if to_list:
                    return data_lines
            except:
                return

            return '\r\n'.join(data_lines)

    def _run_custom_commands(self, config, cmd_list):
        status_code = self._start_connection(config)
        output_data = dict()
        if not status_code:
            return status_code
        for cmd in cmd_list:
            try:
                cmd_output = self._execute_command(cmd)
                logger.debug('Output of Command {}'.format(cmd_output))
                if 'error' in cmd_output.lower():
                    msg = 'For command {} error occurred: {}'.format(cmd, cmd_output)
                    raise ConnectorError(
                        'Context mode disable or invalid context name.' if 'changeto context' in cmd else msg)
                output_data[cmd.strip()] = cmd_output
            except Exception as e:
                logger.error("Exception Occurred {0}".format(e))
                logger.error("Exception Occurred in command {0}".format(cmd))
                raise ConnectorError(str(e))
        return output_data

    def _rest_request(self, config, method, endpoint, params=None, body=None):
        """Any ASA REST API call, with the configured username and password."""
        path = safe_endpoint(endpoint)
        url = 'https://' + config.get('server_url').strip('/') + path
        verify = config.get('verify_ssl', True)
        if isinstance(verify, str):
            verify = verify.strip().lower() not in ('false', '0', 'no')
        try:
            resp = requests.request(method, url, params=params, json=body,
                                    auth=(config.get('username'), config.get('password')),
                                    headers={'User-Agent': 'REST API Agent', 'Accept': 'application/json'},
                                    verify=bool(verify), timeout=REST_TIMEOUT, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            raise ConnectorError('Request to the Cisco ASA failed: {0}'.format(e))
        if resp.status_code >= 400:
            raise ConnectorError('Cisco ASA returned HTTP {0}: {1}'.format(resp.status_code, resp.text[:300]))
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            return {'raw': resp.text}
