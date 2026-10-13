""" Copyright start
  Copyright (C) 2008 - 2025 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import validators
from .const import *
from .ciscoasaconnect import CiscoASAConnect
from connectors.core.connector import get_logger, ConnectorError
from .utils import block_ip_command, update_group_command, json_object

logger = get_logger('ciscoasa')


class Ciscoasa(CiscoASAConnect):
    def __init__(self):
        super(Ciscoasa, self).__init__()

    def check_type_input(self, params, key):
        logger.info('Getting value for key : %s' % key)
        ret_val = params.get(key, None)
        if isinstance(ret_val, bytes):
            ret_val = ret_val.decode('utf-8')
        logger.info('In check_type_input() : ', ret_val)
        return ret_val

    def _test_asset_connectivity(self, config):
        if not (CiscoASAConnect._connect(self, config)):
            logger.info('connect failed')
            logger.info(CONNECTION_UNSUCCESSFUL)
            raise ConnectorError(CONNECTION_UNSUCCESSFUL)
        logger.info('connect passed')
        return True

    def _validate_access_list(self, access_list, direction, intf, acc_groups):
        for curr_acc_list in acc_groups:
            if len(curr_acc_list) == 0:
                continue
            acc_list_broken = curr_acc_list.split(' ')
            if len(acc_list_broken) < 5:
                continue
            if direction == acc_list_broken[2] and intf == acc_list_broken[4]:
                if access_list == acc_list_broken[1]:
                    return ACCESS_LIST_AVAILAIBLE
                else:
                    raise ConnectorError(
                        ERROR_DUPLICATE_ACCESS_LIST.format(present_acl_name=acc_list_broken[1],
                                                           intf=intf, direction=direction,
                                                           acl_name=access_list))
        return ERROR_ACCESS_LIST_NOT_FOUND

    def _list_sessions(self, config):
        """
        List users currently connected over webvpn
        """
        self._connect(config)
        cmd = 'show vpn-sessiondb webvpn'
        cmd_output = self._execute_command(cmd)
        data = self._reformat_cmd_output(cmd_output)
        if data is None:
            raise ConnectorError(ERROR_INVALID_ACCESS_GROUP)
        data = self._parse_to_dict(data)
        return data

    def _parse_to_dict(self, data):
        d = {}
        user_dict = {}
        d['users'] = []
        for line in data[3:]:
            if not line and user_dict:
                d['users'].append(user_dict)
                user_dict = {}
            self._add_line_to_dict(line.split(' : '), user_dict)
        logger.info({'total_users': len(d['users'])})
        d.update({'total_users': len(d['users'])})
        return d

    def _add_line_to_dict(self, line, d):
        if len(line) <= 1:
            return
        else:
            if len(line) == 2:
                d[line[0].replace(' ', '')] = line[1].strip()
                return
            mid = line[1].split()
            d[line[0].replace(' ', '')] = mid[0]
            line = line[2:]
            line[:0] = [' '.join(mid[1:])]
            return self._add_line_to_dict(line, d)

    def _terminate_session(self, config, params):
        self._connect(config)
        target = params['username']
        cmd = 'vpn-sessiondb logoff name {}\n'.format(target)
        cmd_output = self._execute_command(cmd)
        data = self._reformat_cmd_output(cmd_output)
        num = 0
        try:
            num = int(data[1].split(':')[-1])
            if num == 0:
                return {'message': 'No such user is logged in'}
        except:
            output = data[1].split(':')
            if output[0] == 'ERROR':
                return 'Invalid input'
        return {'Sessions Terminated': num}

    def _block_unblock_both(self, access_list, direction, intf, data_to_parse, line, src,
                            dest, cmd_list, create_access_group):
        ret_code = self._validate_access_list(access_list, direction, intf, data_to_parse)
        if ret_code == ERROR_ACCESS_LIST_NOT_FOUND:
            create_access_group = True
        logger.info(ACCESS_LIST_VALIDATED)
        cmd_to_run = cmd_list[1]
        cmd_output = self._execute_command(cmd_to_run)
        logger.info('Output of Command {}'.format(cmd_output))
        logger.info(EXECUTED_COMMAND.format(cmd_to_run))
        cmd_to_run = cmd_list[2]
        cmd_output = self._execute_command(cmd_to_run)
        logger.info('Output of Command {}'.format(cmd_output))
        logger.info(EXECUTED_COMMAND.format(cmd_to_run))
        acc_list = 'access-list %s ' % access_list
        if create_access_group:
            acc_list += 'line %s ' % line
        acc_list += 'extended deny ip host %s ' % src if src != 'any' else 'extended deny ip %s ' % src
        if not create_access_group:
            acc_list = 'no ' + acc_list
        if dest != 'any':
            acc_list += 'host ' + dest
        else:
            acc_list += ' ' + dest
        logger.info(EXECUTING_COMMAND.format(acc_list))
        cmd_output = self._execute_command(acc_list)
        if len(cmd_output) > 0:
            logger.info(DEVICE_RESPONSE_TEXT.format(cmd_output))
        if create_access_group is True:
            acc_group = 'access-group {} {} interface {} '.format(access_list, direction, intf)
            logger.info(EXECUTING_COMMAND.format(acc_group))
            cmd_output = self._execute_command(acc_group)
            logger.info(EXECUTED_COMMAND.format(acc_group))
            if len(cmd_output) > 0:
                logger.info(DEVICE_RESPONSE_TEXT.format(cmd_output))

    def _block_ip(self, config, params, create_access_group):
        """
        Function that implements the block_ip action for an ASA box
        Args:
            The params for the action
            The boolean stating wheather to delete a block ip rule or not
        Return:
            Status code
            Data returned by the command
        """
        msg = "IP Successfully Blocked" if create_access_group else "IP Successfully Unblocked"
        self._connect(config)
        src = params.get('src')
        dest = params.get('dest')
        access_list = params.get('access_list')
        direction = params.get('direction').lower()
        intf = params.get('interface')
        line = 1
        allow = False
        if src.lower() == 'any':
            src = src.lower()
            allow = True
        if dest.lower() == 'any':
            dest = dest.lower()
            allow = True
        if allow or (validators.ipv4(str(src)) and validators.ipv4(str(dest))):
            if src == ANY_POLICY and dest == ANY_POLICY:
                logger.exception(ERROR_SRC_DEST_ANY)
                raise ConnectorError(ERROR_SRC_DEST_ANY)
            else:
                cmd_list = block_ip_command()
                cmd_to_run = cmd_list[0]
                cmd_output = self._execute_command(cmd_to_run)
                data_to_parse = self._reformat_cmd_output(cmd_output)
                if data_to_parse is None:
                    raise ConnectorError(ERROR_INVALID_ACCESS_GROUP)
                if direction == 'both':
                    self._block_unblock_both(access_list, 'in', intf, data_to_parse, line, src=src, dest=dest,
                                             cmd_list=cmd_list, create_access_group=create_access_group)
                    self._block_unblock_both(access_list, 'out', intf, data_to_parse, line, src=dest, dest=src,
                                             cmd_list=cmd_list, create_access_group=create_access_group)
                else:
                    self._block_unblock_both(access_list, direction, intf, data_to_parse, line, src, dest,
                                             cmd_list, create_access_group)
                return msg
        else:
            raise ConnectorError('Invalid IP Address')

    def _get_version(self, config, params):
        self._connect(config)
        cmd_to_run = 'show version'
        cmd_output = self._execute_command(cmd_to_run)
        curr_data = {}
        curr_data['command'] = cmd_to_run
        cmd_output = self._reformat_cmd_output(cmd_output, rem_command=True, to_list=False)
        curr_data['output'] = cmd_output.splitlines()[1] if len(cmd_output.splitlines()) else ''
        curr_data['status'] = 'Command execution successful'
        logger.info(EXECUTED_COMMAND.format(cmd_to_run))
        return curr_data

    def _get_network_group(self, config, params):
        self._connect(config)
        curr_data = {}
        group_name = params.get('group_name')
        cmd_to_run = 'sh run object-group id {group_name}'.format(group_name=group_name)
        logger.info(EXECUTING_COMMAND.format(cmd_to_run))
        cmd_output = self._execute_command(cmd_to_run)
        logger.info(EXECUTED_COMMAND.format(cmd_to_run))
        curr_data['command'] = cmd_to_run
        reformat_cmd_output = self._reformat_cmd_output(cmd_output.rstrip(), rem_command=True, to_list=False)
        if len(reformat_cmd_output.splitlines()) <= 1:
            logger.exception(reformat_cmd_output.strip())
            raise ConnectorError(reformat_cmd_output.strip())
        curr_data['output'] = list(map(lambda x: x.strip(), reformat_cmd_output.splitlines()[
                                                            2 if 'description' in reformat_cmd_output.splitlines()[
                                                                1] else 1:]))
        curr_data['status'] = 'Command execution successful'
        logger.info(EXECUTED_COMMAND.format(cmd_to_run))
        return curr_data

    def _update_group(self, config, params):
        self._connect(config)
        group_name = params.get('group_name')
        method = params.get('method')
        ip = params.get('ip')
        cmd_list = update_group_command()
        for i in range(len(cmd_list)):
            if i == 2:
                cmd_list[i] = cmd_list[i].format(group_name=group_name)
            if i == 3:
                cmd_list[i] = '{0} {1}'.format(('no' if method == 'Remove' else ''), cmd_list[i].format(ip=ip))
            logger.info(EXECUTING_COMMAND.format(cmd_list[i]))
            cmd_output = self._execute_command(cmd_list[i])
            logger.info(EXECUTED_COMMAND.format(cmd_list[i]))
            data_to_parse = self._reformat_cmd_output(cmd_output)
            if len(data_to_parse) != 1 and len(cmd_list) - 1 != i:
                msg = 'Error to execute cmd: {0}'.format(''.join(data_to_parse))
                logger.exception(msg)
                raise ConnectorError(msg)
        curr_data = dict()
        curr_data['command'] = cmd_list
        curr_data['status'] = 'Command execution successful'
        return curr_data

    def run_custom_commands(self, config, params):
        self._connect(config)
        custom_commands = params.get('custom_commands').split(";")

        cmd_output = self._run_custom_commands(config, custom_commands)
        cmd_output['status'] = True
        cmd_output['commands'] = custom_commands
        return cmd_output


def block_ip(config, params):
    obj = Ciscoasa()
    return {"message": obj._block_ip(config, params, create_access_group=True)}


def unblock_ip(config, params):
    obj = Ciscoasa()
    return {"message": obj._block_ip(config, params, create_access_group=False)}


def list_sessions(config, params):
    obj = Ciscoasa()
    return obj._list_sessions(config)


def terminate_sessions(config, params):
    obj = Ciscoasa()
    return obj._terminate_session(config, params)


def get_version(config, params):
    obj = Ciscoasa()
    return obj._get_version(config, params)


def _check_health(config):
    obj = Ciscoasa()
    try:
        logger.info(CONNECTION_SUCCESSFUL)
        return obj._test_asset_connectivity(config)
    except Exception as err:
        logger.exception(CONNECTION_UNSUCCESSFUL)
        raise ConnectorError(err)


def update_group(config, params):
    obj = Ciscoasa()
    return obj._update_group(config, params)


def run_custom_commands(config, params):
    obj = Ciscoasa()
    return obj.run_custom_commands(config, params)


def get_network_group(config, params):
    obj = Ciscoasa()
    return obj._get_network_group(config, params)


def execute_api_request(config, params):
    """Call any ASA REST API endpoint with the configured credentials.

    `endpoint` is a path on the configured server, for example
    /api/monitoring/serialnumber. A full URL is refused.
    """
    method = (params.get('method') or 'GET').upper()
    if method not in REST_METHODS:
        raise ConnectorError('Method must be GET, POST, PUT, PATCH or DELETE')
    query = json_object(params.get('query_params'), 'Query Parameters')
    body = json_object(params.get('request_body'), 'Request Body')
    return Ciscoasa()._rest_request(config, method, params.get('endpoint'), query, body)


operations = {
    'get_version': get_version,
    'block_ip': block_ip,
    'unblock_ip': unblock_ip,
    'list_sessions': list_sessions,
    'terminate_sessions': terminate_sessions,
    'update_group': update_group,
    'get_network_group': get_network_group,
    'run_custom_commands': run_custom_commands,
    'execute_api_request': execute_api_request
}
