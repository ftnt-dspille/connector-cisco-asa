""" Copyright start
  Copyright (C) 2008 - 2025 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, ConnectorError, get_logger
from .utils import _check_and_convert_params, check_config_url
from .operations import operations, _check_health

logger = get_logger('ciscoasa')


class CiscoASA(Connector):

    def execute(self, config, operation, params, **kwargs):
        try:
            operation = operations.get(operation)
            params = _check_and_convert_params(params)
            config = check_config_url(config)
            return operation(config, params)
        except Exception as Err:
            raise ConnectorError(Err)

    def check_health(self, config):
        logger.info('starting health check')
        config = check_config_url(config)
        _check_health(config)
