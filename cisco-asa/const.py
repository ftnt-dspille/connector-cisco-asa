""" Copyright start
  Copyright (C) 2008 - 2025 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

RECEIVE_FIRST_DATA_TIMEOUT = 30
RECEIVE_SECOND_DATA_TIMEOUT = 1
MAX_SIZE_FOR_OUTPUT = 5 * 1024

ERROR_SRC_DEST_ANY = "Both Source and Destination can't be any"
ERROR_INVALID_ACCESS_GROUP = 'Invalid access-group'
ACCESS_LIST_AVAILAIBLE = 'Access list found'
ERROR_DUPLICATE_ACCESS_LIST = "Access list named '{present_acl_name}' configured for the given interface '{intf}' """ \
                              "and direction '{direction}', can't overwrite it with the given access-list '{acl_name}'. " \
                              "Please check the configuration"
ERROR_ACCESS_LIST_NOT_FOUND = 'Access list not found'
ACCESS_LIST_VALIDATED = 'Access List validated'
DEVICE_RESPONSE_TEXT = "Got text from device =  '{}'"
CONNECTION_UNSUCCESSFUL = 'Connection Unsuccessful'
CONNECTION_SUCCESSFUL = 'Connection Successful'
EXECUTING_COMMAND = "Executing command =  '{}'"
EXECUTED_COMMAND = "Executed command =  '{}'"
ANY_POLICY = 'any'
ERROR_SSH_CONNECTION_FAILED = 'SSH connection to device failed'
ERROR_INVALID_NETWORK_GROUP = 'Invalid network-group'
REST_TIMEOUT = 60
REST_METHODS = ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')
