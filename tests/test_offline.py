import pytest

from connectors.core.connector import ConnectorError
from ciscoasa_pkg.operations import operations, execute_api_request
from ciscoasa_pkg.utils import json_object, safe_endpoint


def test_registered():
    assert operations['execute_api_request'] is execute_api_request


def test_get_sends_credentials(fake, config):
    out = execute_api_request(config, {'endpoint': '/api/monitoring/serialnumber'})
    assert out['serialNumber'] == 'TEST123'
    seen = fake.seen[0]
    assert seen['method'] == 'GET' and seen['auth'].startswith('Basic ')
    assert seen['agent'] == 'REST API Agent'


def test_endpoint_without_leading_slash(fake, config):
    execute_api_request(config, {'endpoint': 'api/monitoring/serialnumber'})
    assert fake.seen[0]['path'] == '/api/monitoring/serialnumber'


def test_query_params_as_string(fake, config):
    execute_api_request(config, {'endpoint': '/api/monitoring/serialnumber',
                                 'query_params': '{"limit": 5}'})
    assert fake.seen[0]['path'].endswith('?limit=5')


def test_post_body(fake, config):
    out = execute_api_request(config, {'endpoint': '/api/objects/networkobjects', 'method': 'post',
                                       'request_body': {'name': 'x'}})
    assert out == {'echo': {'name': 'x'}}
    assert fake.seen[0]['body'] == {'name': 'x'}


def test_delete_empty_response(fake, config):
    assert execute_api_request(config, {'endpoint': '/api/objects/networkobjects/x',
                                        'method': 'DELETE'}) == {}


def test_auth_failure_surfaced(fake, config):
    config['password'] = 'wrong'
    with pytest.raises(ConnectorError, match='401'):
        execute_api_request(config, {'endpoint': '/api/monitoring/serialnumber'})


def test_not_found_surfaced(fake, config):
    with pytest.raises(ConnectorError, match='404'):
        execute_api_request(config, {'endpoint': '/api/nothing'})


@pytest.mark.parametrize('endpoint', [
    'https://evil.example.com/x', 'http://evil.example.com', '//evil.example.com/x',
    'ftp://evil.example.com/x',
    '/api/../x', '/api/%2e%2e/x', '/api/%252e%252e/x', '/api/%25252e%25252e/x',
    '/api/..%2fx', '..', '/api\\x', '/api/..\\x',
])
def test_refused_endpoints(fake, config, endpoint):
    with pytest.raises(ConnectorError, match='not a full URL'):
        execute_api_request(config, {'endpoint': endpoint})
    assert fake.seen == []


@pytest.mark.parametrize('endpoint', [None, '', '   '])
def test_missing_endpoint(config, endpoint):
    with pytest.raises(ConnectorError, match='required'):
        execute_api_request(config, {'endpoint': endpoint})


def test_invalid_method(config):
    with pytest.raises(ConnectorError, match='Method'):
        execute_api_request(config, {'endpoint': '/api/x', 'method': 'LIST'})


@pytest.mark.parametrize('field', ['query_params', 'request_body'])
@pytest.mark.parametrize('value', ['{bad', '[1]', '"s"', 5])
def test_invalid_json(config, field, value):
    with pytest.raises(ConnectorError):
        execute_api_request(config, {'endpoint': '/api/x', field: value})


def test_json_object_blank():
    assert json_object('', 'x') is None and json_object(None, 'x') is None
    assert json_object('{"a": 1}', 'x') == {'a': 1}


def test_safe_endpoint_keeps_query():
    assert safe_endpoint('/api/x?a=1') == '/api/x?a=1'
