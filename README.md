# Cisco ASA connector

Operations: Get Version, Block IP, Unblock IP, List Sessions, Terminate Sessions, Get Network Group, Update Group, Run Custom Commands, and Execute API Request.

- Execute API Request calls any Cisco ASA REST API endpoint (a path such as `/api/monitoring/serialnumber`) over HTTPS with the configured username and password; a full URL, a `..` segment or a backslash is refused so the credentials only ever go to the configured server. The ASA REST API must be enabled on the device.

Offline tests: `python3 -m pytest tests -c tests/pytest.ini`
