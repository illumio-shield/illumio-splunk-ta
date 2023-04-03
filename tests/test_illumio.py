from utility import mock_module, reset_mock_module, _mock_response
from mock import patch, Mock, call
import pytest
import base64
import json
import os
import sys
import requests

sys.path.insert(
    0, os.path.abspath(os.path.join(__file__, "..", "..", "TA-Illumio", "bin")),
)


@pytest.fixture(scope="module")
def config():
    """All configuration to test."""
    (mock_util, mock_get_credentials,), old_setup_cred = mock_module("IllumioUtil.get_credentials")
    (_, mock_logger,), old_setup_logger = mock_module("IllumioUtil.get_logger")
    (mock_splunk, mock_ser,), old_setup_search = mock_module("splunk.search")
    (_, mock_res,), old_setup_rest = mock_module("splunk.rest")
    (_, mock_version,), old_setup_version = mock_module("splunk.version")
    (_, mock_clilib, mock_bundle_paths,), old_setup_clilib = mock_module(
        "splunk.clilib.bundle_paths"
    )

    mock_util.resource = {
        "orgs": "/orgs/",
        "api_version": "/api/v2",
        "label": "/labels/",
        "workload": "/workloads/",
        "ip_lists": "/sec_policy/draft/ip_lists",
        "services": "/sec_policy/draft/services",
        "pce_health": "/health",
        "product_version": "/product_version",
    }
    mock_util.app_name = "TA-Illumio"
    mock_splunk.version.__version__ = "8.0.2.1"
    mock_util.get_credentials.return_value = "username", "password"
    mock_clilib.cli_common.getConfStanza.return_value = {"app": "app"}

    import illumio

    mocks = {}
    mocks["mock_clilib"] = mock_clilib
    mocks["mock_util"] = mock_util
    yield illumio, mocks

    reset_mock_module("IllumioUtil.get_credentials", mock_get_credentials)
    reset_mock_module("IllumioUtil.get_logger", old_setup_logger)
    reset_mock_module("splunk.version", old_setup_version)
    reset_mock_module("splunk.search", old_setup_search)
    reset_mock_module("splunk.rest", old_setup_rest)
    reset_mock_module("splunk.clilib.bundle_paths", old_setup_clilib)


@patch("splunk.rest.simpleRequest")
@patch("illumio.Illumio.get_mod_input_configs")
def test_update_mod_inputs(mock_inp_conf, mock_req, config):
    """Test rest_help method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    mock_inp_conf.return_value = val_data = {
        "api_key_id": "api_key_id",
        "api_secret": "api_secret",
        "pce_url": "https://url",
        "name": "input://name",
        "session_key": "session_key",
        "protocol": "protocol",
        "port_number": "8000",
        "stanza": "mod_input",
        "self_signed_cert_path": "",
        "time_interval_port": 10,
        "cnt_port_scan": 10,
        "interval": 3700,
        "qurantine_label": "",
        "hostname": "",
        "org_id": 1,
        "allowed_ip": "",
    }

    content = {
        "interval": 3700,
        "cnt_port_scan": 10,
        "pce_url": "https://url",
        "port_number": 8000,
        "time_interval_port": "3600.00",
    }
    app = {"app": "illumio"}
    entry_1 = {"name": "name", "acl": app, "content": content}
    response = {"entry": [entry_1]}
    status = {"status": 200}
    mock_req.return_value = [status, json.dumps(response)]

    res = il.Illumio().update_mod_inputs(val_data)

    mock_req.assert_called_with(
        "/servicesNS/nobody/illumio/data/inputs/illumio/name",
        "session_key",
        postargs={
            "api_secret": "",
            "api_key_id": "",
            "cnt_port_scan": 10,
            "pce_url": "https://url",
            "interval": 3700,
            "time_interval_port": 3600,
        },
        method="POST",
        raiseAllErrors=True,
    )


@patch("illumio.Illumio.update_mod_inputs")
@patch("illumio.Illumio.get_mod_input_configs")
def test_rest_help(mock_inp_conf, mock_mod_inp, config):
    """Test rest_help method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    mock_inp_conf.return_value = {
        "api_key_id": "api_key_id",
        "api_secret": "api_secret",
        "pce_url": "https://url",
        "name": "input://name",
        "session_key": "session_key",
        "protocol": "protocol",
        "port_number": "8000",
        "stanza": "mod_input",
        "self_signed_cert_path": "",
        "time_interval_port": 10,
        "cnt_port_scan": 10,
        "interval": 3700,
        "qurantine_label": "",
        "hostname": "",
        "org_id": 1,
        "allowed_ip": "",
    }

    res = il.Illumio().rest_help()

    assert all([a == b for a, b in zip(res, ["https://url", "api_key_id", "api_secret", "", 1])])


@patch("get_data.print")
@patch("illumio.Illumio.update_mod_inputs")
@patch("illumio.Illumio.get_mod_input_configs")
def test_print_ps_details(mock_inp_conf, mock_mod_inp, mock_print, config):
    """Test print_ps_details method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    mock_inp_conf.return_value = {
        "api_key_id": "api_key_id",
        "api_secret": "api_secret",
        "pce_url": "https://url",
        "name": "input://name",
        "session_key": "session_key",
        "protocol": "protocol",
        "port_number": "8000",
        "stanza": "mod_input",
        "self_signed_cert_path": "",
        "time_interval_port": 10,
        "cnt_port_scan": 10,
        "interval": 3700,
        "qurantine_label": "",
        "hostname": "",
        "org_id": 1,
        "allowed_ip": "",
    }

    il.Illumio().print_ps_details()

    mock_util.store_password.assert_called_with("name_key", "api_key_id", "session_key")
    mock_print.assert_called_with(
        '<stream><event unbroken="1"><data>{&quot;pce_url&quot;: &quot;https://url&quot;, &quot;port_scan&quot;: 10, &quot;interval&quot;: 10, &quot;illumio_type&quot;: &quot;illumio:pce:ps_details&quot;}</data><done/></event></stream>'
    )


@patch("illumio.Illumio.update_mod_inputs")
@patch("illumio.Illumio.get_mod_input_configs")
def test_get_cred(mock_inp_conf, mock_mod_inp, config):
    """Test if creds get if input already exists."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    mock_inp_conf.return_value = {
        "api_key_id": "",
        "api_secret": "",
        "pce_url": "https://url",
        "name": "input://name",
        "session_key": "session_key",
        "protocol": "protocol",
        "port_number": "8000",
        "stanza": "mod_input",
        "self_signed_cert_path": "",
        "time_interval_port": 10,
        "cnt_port_scan": 10,
        "interval": 3700,
        "qurantine_label": "",
        "hostname": "",
        "org_id": 1,
        "allowed_ip": "",
    }

    il_obj = il.Illumio()

    mock_util.get_credentials.assert_called_with("name_key", "session_key")


@patch("illumio.Illumio.update_mod_inputs")
@patch("illumio.Illumio.get_mod_input_configs")
def test_password_store(mock_inp_conf, mock_mod_inp, config):
    """Test password strore while creating input first time."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    mock_inp_conf.return_value = val_data = {
        "api_key_id": "api_key_id",
        "api_secret": "api_secret",
        "pce_url": "https://url",
        "name": "input://name",
        "session_key": "session_key",
        "protocol": "protocol",
        "port_number": "8000",
        "stanza": "mod_input",
        "self_signed_cert_path": "",
        "time_interval_port": 10,
        "cnt_port_scan": 10,
        "interval": 3700,
        "qurantine_label": "",
        "hostname": "",
        "org_id": 1,
        "allowed_ip": "",
    }

    il_obj = il.Illumio()

    mock_util.store_password.assert_called_with("name_key", "api_key_id", "session_key")


SCHEME = r"""<scheme>
    <title>Illumio</title>
    <description>Enable data inputs for splunk add-on for Illumio</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>xml</streaming_mode>

    <endpoint>
        <args>
            <arg name="name">
                <title>Name</title>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg>
            <arg name="pce_url">
                <title>Supercluster Leader / PCE URL</title>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
                <validation>
                    validate(match(pce_url, '^(https://)\S+'), "PCE URL: PCE URL must begin with 'https://'")
                </validation>
            </arg>
            <arg name="api_key_id">
                <title>API Authentication Username</title>
                <description>e.g. 'api_1234567890'</description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg>
            <arg name="api_secret">
                <title>API Secret</title>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg>
            <arg name="port_number">
                <title>Port Number for syslogs (TCP)</title>
                <description>Only required when receiving syslog directly. Not required when getting syslog from S3. Example value: 514</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="time_interval_port">
                <title>Port Scan configuration: scan interval in seconds</title>
                <description>Interval during which the Port Scan Threshold is exceeded</description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
                <validation>
                    validate(is_nonneg_int(time_interval_port), "Time interval for syslog port scan: Time Interval must be non negative integer.")
                </validation>
            </arg>
            <arg name="cnt_port_scan">
                <title>Port Scan Configuration: Unique ports threshold</title>
                <description>Minimum number of ports scanned by a port-scan</description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
                <validation>
                    validate(is_nonneg_int(cnt_port_scan), "Count for port scan: must be non negative integer.")
                </validation>
            </arg>
            <arg name="self_signed_cert_path">
                <title>Certificate Path</title>
                <description>Path for the custom root certificate</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="qurantine_label">
                <title>Labels to quarantine workloads</title>
                <description>Comma Separated list of three labels of type app, location and environment.</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
                <validation>
                    validate(match(qurantine_label, '(\S+,\S+,\S+)'), "Enter three labels of type app, env and loc")
                </validation>
            </arg>
            <arg name="allowed_ip">
                <title>Comma Separated list of Source IPs, which will be ignored in Port scans</title>
                <description>Port scans from these Source IPs are ignored</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="private_ip">
                <title>(This field is removed from UI but keeping it here to avoid error logs on upgrade) Private IP address of Illumio Nodes</title>
                <description>Comma Separated IP address of all the nodes managed by this PCE instance.</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="hostname">
                <title>Hostnames of Illumio Nodes</title>
                <description>Comma Separated Hostnames of all the nodes managed by this PCE instance.</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="enable_data_collection">
                <title>Data Collection</title>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="org_id">
                <title>Organization ID</title>
                <description>This Org-ID will be used for making REST API calls to PCE.</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
                <validation>
                    validate(is_nonneg_int(org_id), "Organization ID: Must be non-negative integer.")
                </validation>
            </arg>
        </args>
    </endpoint>
</scheme>
"""


@patch("splunk.rest.simpleRequest")
@patch("illumio.validate_connection")
@patch("illumio.syslog_port_status")
@patch("illumio.get_validation_data")
def test_validate_arguments_portstatus0tcpreloadfail(
    mock_getdata, mock_port_status, mock_conn_val, mock_req, config
):
    """Test validate_arguments method."""
    il, mocks = config
    mock_util = mocks["mock_util"]
    val_data = {
        "api_key_id": "api_key_id",
        "api_secret": "api_secret",
        "pce_url": "https://url",
        "session_key": "session_key",
        "protocol": "protocol",
        "port_number": "8000",
        "stanza": "mod_input",
        "self_signed_cert_path": "",
        "time_interval_port": 10,
        "cnt_port_scan": 10,
        "interval": 3700,
        "qurantine_label": "",
        "hostname": "",
        "org_id": 1,
        "allowed_ip": "",
    }

    mock_port_status.return_value = 0
    mock_getdata.return_value = val_data
    mock_req.side_effect = ["fake", Exception("Test")]

    il.validate_arguments()

    mock_util.get_logger().exception.assert_called_with("Unable to reload TCP endpoint")


@patch("splunk.rest.simpleRequest")
@patch("illumio.validate_connection")
@patch("illumio.syslog_port_status")
@patch("illumio.get_validation_data")
def test_validate_arguments_portstatus0exception(
    mock_getdata, mock_port_status, mock_conn_val, mock_req, config
):
    """Test validate_arguments method."""
    il, mocks = config
    mock_util = mocks["mock_util"]
    val_data = {
        "api_key_id": "api_key_id",
        "api_secret": "api_secret",
        "pce_url": "https://url",
        "session_key": "session_key",
        "protocol": "protocol",
        "port_number": "8000",
        "stanza": "mod_input",
        "self_signed_cert_path": "",
        "time_interval_port": 10,
        "cnt_port_scan": 10,
        "interval": 3700,
        "qurantine_label": "",
        "hostname": "",
        "org_id": 1,
        "allowed_ip": "",
    }

    mock_port_status.return_value = 0
    mock_getdata.return_value = val_data
    mock_req.side_effect = Exception("Error")

    with pytest.raises(Exception):
        il.validate_arguments()
        mock_util.get_logger().exception.assert_called_with("Unable to create input")


@patch("illumio.validate_connection")
@patch("illumio.syslog_port_status")
@patch("illumio.get_validation_data")
def test_validate_arguments_portstatus1(mock_getdata, mock_port_status, mock_conn_val, config):
    """Test validate_arguments method."""
    il, mocks = config

    val_data = {
        "api_key_id": "api_key_id",
        "api_secret": "api_secret",
        "pce_url": "https://url",
        "session_key": "session_key",
        "protocol": "protocol",
        "port_number": "8000",
        "stanza": "stanza",
        "self_signed_cert_path": "",
        "time_interval_port": 10,
        "cnt_port_scan": 10,
        "interval": 3700,
        "qurantine_label": "",
        "hostname": "",
        "org_id": 1,
        "allowed_ip": "",
    }

    mock_port_status.return_value = 1
    mock_getdata.return_value = val_data
    il.validate_arguments()


@patch("illumio.get_validation_data")
def test_validate_arguments_noapikey(mock_getdata, config):
    """Test validate_arguments method."""
    il, mocks = config

    val_data = {
        "api_key_id": "",
        "api_secret": "",
        "pce_url": "https://url",
        "session_key": "session_key",
        "protocol": "protocol",
        "port_number": 8000,
        "stanza": "stanza",
        "self_signed_cert_path": "",
        "time_interval_port": 8000,
        "cnt_port_scan": 8000,
        "interval": 3700,
        "qurantine_label": "app,env,loc",
        "hostname": "hostname",
        "org_id": 1,
        "allowed_ip": "10.0.6.29",
    }

    mock_getdata.return_value = val_data
    il.validate_arguments()


@patch("illumio.print_error")
def test_validate_hostname_exception(mock_error, config):
    """Test validate_hostname method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    session_key = "session_key"
    hostname = 123  # Exception
    pce_url = "pce_url"

    il.validate_hostname(hostname, pce_url, session_key)

    mock_util.get_logger().exception.assert_called_with("Error in Validating Hostname")


@patch("illumio.print_error")
def test_validate_hostname_error(mock_error, config):
    """Test validate_hostname method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    session_key = "session_key"
    hostname = "host1,host2"
    pce_url = "pce_url"
    mock_util.is_hostname.side_effect = [True, False]

    il.validate_hostname(hostname, pce_url, session_key)

    mock_error.assert_called_with(
        "Invalid value for Hostname", "session_key",
    )


@patch("illumio.print_error")
def test_validate_allowed_ip(mock_error, config):
    """Test validate_allowed_ip method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    session_key = "session_key"
    allowed_ip = "ip1,ip2"

    mock_util.is_ip.side_effect = [True, True]

    il.validate_allowed_ip(allowed_ip, session_key)


@patch("illumio.print_error")
def test_validate_allowed_ip_exception(mock_error, config):
    """Test validate_allowed_ip method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    session_key = "session_key"
    allowed_ip = 123  # exception

    il.validate_allowed_ip(allowed_ip, session_key)

    mock_util.get_logger().exception.assert_called_with(
        "Error in Validating Allowed port scanner Source IP addresses"
    )


@patch("illumio.print_error")
def test_validate_allowed_ip_error(mock_error, config):
    """Test validate_allowed_ip method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    session_key = "session_key"
    allowed_ip = "ip,ip1"

    mock_util.is_ip.side_effect = [False, False]

    il.validate_allowed_ip(allowed_ip, session_key)

    mock_error.assert_has_calls(
        [
            call(
                "Please enter comma separated valid Allowed port scanner Source IP addresses.",
                "session_key",
            )
        ]
    )


@patch("illumio.print_error")
def test_validate_qurantine_label_exception(mock_error, config):
    """Test validate_qurantine_label method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    session_key = "session_key"
    qurantine_label = 123  # for exception
    pce_url = "pce_url"
    api_key_id = "api_key_id"
    api_secret = "api_secret"
    org_id = "org_id"

    mock_util.check_label_exists.side_effect = ["label", "label", "label"]

    il.validate_qurantine_label(
        qurantine_label, pce_url, api_key_id, api_secret, org_id, session_key
    )
    mock_util.get_logger().exception.assert_called_with("Error in Validating Label")


@patch("illumio.print_error")
def test_validate_qurantine_label_label(mock_error, config):
    """Test validate_qurantine_label method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    session_key = "session_key"
    qurantine_label = "app,env,loc"
    pce_url = "pce_url"
    api_key_id = "api_key_id"
    api_secret = "api_secret"
    org_id = "org_id"

    mock_util.check_label_exists.side_effect = ["label", "label", "label"]

    il.validate_qurantine_label(
        qurantine_label, pce_url, api_key_id, api_secret, org_id, session_key
    )

    mock_util.writeconf.assert_called_with(
        "TA-Illumio",
        session_key,
        "illumio",
        pce_url,
        {"app": "label:app", "env": "label:env", "loc": "label:loc"},
    )


@patch("illumio.print_error")
def test_validate_qurantine_label_loclabelnotfound(mock_error, config):
    """Test validate_qurantine_label method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    session_key = "session_key"
    qurantine_label = "app,env,loc"
    pce_url = "pce_url"
    api_key_id = "api_key_id"
    api_secret = "api_secret"
    org_id = "org_id"

    mock_util.check_label_exists.side_effect = ["label", "label", ""]

    il.validate_qurantine_label(
        qurantine_label, pce_url, api_key_id, api_secret, org_id, session_key
    )
    mock_error.assert_has_calls([call("Third label should be of type loc. ", "session_key",)])


@patch("illumio.print_error")
def test_validate_qurantine_label_envlabelnotfound(mock_error, config):
    """Test validate_qurantine_label method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    session_key = "session_key"
    qurantine_label = "app,env,loc"
    pce_url = "pce_url"
    api_key_id = "api_key_id"
    api_secret = "api_secret"
    org_id = "org_id"

    mock_util.check_label_exists.side_effect = ["label", "", "label"]

    il.validate_qurantine_label(
        qurantine_label, pce_url, api_key_id, api_secret, org_id, session_key
    )
    mock_error.assert_has_calls([call("Second label should be of type env. ", "session_key",)])


@patch("illumio.print_error")
def test_validate_qurantine_label_applabelnotfound(mock_error, config):
    """Test validate_qurantine_label method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    session_key = "session_key"
    qurantine_label = "app,env,loc"
    pce_url = "pce_url"
    api_key_id = "api_key_id"
    api_secret = "api_secret"
    org_id = "org_id"

    mock_util.check_label_exists.side_effect = ["", "label", "label"]

    il.validate_qurantine_label(
        qurantine_label, pce_url, api_key_id, api_secret, org_id, session_key
    )
    mock_error.assert_has_calls([call("First label should be of type app. ", "session_key",)])


@patch("illumio.print_error")
def test_validate_qurantine_label_wronglabel(mock_error, config):
    """Test validate_qurantine_label method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    session_key = "session_key"
    qurantine_label = "label"
    pce_url = "pce_url"
    api_key_id = "api_key_id"
    api_secret = "api_secret"
    org_id = "org_id"

    il.validate_qurantine_label(
        qurantine_label, pce_url, api_key_id, api_secret, org_id, session_key
    )

    mock_error.assert_has_calls(
        [call("One label each of type app,env and loc are required. ", "session_key",)]
    )


@patch("illumio.print_error")
def test_validate_qurantine_label_nolabel(mock_error, config):
    """Test validate_qurantine_label method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    session_key = "session_key"
    qurantine_label = ""
    pce_url = "pce_url"
    api_key_id = "api_key_id"
    api_secret = "api_secret"
    org_id = "org_id"

    il.validate_qurantine_label(
        qurantine_label, pce_url, api_key_id, api_secret, org_id, session_key
    )

    mock_util.writeconf.assert_called_with(
        "TA-Illumio", session_key, "illumio", pce_url, {"app": "", "env": "", "loc": ""}
    )


def test_validate_org_id(config):
    """Test validate_org_id method."""
    il, mocks = config

    org_id = 1
    session_key = "session_key"

    il.validate_org_id(org_id, session_key)


@patch("illumio.print_error")
def test_validate_org_id_wrong_value(mock_error, config):
    """Test validate_org_id method."""
    il, mocks = config

    org_id = -1.1
    session_key = "session_key"

    il.validate_org_id(org_id, session_key)
    mock_error.assert_has_calls(
        [
            call(
                "Organization ID: Invalid organization ID, Only non-negative integer allowed.",
                "session_key",
            )
        ]
    )


@patch("illumio.print_error")
@patch("illumio.requests.get")
def test_validate_connection_exception(mock_req, mock_error, config):
    """Test validate_connection method."""
    il, mocks = config

    pce_url = "https://url"
    session_key = "session_key"
    api_key_id = "api_key_id"
    api_secret = "api_secret"
    cert_path = ""

    mock_req.side_effect = Exception("Test Error")

    il.validate_connection(pce_url, api_key_id, api_secret, cert_path, session_key)
    mock_error.assert_has_calls(
        [call("Illumio Error: Error while validating credentials Test Error", "session_key",)]
    )


@patch("illumio.print_error")
@patch("illumio.requests.get")
def test_validate_connection_status500(mock_req, mock_error, config):
    """Test validate_connection method."""
    il, mocks = config

    pce_url = "https://url"
    session_key = "session_key"
    api_key_id = "api_key_id"
    api_secret = "api_secret"
    cert_path = ""

    mock_res = _mock_response(status=500)
    mock_req.return_value = mock_res

    il.validate_connection(pce_url, api_key_id, api_secret, cert_path, session_key)
    mock_error.assert_has_calls([call("Connection Failed.", "session_key",)])


@patch("illumio.print_error")
@patch("illumio.requests.get")
def test_validate_connection_status403(mock_req, mock_error, config):
    """Test validate_connection method."""
    il, mocks = config

    pce_url = "https://url"
    session_key = "session_key"
    api_key_id = "api_key_id"
    api_secret = "api_secret"
    cert_path = ""

    mock_res = _mock_response(status=403)
    mock_req.return_value = mock_res

    il.validate_connection(pce_url, api_key_id, api_secret, cert_path, session_key)
    mock_error.assert_has_calls(
        [
            call(
                "Authorization failed: user is not authorized, the incorrect Organization ID parameter was used.",
                "session_key",
            )
        ]
    )


@patch("illumio.print_error")
@patch("illumio.requests.get")
def test_validate_connection_status401(mock_req, mock_error, config):
    """Test validate_connection method."""
    il, mocks = config

    pce_url = "https://url"
    session_key = "session_key"
    api_key_id = "api_key_id"
    api_secret = "api_secret"
    cert_path = ""

    mock_res = _mock_response(status=401)
    mock_req.return_value = mock_res

    il.validate_connection(pce_url, api_key_id, api_secret, cert_path, session_key)
    mock_error.assert_has_calls(
        [
            call(
                "Authentication failed: API key id and/or API Secret were incorrect.",
                "session_key",
            )
        ]
    )


def test_validate_port_status(config):
    """Test validate_port_status method."""
    il, mocks = config

    cnt_port_scan = -1
    session_key = "session_key"
    port_status = 1
    protocol = "smtp"
    port_number = 8000

    il.validate_port_status(port_status, protocol, port_number, session_key)


@patch("illumio.print_error")
def test_validate_port_status_wrong_value(mock_error, config):
    """Test validate_port_status method."""
    il, mocks = config

    cnt_port_scan = -1
    session_key = "session_key"
    port_status = 2
    protocol = "smtp"
    port_number = 8000

    il.validate_port_status(port_status, protocol, port_number, session_key)
    mock_error.assert_has_calls(
        [call("smtp: 8000 is not available as it is already in use.", "session_key",)]
    )


def test_validate_cnt_port_scan(config):
    """Test validate_cnt_port_scan method."""
    il, mocks = config

    cnt_port_scan = 1
    session_key = "session_key"
    il.validate_cnt_port_scan(cnt_port_scan, session_key)


@patch("illumio.print_error")
def test_validate_cnt_port_scan_wrong_value(mock_error, config):
    """Test validate_cnt_port_scan method."""
    il, mocks = config

    cnt_port_scan = -1
    session_key = "session_key"
    il.validate_cnt_port_scan(cnt_port_scan, session_key)
    mock_error.assert_has_calls(
        [call("Count for port scan: must be non negative integer.", "session_key",)]
    )


def test_validate_time_interval_port(config):
    """Test validate_time_interval_port method."""
    il, mocks = config

    time_interval_port = 1
    session_key = "session_key"
    il.validate_time_interval_port(time_interval_port, session_key)


@patch("illumio.print_error")
def test_validate_time_interval_port_wrong_value(mock_error, config):
    """Test validate_time_interval_port method."""
    il, mocks = config

    time_interval_port = -1
    session_key = "session_key"
    il.validate_time_interval_port(time_interval_port, session_key)
    mock_error.assert_has_calls(
        [
            call(
                "Time interval for syslog port scan: Time Interval must be non negative integer",
                "session_key",
            )
        ]
    )


def test_validate_port_number(config):
    """Test validate_port_number method."""
    il, mocks = config

    port_number = "5000"
    session_key = "session_key"
    il.validate_port_number(port_number, session_key)


@patch("illumio.print_error")
def test_validate_port_number_wrong_value(mock_error, config):
    """Test validate_port_number method."""
    il, mocks = config

    port_number = "wrong_port"
    session_key = "session_key"
    il.validate_port_number(port_number, session_key)
    mock_error.assert_has_calls([call("Port Number: Invalid port number", "session_key",)])


def test_validate_pce_url(config):
    """Test validate_pce_url method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    pce_url = "https://url"
    session_key = "session_key"
    il.validate_pce_url(pce_url, session_key)


@patch("illumio.print_error")
def test_validate_pce_url_wrong_value(mock_error, config):
    """Test validate_pce_url method."""
    il, mocks = config

    pce_url = "wrong_url"
    session_key = "session_key"
    il.validate_pce_url(pce_url, session_key)
    mock_error.assert_has_calls(
        [call("PCE URL: PCE URL must begin with 'https://'", "session_key",)]
    )


@patch("illumio.print_error")
def test_validate_interval_wrong_value(mock_error, config):
    """Test validate_interval method."""
    il, mocks = config
    mock_util = mocks["mock_util"]
    interval = 3500
    session_key = "session_key"
    il.validate_interval(interval, session_key)
    mock_error.assert_has_calls(
        [
            call(
                "Interval: Enter a non negative interval greater than equal to 3600 seconds or a valid cron schedule",
                "session_key",
            )
        ]
    )


def test_validate_interval_excepion(config):
    """Test validate_interval method."""
    il, mocks = config
    mock_util = mocks["mock_util"]
    interval = "test"
    session_key = "session_key"
    il.validate_interval(interval, session_key)
    mock_util.get_logger().debug.assert_called_with("Interval: An cron expression was entered")


def test_validate_interval(config):
    """Test validate_interval method."""
    il, mocks = config
    interval = 3700
    session_key = "session_key"

    il.validate_interval(interval, session_key)


@patch("splunk.rest.simpleRequest")
def test_get_validation_data(mock_req, config):
    """Test get_validation_data method."""
    il, mocks = config
    pass


@patch("splunk.rest.simpleRequest")
def test_syslog_port_status_return1(mock_req, config):
    """Test syslog_port_status method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    protocol = "protocol"
    port_number = 8000
    mod_input_name = "mod_input_name"
    session_key = "session_key"

    source = {"sourcetype": "illumio:pce"}
    entry_1 = [{"content": source, "name": "8000"}]
    output = {"entry": entry_1}
    mock_req.return_value = ["dummy", json.dumps(output)]

    res = il.syslog_port_status(protocol, port_number, mod_input_name, session_key)
    assert res == 1


@patch("splunk.rest.simpleRequest")
def test_syslog_port_status_return2(mock_req, config):
    """Test syslog_port_status method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    protocol = "protocol"
    port_number = 8000
    mod_input_name = "mod_input_name"
    session_key = "session_key"

    source = {"sourcetype": ""}
    entry_1 = [{"content": source, "name": "8000"}]
    output = {"entry": entry_1}
    mock_req.return_value = ["dummy", json.dumps(output)]

    res = il.syslog_port_status(protocol, port_number, mod_input_name, session_key)
    assert res == 2


@patch("splunk.rest.simpleRequest")
def test_syslog_port_status_return0(mock_req, config):
    """Test syslog_port_status method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    protocol = "protocol"
    port_number = 8000
    mod_input_name = "mod_input_name"
    session_key = "session_key"

    output = {"entry": ""}
    mock_req.return_value = ["dummy", json.dumps(output)]

    res = il.syslog_port_status(protocol, port_number, mod_input_name, session_key)
    assert res == 0


@patch("splunk.rest.simpleRequest")
def test_syslog_port_status_exception(mock_req, config):
    """Test syslog_port_status method."""
    il, mocks = config
    mock_util = mocks["mock_util"]

    protocol = "protocol"
    port_number = 8000
    mod_input_name = "mod_input_name"
    session_key = "session_key"

    mock_req.side_effect = Exception("test")

    with pytest.raises(Exception):
        il.syslog_port_status(protocol, port_number, mod_input_name, session_key)
        mock_util.get_logger().exception.assert_called_with(
            "Unable to load all TCP endpoint in validate_arguments"
        )


@patch("illumio.get_notification_message")
def test_print_error(mock_noti, config):
    """Test print_error method."""
    il, mocks = config
    mock_util = mocks["mock_util"]
    message = "test message"
    session_key = "session_key"

    with pytest.raises(SystemExit):
        il.print_error(message, session_key)
        mock_util.get_logger().exception.assert_called_with("message")


@patch("splunk.rest.simpleRequest")
def test_get_notification_message_exception(mock_req, config):
    """Test get_notification_message method."""
    il, mocks = config
    mock_util = mocks["mock_util"]
    message = "test message"
    session_key = "session_key"

    mock_req.side_effect = Exception("test")

    il.get_notification_message(message, session_key)

    mock_util.get_logger().exception.assert_called_with("Failed to give notification message")


@patch("splunk.rest.simpleRequest")
def test_get_notification_message(mock_req, config):
    """Test get_notification_message method."""
    il, _ = config

    message = "test message"
    session_key = "session_key"

    il.get_notification_message(message, session_key)
    mock_req.assert_has_calls(
        [
            call(
                "/services/messages",
                "session_key",
                postargs={
                    "severity": "error",
                    "name": "TA-Illumio",
                    "value": "TA-Illumio modular input validation failed: test message",
                },
            )
        ]
    )


def test_do_scheme(config):
    """Test method."""
    il, _ = config
    with patch("illumio.print") as mock_print:
        expected_output = SCHEME
        il.do_scheme()
        mock_print.assert_has_calls([call(expected_output)])


if __name__ == "__main__":
    pass
