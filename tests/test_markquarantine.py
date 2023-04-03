from utility import mock_module, reset_mock_module, SampleModularAction, _mock_response
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
    (mock_splunk, mock_res,), old_setup_search = mock_module("splunk.search")
    (_, mock_version,), old_setup_version = mock_module("splunk.version")
    (_, mock_clilib, mock_bundle_paths,), old_setup_clilib = mock_module(
        "splunk.clilib.bundle_paths"
    )
    (mock_cim_action, mock_modular_action,), old_setup_cim = mock_module(
        "cim_actions.ModularAction"
    )

    mock_splunk.version.__version__ = "8.0.2.1"
    mock_util.get_credentials.return_value = "username", "password"
    mock_clilib.cli_common.getConfStanza.return_value = {"app": "app"}
    mock_cim_action.ModularAction = SampleModularAction

    import markquarantine

    mocks = {}
    mocks["mock_clilib"] = mock_clilib
    yield markquarantine, mocks

    reset_mock_module("IllumioUtil.get_credentials", mock_get_credentials)
    reset_mock_module("IllumioUtil.get_logger", old_setup_logger)
    reset_mock_module("splunk.version", old_setup_version)
    reset_mock_module("splunk.search", old_setup_search)
    reset_mock_module("splunk.clilib.bundle_paths", old_setup_clilib)
    reset_mock_module("cim_actions.ModularAction", old_setup_cim)


@patch("splunk.rest.simpleRequest")
def test_quarantine_workload_noentry(mock_simple_req, config):
    """Test quarantine_workload method ."""
    mq, _ = config

    mock_simple_req.return_value = [None, json.dumps({"entry": []})]

    res = mq.quarantine_workload("workload_uuid", "fqdn", "session_key")
    assert res == "noSetupFound"


@patch("splunk.rest.simpleRequest")
def test_quarantine_workload_no_pceurl(mock_simple_req, config):
    """Test quarantine_workload method ."""
    mq, _ = config
    content1 = {
        "pce_url": "url",  # https://fqdn
    }
    entry1 = {"content": content1, "name": "modinput"}
    mock_simple_req.return_value = [None, json.dumps({"entry": [entry1]})]

    res = mq.quarantine_workload("workload_uuid", "fqdn", "session_key")
    assert res == "noSetupFound"


@patch("splunk.search.searchAll")
@patch("splunk.rest.simpleRequest")
def test_quarantine_workload_no_label(mock_simple_req, mock_search, config):
    """Test quarantine_workload method ."""
    mq, _ = config
    content1 = {
        "pce_url": "https://fqdn",
    }
    entry1 = {"content": content1, "name": "modinput"}
    mock_simple_req.return_value = [None, json.dumps({"entry": [entry1]})]
    mock_search.return_value = []
    res = mq.quarantine_workload("workload_uuid", "fqdn", "session_key")

    assert res == "noLabelFound"


@patch("markquarantine.request_quarantine")
@patch("splunk.search.searchAll")
@patch("splunk.rest.simpleRequest")
def test_quarantine_workload(mock_simple_req, mock_search, mock_req_qua, config):
    """Test quarantine_workload method ."""
    mq, mocks = config
    mock_clilib = mocks["mock_clilib"]

    content1 = {
        "pce_url": "https://fqdn",
    }
    entry1 = {"content": content1, "name": "modinput"}
    mock_simple_req.return_value = [None, json.dumps({"entry": [entry1]})]
    mock_search.return_value = []

    mock_clilib.cli_common.getConfStanza.return_value = {"app": "123:#54"}
    mock_req_qua.return_value = "false"
    res = mq.quarantine_workload("workload_uuid", "fqdn", "session_key")
    # so here output depends on request_quarantine so no need to take all values
    assert res == "false"


def test_set_labels(config):
    """Test set_labels method."""
    mq, mocks = config
    labels = [{"href": "href", "type": "app"}, {"href": "href", "type": "env"}]
    labels_list = []
    app = ["app_href", "app_label"]
    env = ["env_href", "env_label"]
    loc = ["loc_href", "loc_label"]
    role = []

    res1, res2 = mq.set_labels(labels, labels_list, app, env, loc, role)

    expected_res1 = ["app:app_label:app_href", "env:env_label:env_href", "loc:loc_label:loc_href"]
    expected_res2 = [{"href": "app_href"}, {"href": "env_href"}, {"href": "loc_href"}]

    assert res1 == expected_res1
    assert res2 == expected_res2


def test_set_labels_empty_labels(config):
    """Test set_labels method."""
    mq, mocks = config
    labels = []
    labels_list = []
    app = ["app_href", "app_label"]
    env = ["env_href", "env_label"]
    loc = ["loc_href", "loc_label"]
    role = []

    res1, res2 = mq.set_labels(labels, labels_list, app, env, loc, role)

    expected_res1 = ["app:app_label:app_href", "loc:loc_label:loc_href", "env:env_label:env_href"]
    expected_res2 = [{"href": "app_href"}, {"href": "loc_href"}, {"href": "env_href"}]

    assert res1 == expected_res1
    assert res2 == expected_res2


@patch("markquarantine.requests.put")
def test_request_quarantine_status500(mock_req, config):
    """Test request_quarantine method."""
    mq, mocks = config
    cred_list = ["pce_url", "org_id", "api_key", "api_secret"]
    workload_uuid = "10"
    label_list = [{"href": "app_href"}, {"href": "env_href"}, {"href": "loc_href"}]
    type_label = "type_label"
    session_key = "session_key"

    mock_res = _mock_response(status=500, raise_for_status=requests.HTTPError("Service is down"))
    mock_req.return_value = mock_res

    output = mq.request_quarantine(cred_list, workload_uuid, label_list, type_label, session_key)

    assert output == "false"


@patch("splunk.search.searchAll")
@patch("markquarantine.requests.put")
def test_request_quarantine(mock_req, mock_search, config):
    """Test request_quarantine method."""
    mq, mocks = config
    cred_list = ["pce_url", "org_id", "api_key", "api_secret"]
    workload_uuid = "10"
    label_list = [{"href": "app_href"}, {"href": "env_href"}, {"href": "loc_href"}]
    type_label = "type_label"
    session_key = "session_key"

    mock_res = _mock_response(status=200)

    output_text = [
        {"status": "updated"},
    ]
    mock_res.text = json.dumps(output_text)
    mock_req.return_value = mock_res
    mock_search.return_value = []

    output = mq.request_quarantine(cred_list, workload_uuid, label_list, type_label, session_key)

    assert mock_search.call_count == 1
    assert output == mock_res


@patch("markquarantine.quarantine_workload")
def test_handle_response_false(mock_quar, config):
    """Test handle Response."""
    mq, mocks = config

    work_uuid = "uuid"
    fqdn = "fqdn"

    mock_quar.return_value = "false"

    with patch("utility.print") as mock_print:
        expected_output = "Quarantine Workload was unsuccessful status=2"
        mq.IllumioAction().handle_response(work_uuid, fqdn)
        mock_print.assert_has_calls([call(expected_output)])


@patch("markquarantine.quarantine_workload")
def test_handle_response_noLabelFound(mock_quar, config):
    """Test handle Response."""
    mq, mocks = config

    work_uuid = "uuid"
    fqdn = "fqdn"
    mock_quar.return_value = "noLabelFound"

    with patch("utility.print") as mock_print:
        expected_output = (
            "Quarantine Workload was unsuccessful, Labels Configuration not found status=2"
        )
        mq.IllumioAction().handle_response(work_uuid, fqdn)
        mock_print.assert_has_calls([call(expected_output)])


@patch("markquarantine.quarantine_workload")
def test_handle_response_noSetupFound(mock_quar, config):
    """Test handle Response."""
    mq, mocks = config

    work_uuid = "uuid"
    fqdn = "fqdn"
    mock_quar.return_value = "noSetupFound"

    with patch("utility.print") as mock_print:
        expected_output = (
            "Illumio credentials not found for fqdn, please complete Illumio setup status=2"
        )
        mq.IllumioAction().handle_response(work_uuid, fqdn)
        mock_print.assert_has_calls([call(expected_output)])


@patch("markquarantine.quarantine_workload")
def test_handle_response_status_200_updated(mock_quar, config):
    """Test handle Response."""
    mq, mocks = config

    work_uuid = "uuid"
    fqdn = "fqdn"

    mock_res = _mock_response(status=200)

    output_text = [
        {"status": "updated"},
    ]
    mock_res.text = json.dumps(output_text)
    mock_quar.return_value = mock_res

    with patch("utility.print") as mock_print:
        expected_output = '[{"status": "updated"}] status=200'
        mq.IllumioAction().handle_response(work_uuid, fqdn)
        mock_print.assert_has_calls([call(expected_output)])


@patch("markquarantine.quarantine_workload")
def test_handle_response_status_200_pending(mock_quar, config):
    """Test handle Response."""
    mq, mocks = config

    work_uuid = "uuid"
    fqdn = "fqdn"

    mock_res = _mock_response(status=200)

    output_text = [
        {"status": "pending"},
    ]
    mock_res.text = json.dumps(output_text)
    mock_quar.return_value = mock_res

    with patch("utility.print") as mock_print:
        expected_output = '[{"status": "pending"}] status=200'
        mq.IllumioAction().handle_response(work_uuid, fqdn)
        mock_print.assert_has_calls([call(expected_output)])


@patch("markquarantine.quarantine_workload")
def test_handle_response_status_500(mock_quar, config):
    """Test handle Response."""
    mq, mocks = config

    work_uuid = "uuid"
    fqdn = "fqdn"

    mock_res = _mock_response(status=500)

    mock_res.text = json.dumps("service is down.")
    mock_quar.return_value = mock_res

    with patch("utility.print") as mock_print:
        expected_output = '"service is down." status=500'
        mq.IllumioAction().handle_response(work_uuid, fqdn)
        mock_print.assert_has_calls([call(expected_output)])


@patch("splunk.search.searchOne")
def test_do_work_no_result(mock_search, config):
    """Test handle Response."""
    mq, mocks = config

    mock_search.return_value = False

    with patch("utility.print") as mock_print:
        expected_output_1 = "Required capability not assigned, Quarantine Workload was unsuccessful"
        expected_output_2 = (
            "Required capability not assigned, Quarantine Workload was unsuccessful status=2"
        )
        output = mq.IllumioAction().dowork()
        mock_print.assert_has_calls([call(expected_output_1), call(expected_output_2)])
        assert output == 0


@patch("splunk.search.searchOne")
def test_do_work_with_zero_result(mock_search, config):
    """Test handle Response."""
    mq, mocks = config

    mock_result = Mock()
    mock_result.values.return_value = [0]
    mock_search.return_value = mock_result

    with patch("utility.print") as mock_print:
        expected_output_1 = (
            "Required capability not assigned, Quarantine Workload was unsuccessful status=2"
        )
        expected_output_2 = "Quarantine Workload was unsuccessful, workload_uuid or pce_fqdn parameter not found status=2"
        output = mq.IllumioAction().dowork()
        mock_print.assert_has_calls([call(expected_output_1), call(expected_output_2)])


@patch("splunk.search.searchOne")
@patch("markquarantine.quarantine_workload")
def test_do_work_with_one_result(mock_quar, mock_search, config):
    """Test handle Response."""
    mq, mocks = config

    mock_quar.return_value = "noSetupFound"
    mock_result = Mock()
    mock_result.values.return_value = [1]
    mock_search.return_value = mock_result
    # here we tested handle_response call from do_work
    with patch("utility.print") as mock_print:
        expected_output_1 = (
            "Illumio credentials not found for fqdn, please complete Illumio setup status=2"
        )
        output = mq.IllumioAction().dowork()
        mock_print.assert_has_calls([call(expected_output_1)])


@patch("splunk.search.searchOne")
def test_do_work_with_exception(mock_search, config):
    """Test handle Response."""
    mq, mocks = config

    mock_result = Mock()
    mock_result.values.return_value = [0]
    mock_search.side_effect = Exception("Error Test")
    with patch("utility.print") as mock_print:
        expected_output_1 = "Quarantine Workload was unsuccessful exception=Error Test status=2"
        output = mq.IllumioAction().dowork()
        mock_print.assert_has_calls([call(expected_output_1)])


if __name__ == "__main__":
    pass
