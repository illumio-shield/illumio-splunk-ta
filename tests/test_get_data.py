from utility import mock_module, reset_mock_module, _mock_response
import requests
from mock import patch, Mock, call
import pytest
import base64
import json
import os
import sys

sys.path.insert(
    0, os.path.abspath(os.path.join(__file__, "..", "..", "TA-Illumio", "bin")),
)


@pytest.fixture(scope="module")
def config():
    """All configuration to test."""
    (mock_util, mock_res,), old_setup_resource = mock_module("IllumioUtil.resource")
    (_, mock_logger,), old_setup_logger = mock_module("IllumioUtil.get_logger")

    (_, mock_clilib, mock_bundle_paths,), old_setup_clilib = mock_module(
        "splunk.clilib.bundle_paths"
    )
    mock_clilib.cli_common.getConfStanza.return_value = json.dumps({"supercluster_members":"https://test_url:port"})

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
    import get_data

    yield get_data
    reset_mock_module("IllumioUtil.resource", old_setup_resource)
    reset_mock_module("IllumioUtil.get_logger", old_setup_logger)
    reset_mock_module("splunk.clilib.bundle_paths", old_setup_clilib)


@pytest.fixture(scope="module")
def rest_help():
    """Return rest_help dictonary."""
    rest_list = ["https://test_url:port", "api_key", "api_secret", "cert_path", "org_id", 0, "pce_leader_url",""]
    return rest_list


def test_encode_xml(config):
    """Test encode_xml_text method."""
    gd = config
    raw_text = "&a\"'<>\n"
    encoded_text = gd.encode_xml_text(raw_text)
    expected_output = "&amp;a&quot;&apos;&lt;&gt;"
    assert expected_output == encoded_text


def test_print_xml_stream(config):
    """Test print_xml_stream method."""
    gd = config
    with patch("get_data.print") as mock_print:
        input_text = "test"
        expected_print = '<stream><event unbroken="1"><data>test</data><done/></event></stream>'
        gd.print_xml_stream(input_text)
        mock_print.assert_has_calls([call(expected_print)])


@patch("get_data.requests.get")
def test_get_details_First_httpraise(mock_req, config, rest_help):
    """Test get details."""
    gd = config
    option = "test"

    mock_res = _mock_response(status=500, raise_for_status=requests.HTTPError("Service is down"))
    mock_req.return_value = mock_res

    # Actual call
    data = gd.get_details(option, rest_help)

    autho = "Basic " + base64.b64encode(
        ("%s:%s" % ("api_key", "api_secret")).encode()
    ).decode().replace("\n", "")

    headers = {
        "Authorization": autho,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Prefer": "respond-async",
    }
    expected_call = call("https://test_url:port/api/v2/orgs/org_id", headers=headers, verify="cert_path")

    mock_req.assert_has_calls([expected_call])
    assert mock_res.raise_for_status.call_count == 1
    assert data is None


@patch("get_data.requests.get")
def test_get_details_Second_httpraise(mock_req, config, rest_help):
    """Test get details."""
    gd = config
    option = "test"

    href = {"href": "something"}
    mock_content = json.dumps({"status": "done", "result": href})
    mock_res_1 = _mock_response(status=200, content=mock_content)
    mock_res_2 = _mock_response(status=500, raise_for_status=requests.HTTPError("Service is down"))
    mock_req.side_effect = mock_res_1, mock_res_2

    data = gd.get_details(option, rest_help)
    assert mock_res_2.raise_for_status.call_count == 1
    assert data is None


@patch("get_data.requests.get")
def test_get_details_Second_httpraise_with_503(mock_req, config, rest_help):
    """Test get details."""
    gd = config
    option = "test"

    href = {"href": "something"}
    mock_content = json.dumps({"status": "done", "result": href})
    mock_res_1 = _mock_response(status=200, content=mock_content)
    mock_res_2 = _mock_response(status=503, raise_for_status=requests.HTTPError("Service is down"))
    mock_res_3 = _mock_response(status=500, raise_for_status=requests.HTTPError("Service is down"))
    mock_req.side_effect = mock_res_1, mock_res_2, mock_res_3

    data = gd.get_details(option, rest_help)

    autho = "Basic " + base64.b64encode(
        ("%s:%s" % ("api_key", "api_secret")).encode()
    ).decode().replace("\n", "")

    headers = {
        "Authorization": autho,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    expected_call = call("https://test_url:port/api/v2test", headers=headers, verify="cert_path")

    mock_req.assert_has_calls([expected_call])
    assert mock_res_3.raise_for_status.call_count == 1
    assert data is None


@patch("get_data.requests.get")
def test_get_details_Third_httpraise(mock_req, config, rest_help):
    """Test get details."""
    gd = config
    option = "test"

    href = {"href": "something"}
    mock_content = json.dumps({"status": "pending", "result": href})
    mock_res_1 = _mock_response(status=200)
    mock_res_2 = _mock_response(status=200, content=mock_content)
    mock_res_3 = _mock_response(status=500, raise_for_status=requests.HTTPError("Service is down"))
    mock_req.side_effect = mock_res_1, mock_res_2, mock_res_3

    data = gd.get_details(option, rest_help)
    assert mock_res_2.raise_for_status.call_count == 1
    assert mock_res_3.raise_for_status.call_count == 1
    assert data is None


@patch("get_data.requests.get")
def test_get_details_pending_and_done(mock_req, config, rest_help):
    """Test get details."""
    gd = config
    option = "test"

    href = {"href": "final_location"}
    mock_content = json.dumps({"status": "pending", "result": href})
    mock_content_done = json.dumps({"status": "done", "result": href})
    mock_res_1 = _mock_response(status=200)
    mock_res_2 = _mock_response(status=200, content=mock_content)
    mock_res_3 = _mock_response(status=200, content=mock_content_done)
    mock_req.side_effect = mock_res_1, mock_res_2, mock_res_3

    data = gd.get_details(option, rest_help)

    autho = "Basic " + base64.b64encode(
        ("%s:%s" % ("api_key", "api_secret")).encode()
    ).decode().replace("\n", "")

    headers = {
        "Authorization": autho,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    expected_call = call(
        "https://test_url:port/api/v2final_location", headers=headers, verify="cert_path"
    )

    mock_req.assert_has_calls([expected_call])
    assert mock_res_2.raise_for_status.call_count == 1
    assert mock_res_3.raise_for_status.call_count == 1
    assert data is None


@patch("get_data.requests.get")
def test_get_details_Forth_httpraise(mock_req, config, rest_help):
    """Test get details."""
    gd = config
    option = "test"

    href = {"href": "something"}
    mock_content = json.dumps({"status": "done", "result": href})

    mock_res_1 = _mock_response(status=200)
    mock_res_2 = _mock_response(status=200, content=mock_content)
    mock_res_3 = _mock_response(status=500, raise_for_status=requests.HTTPError("Service is down"))
    mock_req.side_effect = mock_res_1, mock_res_2, mock_res_3

    data = gd.get_details(option, rest_help)
    assert mock_res_2.raise_for_status.call_count == 1
    assert mock_res_3.raise_for_status.call_count == 1
    assert data is None


@patch("get_data.requests.get")
def test_get_details_Final_data(mock_req, config, rest_help):
    """Test get details."""
    gd = config
    option = "test"

    href = {"href": "something"}
    mock_content = json.dumps({"status": "done", "result": href})

    mock_res_1 = _mock_response(status=200)
    mock_res_2 = _mock_response(status=200, content=mock_content)
    mock_res_3 = _mock_response(status=200, content="data")
    mock_req.side_effect = mock_res_1, mock_res_2, mock_res_3

    data = gd.get_details(option, rest_help)
    assert data.content == "data"


@patch("get_data.get_details")
def test_get_label(mock_get_details, config, rest_help):
    """Test get label data."""
    gd = config
    label_data = Mock()
    label_dict = [{}, {}]
    label_data.content = json.dumps(label_dict)
    mock_get_details.return_value = label_data

    with patch("get_data.print") as mock_print:
        expected_output = '<stream><event unbroken="1"><data>{&quot;illumio_type&quot;: &quot;illumio:pce:label&quot;}</data><done/></event></stream>'
        gd.get_label(rest_help)
        mock_print.assert_has_calls([call(expected_output)])


@patch("get_data.get_details")
def test_get_workload_online(mock_get_details, config, rest_help):
    """Test get_workload online 1 offline 0."""
    gd = config
    label_data = Mock()
    label_dict = [{"online": True}, {}]
    label_data.content = json.dumps(label_dict)
    mock_get_details.return_value = label_data
    rest_help[0] = "https://test_url:port"
    with patch("get_data.print") as mock_print:
        expected_output = '<stream><event unbroken="1"><data>{&quot;online&quot;: true, &quot;illumio_type&quot;: &quot;illumio:pce:workload&quot;, &quot;fqdn&quot;: &quot;test_url&quot;}</data><done/></event></stream>'
        expected_output1 = '<stream><event unbroken="1"><data>{&quot;illumio_type&quot;: &quot;illumio:pce:workload&quot;, &quot;fqdn&quot;: &quot;test_url&quot;}</data><done/></event></stream>'
        expected_output2 = '<stream><event unbroken="1"><data>{&quot;illumio_type&quot;: &quot;illumio:pce:workload&quot;, &quot;online_workloads&quot;: 1, &quot;offline_worloads&quot;: 0, &quot;total_workloads&quot;: 1}</data><done/></event></stream>'
        gd.get_workload(rest_help)
        mock_print.assert_has_calls(
            [call(expected_output), call(expected_output1), call(expected_output2)]
        )


@patch("get_data.get_details")
def test_get_workload_offline(mock_get_details, config, rest_help):
    """Test get_workload online 0 offline 1."""
    gd = config
    label_data = Mock()
    label_dict = [{"online": False}]
    label_data.content = json.dumps(label_dict)
    mock_get_details.return_value = label_data

    with patch("get_data.print") as mock_print:
        expected_output = '<stream><event unbroken="1"><data>{&quot;online&quot;: false, &quot;illumio_type&quot;: &quot;illumio:pce:workload&quot;, &quot;fqdn&quot;: &quot;test_url&quot;}</data><done/></event></stream>'
        expected_output1 = '<stream><event unbroken="1"><data>{&quot;illumio_type&quot;: &quot;illumio:pce:workload&quot;, &quot;online_workloads&quot;: 0, &quot;offline_worloads&quot;: 1, &quot;total_workloads&quot;: 1}</data><done/></event></stream>'
        gd.get_workload(rest_help)
        mock_print.assert_has_calls([call(expected_output), call(expected_output1)])


@patch("get_data.get_details")
def test_ip_lists(mock_get_details, config, rest_help):
    """Test get ip lists."""
    gd = config
    label_data = Mock()
    label_dict = [{}, {}]
    label_data.content = json.dumps(label_dict)
    mock_get_details.return_value = label_data

    with patch("get_data.print") as mock_print:
        expected_output = '<stream><event unbroken="1"><data>{&quot;illumio_type&quot;: &quot;illumio:pce:ip_lists&quot;}</data><done/></event></stream>'
        gd.get_ip_lists(rest_help)
        mock_print.assert_has_calls([call(expected_output)])


@patch("get_data.get_details")
def test_get_services(mock_get_details, config, rest_help):
    """Test get_services."""
    gd = config
    label_data = Mock()
    label_dict = [{}, {}]
    label_data.content = json.dumps(label_dict)
    mock_get_details.return_value = label_data

    with patch("get_data.print") as mock_print:
        expected_output = '<stream><event unbroken="1"><data>{&quot;illumio_type&quot;: &quot;illumio:pce:services&quot;}</data><done/></event></stream>'
        gd.get_services(rest_help)
        mock_print.assert_has_calls([call(expected_output)])


@patch("get_data.requests.get")
def test_get_pce_health_http_error(mock_req, config, rest_help):
    """Test get pce health."""
    gd = config
    rest_help = rest_help[:5]
    rest_help.append("session_key")
   
    mock_res = _mock_response(status=500, raise_for_status=requests.HTTPError("Service is down"))
    mock_req.return_value = mock_res


    # Actual call
    with patch("get_data.print") as mock_print:
        gd.get_pce_health(rest_help)
        assert mock_print.call_count == 0

        autho = "Basic " + base64.b64encode(
            ("%s:%s" % ("api_key", "api_secret")).encode()
        ).decode().replace("\n", "")

        headers = {
            "Authorization": autho,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        expected_call = call("https://test_url:port/api/v2/health", headers=headers, verify="cert_path")

        mock_req.assert_has_calls([expected_call])


@patch("get_data.requests.get")
def test_get_pce_health_data(mock_req, config, rest_help):
    """Test get pce health."""
    gd = config
    output = json.dumps([{"type": "standalone"}])
    mock_res = _mock_response(
        status=200, content=output
    )
    mock_req.return_value = mock_res

    with patch("get_data.print") as mock_print:
        # Actual call
        gd.get_pce_health(rest_help)

        autho = "Basic " + base64.b64encode(
            ("%s:%s" % ("api_key", "api_secret")).encode()
        ).decode().replace("\n", "")

        headers = {
            "Authorization": autho,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        expected_call = call("https://test_url:port/api/v2/health", headers=headers, verify="cert_path")
        expected_print = '<stream><event unbroken="1"><data>{&quot;type&quot;: &quot;standalone&quot;, &quot;illumio_type&quot;: &quot;illumio:pce:health&quot;}</data><done/></event></stream>'

        mock_req.assert_has_calls([expected_call])
        mock_print.assert_has_calls([call(expected_print)])


@patch("get_data.requests.get")
def test_get_pce_supercluster_health_data(mock_req, config, rest_help):
    """Test get pce supercluster health with leader_fqdn."""
    gd = config
    output = json.dumps([{"type": "member","fqdn": "pce_url"}])
    mock_res = _mock_response(
        status=200, content=output
    )
    mock_req.return_value = mock_res

    with patch("get_data.print") as mock_print:
        # Actual call
        gd.get_pce_health(rest_help)

        autho = "Basic " + base64.b64encode(
            ("%s:%s" % ("api_key", "api_secret")).encode()
        ).decode().replace("\n", "")

        headers = {
            "Authorization": autho,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        expected_call = call("https://test_url:port/api/v2/health", headers=headers, verify="cert_path")
        expected_print = '<stream><event unbroken="1"><data>{&quot;type&quot;: &quot;member&quot;, &quot;fqdn&quot;: &quot;pce_url&quot;, &quot;illumio_type&quot;: &quot;illumio:pce:health&quot;, &quot;leader_fqdn&quot;: &quot;test_url&quot;}</data><done/></event></stream>'

        mock_req.assert_has_calls([expected_call])
        mock_print.assert_has_calls([call(expected_print)])


@patch("get_data.get_details")
def test_supercluster_ip_lists(mock_get_details, config, rest_help):
    """Test get ip lists for supercluster PCE."""
    gd = config
    label_data = Mock()
    rest_help[5] = 1
    label_dict = [{}, {}]
    label_data.content = json.dumps(label_dict)
    mock_get_details.return_value = label_data

    with patch("get_data.print") as mock_print:
        expected_output = '<stream><event unbroken="1"><data>{&quot;illumio_type&quot;: &quot;illumio:pce:ip_lists&quot;, &quot;leader_fqdn&quot;: &quot;pce_leader_url&quot;}</data><done/></event></stream>'
        gd.get_ip_lists(rest_help)
        mock_print.assert_has_calls([call(expected_output)])


@patch("get_data.get_details")
def test_get_supercluster_services(mock_get_details, config, rest_help):
    """Test get_services for supercluster PCE."""
    gd = config
    label_data = Mock()
    rest_help[5] = 1
    label_dict = [{}, {}]
    label_data.content = json.dumps(label_dict)
    mock_get_details.return_value = label_data

    with patch("get_data.print") as mock_print:
        expected_output = '<stream><event unbroken="1"><data>{&quot;illumio_type&quot;: &quot;illumio:pce:services&quot;, &quot;leader_fqdn&quot;: &quot;pce_leader_url&quot;}</data><done/></event></stream>'
        gd.get_services(rest_help)
        mock_print.assert_has_calls([call(expected_output)])


@patch("get_data.get_details")
def test_get_supercluster_label(mock_get_details, config, rest_help):
    """Test get label data for supercluster PCE."""
    gd = config
    label_data = Mock()
    label_dict = [{}, {}]
    rest_help[5] = 1
    label_data.content = json.dumps(label_dict)
    mock_get_details.return_value = label_data

    with patch("get_data.print") as mock_print:
        expected_output = '<stream><event unbroken="1"><data>{&quot;illumio_type&quot;: &quot;illumio:pce:label&quot;, &quot;leader_fqdn&quot;: &quot;pce_leader_url&quot;}</data><done/></event></stream>'
        gd.get_label(rest_help)
        mock_print.assert_has_calls([call(expected_output)])


@patch("get_data.requests.get")
def test_get_details_second_httpraise_supercluster(mock_req, config, rest_help):
    """Test get details when member available."""
    gd = config
    option = "test"
    rest_help[5] = 1
    rest_help[7] = "https://test_url:port"

    mock_res = _mock_response(status=500, raise_for_status=requests.HTTPError("Service is down"))
    mock_req.return_value = mock_res

    # Actual call
    data = gd.get_details(option, rest_help)

    autho = "Basic " + base64.b64encode(
        ("%s:%s" % ("api_key", "api_secret")).encode()
    ).decode().replace("\n", "")

    headers = {
        "Authorization": autho,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Prefer": "respond-async",
    }
    expected_call = call("https://test_url:port/api/v2/orgs/org_id", headers=headers, verify="cert_path")

    mock_req.assert_has_calls([expected_call])
    assert mock_res.raise_for_status.call_count == 2
    assert data is None


@patch("get_data.requests.get")
def test_get_details_Final_data_when_leader_down(mock_req, config, rest_help):
    """Test get details when leader down."""
    gd = config
    option = "test"
    rest_help[5] = 1
    rest_help[7] = "https://test_url:port"

    href = {"href": "something"}
    mock_content = json.dumps({"status": "done", "result": href})

    mock_res_1 = _mock_response(status=500, raise_for_status=requests.HTTPError("Service is down"))
    mock_res_2 = _mock_response(status=200)
    mock_res_3 = _mock_response(status=200, content=mock_content)
    mock_res_4 = _mock_response(status=200, content="data")
    mock_req.side_effect = mock_res_1, mock_res_2, mock_res_3, mock_res_4

    data = gd.get_details(option, rest_help)
    assert data.content == "data"


@patch("get_data.requests.get")
def test_get_details_when_leader_down_in_retry_mechanism(mock_req, config, rest_help):
    """Test get details when leader down in retry mechanism."""
    gd = config
    option = "test"
    rest_help[5] = 1
    rest_help[7] = "https://test_url:port"

    href = {"href": "something"}
    mock_content = json.dumps({"status": "done", "result": href})

    mock_res_1 = _mock_response(status=200)
    mock_res_2 = _mock_response(status=503, raise_for_status=requests.HTTPError("Service Unavailable"))
    mock_res_3 = _mock_response(status=503, raise_for_status=requests.HTTPError("Service Unavailable"))
    mock_res_4 = _mock_response(status=503, raise_for_status=requests.HTTPError("Service Unavailable"))
    mock_res_5 = _mock_response(status=503, raise_for_status=requests.HTTPError("Service Unavailable"))
    mock_res_6 = _mock_response(status=503, raise_for_status=requests.HTTPError("Service Unavailable"))
    mock_res_7 = _mock_response(status=200)
    mock_res_8 = _mock_response(status=200, content=mock_content)
    mock_res_9 = _mock_response(status=200, content="data")
    mock_req.side_effect = mock_res_1, mock_res_2, mock_res_3, mock_res_4, mock_res_5, mock_res_6, mock_res_7, mock_res_8, mock_res_9

    data = gd.get_details(option, rest_help)
    assert data.content == "data"


@patch("get_data.requests.get")
def test_get_details_when_leader_and_members_down_except_last_member(mock_req, config, rest_help):
    """Test get details when leader and member down in retry mechanism but last member is up."""
    gd = config
    option = "test"
    rest_help[5] = 1
    rest_help[7] = "https://test_url:port,https://test_url:port,https://test_url:port"

    href = {"href": "something"}
    mock_content = json.dumps({"status": "done", "result": href})

    mock_res_1 = _mock_response(status=500, raise_for_status=requests.HTTPError("Service is down"))
    mock_res_2 = _mock_response(status=200)
    mock_res_3 = _mock_response(status=503, raise_for_status=requests.HTTPError("Service Unavailable"))
    mock_res_4 = _mock_response(status=503, raise_for_status=requests.HTTPError("Service Unavailable"))
    mock_res_5 = _mock_response(status=503, raise_for_status=requests.HTTPError("Service Unavailable"))
    mock_res_6 = _mock_response(status=503, raise_for_status=requests.HTTPError("Service Unavailable"))
    mock_res_7 = _mock_response(status=503, raise_for_status=requests.HTTPError("Service Unavailable"))
    mock_res_8 = _mock_response(status=200)
    mock_res_9 = _mock_response(status=200, content=mock_content)
    mock_res_10 = _mock_response(status=500, raise_for_status=requests.HTTPError("Service is down"))
    mock_res_11 = _mock_response(status=200)
    mock_res_12 = _mock_response(status=200, content=mock_content)
    mock_res_13 = _mock_response(status=200, content="data")
    mock_req.side_effect = mock_res_1, mock_res_2, mock_res_3, mock_res_4, mock_res_5, mock_res_6, mock_res_7, mock_res_8, mock_res_9, mock_res_10, mock_res_11, mock_res_12, mock_res_13

    data = gd.get_details(option, rest_help)
    assert data.content == "data"


@patch("get_data.get_details")
def test_get_supercluster_workload_offline(mock_get_details, config, rest_help):
    """Test get_workload online 0 offline 1 when supercluser PCE."""
    gd = config
    rest_help[5] = 1
    label_data = Mock()
    label_dict = [{"online": False}]
    label_data.content = json.dumps(label_dict)
    mock_get_details.return_value = label_data

    with patch("get_data.print") as mock_print:
        expected_output = '<stream><event unbroken="1"><data>{&quot;online&quot;: false, &quot;illumio_type&quot;: &quot;illumio:pce:workload&quot;, &quot;fqdn&quot;: &quot;test_url&quot;, &quot;leader_fqdn&quot;: &quot;pce_leader_url&quot;}</data><done/></event></stream>'
        expected_output1 = '<stream><event unbroken="1"><data>{&quot;illumio_type&quot;: &quot;illumio:pce:workload&quot;, &quot;online_workloads&quot;: 0, &quot;offline_worloads&quot;: 1, &quot;total_workloads&quot;: 1}</data><done/></event></stream>'
        gd.get_workload(rest_help)
        mock_print.assert_has_calls([call(expected_output), call(expected_output1)])


@patch("get_data.get_details")
def test_get_supercluster_workload_online(mock_get_details, config, rest_help):
    """Test get_workload online 1 offline 0 when supercluser PCE."""
    gd = config
    label_data = Mock()
    rest_help[5] = 1
    label_dict = [{"online": True}, {}]
    label_data.content = json.dumps(label_dict)
    mock_get_details.return_value = label_data

    with patch("get_data.print") as mock_print:
        expected_output = '<stream><event unbroken="1"><data>{&quot;online&quot;: true, &quot;illumio_type&quot;: &quot;illumio:pce:workload&quot;, &quot;fqdn&quot;: &quot;test_url&quot;, &quot;leader_fqdn&quot;: &quot;pce_leader_url&quot;}</data><done/></event></stream>'
        expected_output1 = '<stream><event unbroken="1"><data>{&quot;illumio_type&quot;: &quot;illumio:pce:workload&quot;, &quot;fqdn&quot;: &quot;test_url&quot;, &quot;leader_fqdn&quot;: &quot;pce_leader_url&quot;}</data><done/></event></stream>'
        expected_output2 = '<stream><event unbroken="1"><data>{&quot;illumio_type&quot;: &quot;illumio:pce:workload&quot;, &quot;online_workloads&quot;: 1, &quot;offline_worloads&quot;: 0, &quot;total_workloads&quot;: 1}</data><done/></event></stream>'
        gd.get_workload(rest_help)
        mock_print.assert_has_calls(
            [call(expected_output), call(expected_output1), call(expected_output2)]
        )


@patch("get_data.requests.get")
def test_get_details_when_all_PCE_down_when_retrying(mock_req, config, rest_help):
    """Test get details when all PCE in supercluster down while retry mechanism."""
    gd = config
    option = "test"
    rest_help[5] = 1
    rest_help[7] = "https://test_url:port"

    mock_res_1 = _mock_response(status=500, raise_for_status=requests.HTTPError("Service is down"))
    mock_res_2 = _mock_response(status=200)
    mock_res_3 = _mock_response(status=503, raise_for_status=requests.HTTPError("Service Unavailable"))
    mock_res_4 = _mock_response(status=503, raise_for_status=requests.HTTPError("Service Unavailable"))
    mock_res_5 = _mock_response(status=503, raise_for_status=requests.HTTPError("Service Unavailable"))
    mock_res_6 = _mock_response(status=503, raise_for_status=requests.HTTPError("Service Unavailable"))
    mock_res_7 = _mock_response(status=503, raise_for_status=requests.HTTPError("Service Unavailable"))
    
    mock_req.side_effect = mock_res_1, mock_res_2, mock_res_3, mock_res_4, mock_res_5, mock_res_6, mock_res_7

    data = gd.get_details(option, rest_help)
    assert data is None


if __name__ == "__main__":
    pass
