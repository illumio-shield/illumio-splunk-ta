import base64
import importlib.util
import sys
from pathlib import Path
from unittest.mock import Mock, patch


# Load the helper module directly so the test stays isolated from the wider illumio package imports.
HELPER_PATH = Path(__file__).resolve().parents[2] / "lib" / "illumio" / "kvstore_mgmt" / "kvstore_helpers.py"
HELPER_SPEC = importlib.util.spec_from_file_location("kvstore_helpers_under_test", HELPER_PATH)
kvstore_helpers = importlib.util.module_from_spec(HELPER_SPEC)
HELPER_SPEC.loader.exec_module(kvstore_helpers)
request = kvstore_helpers.request


def _build_response(status=200, body=b"ok"):
    response = Mock()
    response.status = status
    response.read.return_value = body
    return response


@patch.object(kvstore_helpers.httplib, "HTTPSConnection")
def test_request_without_proxy_uses_direct_https_connection(mock_https_connection):
    # This test covers the unchanged direct-connection path when no proxy is configured.
    connection = Mock()
    connection.getresponse.return_value = _build_response()
    mock_https_connection.return_value = connection

    response_data, response_status = request(
        "POST",
        "https://example.com:8089/services/test?output_mode=json",
        "{}",
        {"Content-Type": "application/json"},
    )

    assert response_data == b"ok"
    assert response_status == 200
    mock_https_connection.assert_called_once()
    # Without a proxy, the helper should preserve the existing full request target behavior.
    connection.request.assert_called_once_with(
        "POST",
        "https://example.com:8089/services/test?output_mode=json",
        b"{}",
        {"Content-Type": "application/json"},
    )


@patch.object(kvstore_helpers.httplib, "HTTPSConnection")
def test_request_with_http_proxy_uses_tunnel_and_path_only(mock_https_connection):
    # This test covers the new proxy path for an HTTPS target behind an HTTP proxy.
    connection = Mock()
    connection.getresponse.return_value = _build_response()
    mock_https_connection.return_value = connection

    response_data, response_status = request(
        "POST",
        "https://example.com:8089/services/test?output_mode=json",
        "{}",
        {"Content-Type": "application/json"},
        proxy="http://10.2.35.3:3128",
    )

    assert response_data == b"ok"
    assert response_status == 200
    # Use HTTPSConnection here so Python wraps the tunneled socket with TLS for the HTTPS target.
    mock_https_connection.assert_called_once()
    # When a proxy is configured, the helper should tunnel to the target Splunk host.
    connection.set_tunnel.assert_called_once_with(
        "example.com", 8089, headers={"Host": "example.com:8089"}
    )
    # Through a proxy tunnel, the HTTP request target must be the path and query only.
    connection.request.assert_called_once_with(
        "POST",
        "/services/test?output_mode=json",
        b"{}",
        {"Content-Type": "application/json"},
    )


@patch.object(kvstore_helpers.httplib, "HTTPSConnection")
def test_request_with_proxy_credentials_sends_basic_proxy_authorization(mock_https_connection):
    # This test covers the new proxy credential handling added to the helper.
    connection = Mock()
    connection.getresponse.return_value = _build_response()
    mock_https_connection.return_value = connection

    request(
        "POST",
        "https://example.com:8089/services/test",
        "{}",
        {"Content-Type": "application/json"},
        proxy="http://testuser:testpass@10.2.35.3:3128",
    )

    expected_auth = base64.b64encode(b"testuser:testpass").decode("ascii")
    connection.set_tunnel.assert_called_once_with(
        "example.com",
        8089,
        headers={
            "Host": "example.com:8089",
            "Proxy-Authorization": f"Basic {expected_auth}",
        },
    )


@patch.object(kvstore_helpers.httplib, "HTTPConnection")
def test_request_with_http_target_and_proxy_uses_absolute_url_without_tunnel(mock_http_connection):
    # Plain HTTP targets should go through the proxy without CONNECT tunneling.
    connection = Mock()
    connection.getresponse.return_value = _build_response()
    mock_http_connection.return_value = connection
    expected_auth = base64.b64encode(b"testuser:testpass").decode("ascii")

    response_data, response_status = request(
        "POST",
        "http://example.com:8089/services/auth/login",
        {"username": "user", "password": "pass"},
        {"Content-Type": "application/x-www-form-urlencoded"},
        proxy="http://testuser:testpass@10.2.35.3:3128",
    )

    assert response_data == b"ok"
    assert response_status == 200
    mock_http_connection.assert_called_once_with("10.2.35.3:3128")
    connection.set_tunnel.assert_not_called()
    connection.request.assert_called_once_with(
        "POST",
        "http://example.com:8089/services/auth/login",
        b"username=user&password=pass",
        {
            "Content-Type": "application/x-www-form-urlencoded",
            "Proxy-Authorization": f"Basic {expected_auth}",
        },
    )


@patch.object(kvstore_helpers.httplib, "HTTPSConnection")
def test_request_with_proxy_uses_default_port_443_when_not_specified(mock_https_connection):
    # When target URL has no explicit port, tunnel should use default HTTPS port 443.
    connection = Mock()
    connection.getresponse.return_value = _build_response()
    mock_https_connection.return_value = connection

    request(
        "GET",
        "https://splunk-cloud.example.com/services/auth/login",
        "",
        {"Content-Type": "application/json"},
        proxy="http://10.2.35.3:3128",
    )

    connection.set_tunnel.assert_called_once_with(
        "splunk-cloud.example.com", 443, headers={"Host": "splunk-cloud.example.com"}
    )


@patch.object(kvstore_helpers.httplib, "HTTPSConnection")
def test_request_with_https_proxy_scheme_creates_https_connection_to_proxy(mock_https_connection):
    # When proxy URL uses https://, the connection to the proxy itself should use HTTPS.
    connection = Mock()
    connection.getresponse.return_value = _build_response()
    mock_https_connection.return_value = connection

    request(
        "POST",
        "https://example.com:8089/services/test",
        "{}",
        {"Content-Type": "application/json"},
        proxy="https://secure-proxy.example.com:8443",
    )

    # HTTPSConnection should be called for the proxy endpoint.
    mock_https_connection.assert_called()
    # Verify tunnel is set to target host.
    connection.set_tunnel.assert_called_once_with(
        "example.com", 8089, headers={"Host": "example.com:8089"}
    )


@patch.object(kvstore_helpers.httplib, "HTTPSConnection")
def test_request_with_proxy_handles_url_encoded_credentials(mock_https_connection):
    # Proxy credentials with special characters should be URL-decoded before use.
    connection = Mock()
    connection.getresponse.return_value = _build_response()
    mock_https_connection.return_value = connection

    request(
        "POST",
        "https://example.com:8089/services/test",
        "{}",
        {"Content-Type": "application/json"},
        proxy="http://test%40user:pass%23word@10.2.35.3:3128",
    )

    # Credentials should be decoded: test@user:pass#word
    expected_auth = base64.b64encode(b"test@user:pass#word").decode("ascii")
    connection.set_tunnel.assert_called_once_with(
        "example.com",
        8089,
        headers={
            "Host": "example.com:8089",
            "Proxy-Authorization": f"Basic {expected_auth}",
        },
    )


@patch.object(kvstore_helpers.httplib, "HTTPSConnection")
def test_request_with_proxy_preserves_query_string_in_request_target(mock_https_connection):
    # Query parameters should be preserved when tunneling through proxy.
    connection = Mock()
    connection.getresponse.return_value = _build_response()
    mock_https_connection.return_value = connection

    request(
        "GET",
        "https://example.com:8089/servicesNS/nobody/TA-Illumio/storage/collections/data/test?output_mode=json&count=0",
        "",
        {"Content-Type": "application/json"},
        proxy="http://10.2.35.3:3128",
    )

    connection.request.assert_called_once_with(
        "GET",
        "/servicesNS/nobody/TA-Illumio/storage/collections/data/test?output_mode=json&count=0",
        b"",
        {"Content-Type": "application/json"},
    )
