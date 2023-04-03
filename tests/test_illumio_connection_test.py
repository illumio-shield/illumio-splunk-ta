import os
import sys
import requests
from mock import patch, Mock, call
from utility import _mock_response

sys.path.insert(
    0, os.path.abspath(os.path.join(__file__, "..", "..", "TA-Illumio", "bin")),
)

import illumio_connection_test as ict


@patch("illumio_connection_test.requests.get")
def test_connection_status_401(mock_get):
    """Test test_connection method."""
    pce_url = "pce_url"
    api_key_id = "key_id"
    api_secret = "api_secret"
    cert_path = "cert_path"

    mock_res = _mock_response(status=401)
    mock_get.return_value = mock_res

    with patch("illumio_connection_test.print") as mock_print:
        expected_output = (
            "Authentication failed: API key id and/or API Secret were incorrect. Status Code: 401"
        )
        ict.test_connection(pce_url, api_key_id, api_secret, cert_path)
        mock_print.assert_has_calls([call(expected_output)])


@patch("illumio_connection_test.requests.get")
def test_connection_status_403(mock_get):
    """Test test_connection method."""
    pce_url = "pce_url"
    api_key_id = "key_id"
    api_secret = "api_secret"
    cert_path = "cert_path"

    mock_res = _mock_response(status=403)
    mock_get.return_value = mock_res
    with patch("illumio_connection_test.print") as mock_print:
        expected_output = "Authorization failed: user is not authorized. Status Code: 403"
        ict.test_connection(pce_url, api_key_id, api_secret, cert_path)
        mock_print.assert_has_calls([call(expected_output)])


@patch("illumio_connection_test.requests.get")
def test_connection_status_500(mock_get):
    """Test test_connection method."""
    pce_url = "pce_url"
    api_key_id = "key_id"
    api_secret = "api_secret"
    cert_path = "cert_path"

    mock_res = _mock_response(status=500)
    mock_get.return_value = mock_res
    with patch("illumio_connection_test.print") as mock_print:
        expected_output = "Connection Failed. Status Code: 500"
        ict.test_connection(pce_url, api_key_id, api_secret, cert_path)
        mock_print.assert_has_calls([call(expected_output)])


@patch("illumio_connection_test.requests.get")
def test_connection_status_200(mock_get):
    """Test test_connection method."""
    pce_url = "pce_url"
    api_key_id = "key_id"
    api_secret = "api_secret"
    cert_path = "cert_path"

    mock_res = _mock_response(status=200)
    mock_get.return_value = mock_res
    with patch("illumio_connection_test.print") as mock_print:
        expected_output = "Connection successful. Status Code: 200"
        ict.test_connection(pce_url, api_key_id, api_secret, cert_path)
        mock_print.assert_has_calls([call(expected_output)])


@patch("illumio_connection_test.requests.get")
def test_connection_status_sslerror(mock_get):
    """Test test_connection method."""
    pce_url = "pce_url"
    api_key_id = "key_id"
    api_secret = "api_secret"
    cert_path = "cert_path"

    mock_get.side_effect = requests.exceptions.SSLError("Test SSL Error")
    with patch("illumio_connection_test.print") as mock_print:
        expected_output = (
            "SSLError: Invalid certificate file or certificate not found. Test SSL Error"
        )
        ict.test_connection(pce_url, api_key_id, api_secret, cert_path)
        mock_print.assert_has_calls([call(expected_output)])


@patch("illumio_connection_test.requests.get")
def test_connection_status_connectionerror(mock_get):
    """Test test_connection method."""
    pce_url = "pce_url"
    api_key_id = "key_id"
    api_secret = "api_secret"
    cert_path = "cert_path"

    mock_get.side_effect = requests.exceptions.ConnectionError("Test Connection Error")
    with patch("illumio_connection_test.print") as mock_print:
        expected_output = "Connection Error: Please enter valid URL or Check the network connection. Test Connection Error"
        ict.test_connection(pce_url, api_key_id, api_secret, cert_path)
        mock_print.assert_has_calls([call(expected_output)])


@patch("illumio_connection_test.requests.get")
def test_connection_status_timeouterror(mock_get):
    """Test test_connection method."""
    pce_url = "pce_url"
    api_key_id = "key_id"
    api_secret = "api_secret"
    cert_path = "cert_path"

    mock_get.side_effect = requests.exceptions.Timeout("Test Timeout Error")
    with patch("illumio_connection_test.print") as mock_print:
        expected_output = (
            "Request timed out while trying to connect to the remote server. Test Timeout Error"
        )
        ict.test_connection(pce_url, api_key_id, api_secret, cert_path)
        mock_print.assert_has_calls([call(expected_output)])


@patch("illumio_connection_test.requests.get")
def test_connection_status_error(mock_get):
    """Test test_connection method."""
    pce_url = "pce_url"
    api_key_id = "key_id"
    api_secret = "api_secret"
    cert_path = "cert_path"

    mock_get.side_effect = Exception("Test Error")
    with patch("illumio_connection_test.print") as mock_print:
        expected_output = "Connection Failed: Test Error"
        ict.test_connection(pce_url, api_key_id, api_secret, cert_path)
        mock_print.assert_has_calls([call(expected_output)])


if __name__ == "__main__":
    pass
