import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import Mock, patch


MODULE_PATH = Path(__file__).resolve().parents[2] / "bin" / "illumio_kvstore_upload.py"


class DummyEventWriter:
    INFO = "INFO"
    ERROR = "ERROR"


def _load_module():
    kvstore_helpers = types.ModuleType("illumio.kvstore_mgmt.kvstore_helpers")
    kvstore_helpers.request = Mock()

    kvstore_ops = types.ModuleType("illumio.kvstore_mgmt.kvstore_operations")
    kvstore_ops.getCollectionNamesToReplicate = Mock()
    kvstore_ops.copyCollection = Mock()

    illumio_pkg = types.ModuleType("illumio")
    kvstore_pkg = types.ModuleType("illumio.kvstore_mgmt")

    splunklib_pkg = types.ModuleType("splunklib")
    modularinput_mod = types.ModuleType("splunklib.modularinput")
    modularinput_mod.EventWriter = DummyEventWriter

    constants_mod = types.ModuleType("illumio_constants")
    constants_mod.ILLUMIO_TA = "TA-Illumio"

    splunk_utils_mod = types.ModuleType("illumio_splunk_utils")
    splunk_utils_mod.get_credentials_for_search_heads = Mock()

    stubbed_modules = {
        "illumio": illumio_pkg,
        "illumio.kvstore_mgmt": kvstore_pkg,
        "illumio.kvstore_mgmt.kvstore_helpers": kvstore_helpers,
        "illumio.kvstore_mgmt.kvstore_operations": kvstore_ops,
        "splunklib": splunklib_pkg,
        "splunklib.modularinput": modularinput_mod,
        "illumio_constants": constants_mod,
        "illumio_splunk_utils": splunk_utils_mod,
    }

    with patch.dict(sys.modules, stubbed_modules):
        spec = importlib.util.spec_from_file_location("illumio_kvstore_upload_under_test", MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

    return module, kvstore_ops, kvstore_helpers, splunk_utils_mod


def test_upload_collections_skips_host_when_remote_login_fails():
    module, kvstore_ops, kvstore_helpers, splunk_utils_mod = _load_module()
    service = types.SimpleNamespace(scheme="https", host="local-hf", port=8089, token="local-token")
    ew = Mock()

    splunk_utils_mod.get_credentials_for_search_heads.return_value = {
        "search-head-1.example.com": {"username": "admin", "password": "bad-password"}
    }
    kvstore_ops.getCollectionNamesToReplicate.return_value = [["TA-Illumio", "illumio_workloads"]]
    kvstore_helpers.request.side_effect = RuntimeError("401 Unauthorized")

    uploader = module.KVStoreUpload(service, ew, proxy=None, input_name="illumio://scp3-emea")
    uploader.upload_collections()

    kvstore_ops.copyCollection.assert_not_called()
    error_messages = [call.args[1] for call in ew.log.call_args_list if call.args[0] == DummyEventWriter.ERROR]
    assert any("scp3-emea" in message for message in error_messages)
    assert any("search-head-1.example.com:8089" in message for message in error_messages)
    assert any("login failed" in message for message in error_messages)


def test_upload_collections_logs_target_hosts_and_replicates_on_success():
    module, kvstore_ops, kvstore_helpers, splunk_utils_mod = _load_module()
    service = types.SimpleNamespace(scheme="https", host="local-hf", port=8089, token="local-token")
    ew = Mock()

    splunk_utils_mod.get_credentials_for_search_heads.return_value = {
        "search-head-2.example.com": {"username": "admin", "password": "good-password", "is_token": False}
    }
    kvstore_ops.getCollectionNamesToReplicate.return_value = [["TA-Illumio", "illumio_labels"]]
    kvstore_helpers.request.return_value = (b"<response><sessionKey>remote-token</sessionKey></response>", 200)

    uploader = module.KVStoreUpload(service, ew, proxy="http://proxy:3128", input_name="illumio://scp3-emea")
    uploader.upload_collections()

    kvstore_ops.copyCollection.assert_called_once_with(
        ew,
        "local-token",
        "https://local-hf:8089",
        "remote-token",
        "https://search-head-2.example.com:8089",
        "TA-Illumio",
        "illumio_labels",
        "http://proxy:3128",
        False,  # is_bearer_token
    )
    # Check that login was called (now there are additional calls for session info and auth probe)
    kvstore_helpers.request.assert_any_call(
        "POST",
        "https://search-head-2.example.com:8089/services/auth/login",
        {"username": "admin", "password": "good-password"},
        {"Content-Type": "application/x-www-form-urlencoded"},
        proxy="http://proxy:3128",
    )
    info_messages = [call.args[1] for call in ew.log.call_args_list if call.args[0] == DummyEventWriter.INFO]
    assert any(
        "KV-store replication targets for input 'scp3-emea': search-head-2.example.com" in message
        for message in info_messages
    )
    assert any("Replicating KV-store collection 'TA-Illumio/illumio_labels'" in message for message in info_messages)


def test_upload_collections_uses_port_from_stored_search_head_target():
    module, kvstore_ops, kvstore_helpers, splunk_utils_mod = _load_module()
    service = types.SimpleNamespace(scheme="https", host="local-hf", port=8089, token="local-token")
    ew = Mock()

    splunk_utils_mod.get_credentials_for_search_heads.return_value = {
        "10.2.2.79": {"username": "admin", "password": "good-password", "port": 8089, "is_token": False}
    }
    kvstore_ops.getCollectionNamesToReplicate.return_value = [["TA-Illumio", "illumio_labels"]]
    kvstore_helpers.request.return_value = (b"<response><sessionKey>remote-token</sessionKey></response>", 200)

    uploader = module.KVStoreUpload(service, ew, proxy=None, input_name="illumio://scp3-emea")
    uploader.upload_collections()

    # Check that login was called (now there are additional calls for session info and auth probe)
    kvstore_helpers.request.assert_any_call(
        "POST",
        "https://10.2.2.79:8089/services/auth/login",
        {"username": "admin", "password": "good-password"},
        {"Content-Type": "application/x-www-form-urlencoded"},
        proxy=None,
    )
    kvstore_ops.copyCollection.assert_called_once_with(
        ew,
        "local-token",
        "https://local-hf:8089",
        "remote-token",
        "https://10.2.2.79:8089",
        "TA-Illumio",
        "illumio_labels",
        None,
        False,  # is_bearer_token
    )


def test_upload_collections_continues_to_next_host_when_auth_probe_request_fails():
    module, kvstore_ops, kvstore_helpers, splunk_utils_mod = _load_module()
    service = types.SimpleNamespace(scheme="https", host="local-hf", port=8089, token="local-token")
    ew = Mock()

    splunk_utils_mod.get_credentials_for_search_heads.return_value = {
        "bad.example.com": {"username": "admin1", "password": "token-1", "is_token": False},
        "good.example.com": {"username": "admin2", "password": "token-2", "is_token": False},
    }
    kvstore_ops.getCollectionNamesToReplicate.return_value = [["TA-Illumio", "illumio_labels"]]

    def request_side_effect(method, url, data, headers, proxy=None):
        if method == "POST" and url == "https://bad.example.com:8089/services/auth/login":
            return (b"<response><sessionKey>bad-session</sessionKey></response>", 200)
        if method == "POST" and url == "https://good.example.com:8089/services/auth/login":
            return (b"<response><sessionKey>good-session</sessionKey></response>", 200)
        if method == "GET" and "bad.example.com:8089/services/authentication/current-context" in url:
            raise RuntimeError("Tunnel connection failed: 503 Service Unavailable")
        if method == "GET" and "good.example.com:8089/services/authentication/current-context" in url:
            return ('{"entry":[{"content":{"username":"admin2","realname":"Admin Two","roles":["admin"],"capabilities":["admin_all_objects"]}}]}', 200)
        if method == "GET" and "good.example.com:8089/services/authentication/httpauth-tokens" in url:
            return ('{"entry":[]}', 200)
        if method == "GET" and "bad.example.com:8089/servicesNS/nobody/TA-Illumio/storage/collections/config" in url:
            raise RuntimeError("Tunnel connection failed: 503 Service Unavailable")
        if method == "GET" and "good.example.com:8089/servicesNS/nobody/TA-Illumio/storage/collections/config" in url:
            return ('{"entry":[]}', 200)
        raise AssertionError(f"Unexpected request: {method} {url}")

    kvstore_helpers.request.side_effect = request_side_effect

    uploader = module.KVStoreUpload(service, ew, proxy="http://proxy:3128", input_name="illumio://scp3-emea")
    uploader.upload_collections()

    kvstore_ops.copyCollection.assert_called_once_with(
        ew,
        "local-token",
        "https://local-hf:8089",
        "good-session",
        "https://good.example.com:8089",
        "TA-Illumio",
        "illumio_labels",
        "http://proxy:3128",
        False,
    )
    error_messages = [call.args[1] for call in ew.log.call_args_list if call.args[0] == DummyEventWriter.ERROR]
    info_messages = [call.args[1] for call in ew.log.call_args_list if call.args[0] == DummyEventWriter.INFO]
    assert any("Auth probe failed" in message and "bad.example.com:8089" in message for message in error_messages)
    assert any("Replicating KV-store collection 'TA-Illumio/illumio_labels'" in message and "good.example.com:8089" in message for message in info_messages)
