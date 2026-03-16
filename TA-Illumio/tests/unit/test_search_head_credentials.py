import importlib.util
import sys
import types
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "bin" / "illumio_splunk_utils.py"


def _load_module():
    splunk_client = types.ModuleType("splunklib.client")
    splunk_client.Service = object

    splunklib_pkg = types.ModuleType("splunklib")
    constants_mod = types.ModuleType("illumio_constants")
    constants_mod.SEARCH_HEAD_CREDENTIALS_PREFIX = "kvstore"
    constants_mod.KVSTORE_BATCH_DEFAULT = 1000
    pce_utils_mod = types.ModuleType("illumio_pce_utils")
    pce_utils_mod.IllumioInputParameters = object

    stubbed_modules = {
        "splunklib": splunklib_pkg,
        "splunklib.client": splunk_client,
        "illumio_constants": constants_mod,
        "illumio_pce_utils": pce_utils_mod,
    }

    original_modules = {name: sys.modules.get(name) for name in stubbed_modules}
    try:
        sys.modules.update(stubbed_modules)
        spec = importlib.util.spec_from_file_location("illumio_splunk_utils_under_test", MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, original in original_modules.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


def _build_service(entries):
    storage_passwords = types.SimpleNamespace(list=lambda: entries)
    return types.SimpleNamespace(storage_passwords=storage_passwords)


@pytest.mark.parametrize(
    ("stored_username", "expected"),
    [
        (
            "admin@10.2.2.79",
            {"10.2.2.79": {"username": "admin", "password": "secret", "port": None}},
        ),
        (
            "admin@10.2.2.79:8089",
            {"10.2.2.79": {"username": "admin", "password": "secret", "port": 8089}},
        ),
        (
            "admin@search-head.example.com",
            {"search-head.example.com": {"username": "admin", "password": "secret", "port": None}},
        ),
        (
            "admin@search-head.example.com:8443",
            {"search-head.example.com": {"username": "admin", "password": "secret", "port": 8443}},
        ),
        (
            " admin @search-head.example.com:8089/ ",
            {"search-head.example.com": {"username": "admin", "password": "secret", "port": 8089}},
        ),
    ],
)
def test_get_credentials_for_search_heads_accepts_supported_target_formats(stored_username, expected):
    module = _load_module()
    service = _build_service(
        [
            {
                "content": {
                    "realm": "kvstore://scp3-emea",
                    "username": stored_username,
                    "clear_password": "secret",
                }
            }
        ]
    )

    credentials = module.get_credentials_for_search_heads(service, "illumio://scp3-emea")

    assert credentials == expected


@pytest.mark.parametrize(
    "stored_username",
    [
        "admin10.2.2.79",
        "admin@",
        "@10.2.2.79",
        "admin@10.2.2.79:abc",
        "admin@10.2.2.79:0",
        "admin@10.2.2.79:65536",
        "admin@search-head.example.com:8089:8089",
    ],
)
def test_get_credentials_for_search_heads_rejects_malformed_target_formats(stored_username):
    module = _load_module()
    service = _build_service(
        [
            {
                "content": {
                    "realm": "kvstore://scp3-emea",
                    "username": stored_username,
                    "clear_password": "secret",
                }
            }
        ]
    )

    credentials = module.get_credentials_for_search_heads(service, "illumio://scp3-emea")

    assert credentials == {}
