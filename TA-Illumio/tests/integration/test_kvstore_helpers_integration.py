import importlib.util
import os
import sys
from pathlib import Path

import pytest


# Load the helper module directly so the test stays isolated from the wider illumio package imports.
HELPER_PATH = Path(__file__).resolve().parents[2] / "lib" / "illumio" / "kvstore_mgmt" / "kvstore_helpers.py"
HELPER_SPEC = importlib.util.spec_from_file_location("kvstore_helpers_under_test", HELPER_PATH)
kvstore_helpers = importlib.util.module_from_spec(HELPER_SPEC)
HELPER_SPEC.loader.exec_module(kvstore_helpers)
request = kvstore_helpers.request


# The integration test is opt-in because it depends on a real proxy and a reachable HTTPS target.
TEST_PROXY = os.environ.get("KVSTORE_HELPERS_TEST_PROXY")
TEST_URL = os.environ.get("KVSTORE_HELPERS_TEST_URL")


@pytest.mark.skipif(
    not TEST_PROXY or not TEST_URL,
    reason="Set KVSTORE_HELPERS_TEST_PROXY and KVSTORE_HELPERS_TEST_URL to run proxy integration tests.",
)
def test_request_uses_real_proxy_for_https_target():
    # This test exercises the helper against a real proxy without requiring Splunk or KV-store fixtures.
    response_data, response_status = request(
        "GET",
        TEST_URL,
        "",
        {"Content-Type": "application/json"},
        proxy=TEST_PROXY,
    )

    assert response_status == 200
    # A non-empty body is enough here because this test is only validating the proxy network path.
    assert response_data
