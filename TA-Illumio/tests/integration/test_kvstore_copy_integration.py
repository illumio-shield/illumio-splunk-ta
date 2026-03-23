import json
import os
import sys
import types
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


# Add the TA lib directory so the integration test can import the KV-store modules directly.
LIB_PATH = Path(__file__).resolve().parents[2] / "lib"
BIN_PATH = Path(__file__).resolve().parents[2] / "bin"
sys.path.insert(0, str(LIB_PATH))
sys.path.insert(1, str(BIN_PATH))

# Stub the Splunk cli module used by kvstore_operations so the test can import the module outside Splunk.
splunk = types.ModuleType("splunk")
clilib = types.ModuleType("splunk.clilib")
cli_common = types.ModuleType("splunk.clilib.cli_common")
cli_common.getConfStanza = lambda *args, **kwargs: {}
clilib.cli_common = cli_common
splunk.clilib = clilib
sys.modules["splunk"] = splunk
sys.modules["splunk.clilib"] = clilib
sys.modules["splunk.clilib.cli_common"] = cli_common

from illumio.kvstore_mgmt.kvstore_helpers import request
from illumio.kvstore_mgmt.kvstore_operations import copyCollection, deleteCollection


# This integration test is opt-in because it writes to real Splunk KV-store collections on source and target.
TEST_SOURCE_HOST = os.environ.get("KVSTORE_SOURCE_HOST")
TEST_SOURCE_PORT = os.environ.get("KVSTORE_SOURCE_PORT", "8089")
TEST_SOURCE_SCHEME = os.environ.get("KVSTORE_SOURCE_SCHEME", "https")
TEST_SOURCE_USERNAME = os.environ.get("KVSTORE_SOURCE_USERNAME")
TEST_SOURCE_PASSWORD = os.environ.get("KVSTORE_SOURCE_PASSWORD")

TEST_TARGET_HOST = os.environ.get("KVSTORE_TARGET_HOST")
TEST_TARGET_PORT = os.environ.get("KVSTORE_TARGET_PORT", "8089")
TEST_TARGET_SCHEME = os.environ.get("KVSTORE_TARGET_SCHEME", "https")
TEST_TARGET_USERNAME = os.environ.get("KVSTORE_TARGET_USERNAME")
TEST_TARGET_PASSWORD = os.environ.get("KVSTORE_TARGET_PASSWORD")

TEST_SPLUNK_APP = os.environ.get("KVSTORE_SPLUNK_APP", "TA-Illumio")
TEST_TARGET_PROXY = os.environ.get("KV_STORE_REPLICATION_PROXY")


class _EventWriterStub:
    # This stub preserves the copyCollection call shape without requiring a running modular-input context.
    def log(self, *_args, **_kwargs):
        return None


def _remote_uri(scheme, host, port):
    return f"{scheme}://{host}:{port}"


def _login(remote_uri, username, password, proxy=None):
    login_url = f"{remote_uri}/services/auth/login"
    response_data, response_status = request(
        "POST",
        login_url,
        {"username": username, "password": password},
        {"Content-Type": "application/x-www-form-urlencoded"},
        proxy=proxy,
    )
    assert response_status == 200, response_data
    session_key = ET.fromstring(response_data).findtext("./sessionKey")
    assert session_key
    return session_key


def _create_collection(remote_uri, session_key, collection_name, proxy=None):
    collection_url = (
        f"{remote_uri}/servicesNS/nobody/{TEST_SPLUNK_APP}"
        "/storage/collections/config?output_mode=json"
    )
    response_data, response_status = request(
        "POST",
        collection_url,
        {"name": collection_name},
        {
            "Authorization": f"Splunk {session_key}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        proxy=proxy,
    )
    assert response_status in (200, 201), response_data


def _insert_documents(remote_uri, session_key, collection_name, documents, proxy=None):
    data_url = (
        f"{remote_uri}/servicesNS/nobody/{TEST_SPLUNK_APP}"
        f"/storage/collections/data/{collection_name}/batch_save?output_mode=json"
    )
    response_data, response_status = request(
        "POST",
        data_url,
        json.dumps(documents),
        {
            "Authorization": f"Splunk {session_key}",
            "Content-Type": "application/json",
        },
        proxy=proxy,
    )
    assert response_status == 200, response_data


def _read_collection(remote_uri, session_key, collection_name, proxy=None):
    data_url = (
        f"{remote_uri}/servicesNS/nobody/{TEST_SPLUNK_APP}"
        f"/storage/collections/data/{collection_name}?output_mode=json"
    )
    response_data, response_status = request(
        "GET",
        data_url,
        "",
        {
            "Authorization": f"Splunk {session_key}",
            "Content-Type": "application/json",
        },
        proxy=proxy,
    )
    assert response_status == 200, response_data
    return json.loads(response_data)


@pytest.mark.skipif(
    not TEST_SOURCE_HOST
    or not TEST_SOURCE_USERNAME
    or not TEST_SOURCE_PASSWORD
    or not TEST_TARGET_HOST
    or not TEST_TARGET_USERNAME
    or not TEST_TARGET_PASSWORD,
    reason="Set source and target Splunk connection environment variables to run copyCollection integration tests.",
)
def test_copy_collection_replicates_documents_from_source_to_target():
    # This test creates a source collection with sample data, copies it through the real copyCollection path,
    # verifies the target data, and leaves both collections in place for manual inspection.
    source_uri = _remote_uri(TEST_SOURCE_SCHEME, TEST_SOURCE_HOST, TEST_SOURCE_PORT)
    target_uri = _remote_uri(TEST_TARGET_SCHEME, TEST_TARGET_HOST, TEST_TARGET_PORT)
    source_session_key = _login(source_uri, TEST_SOURCE_USERNAME, TEST_SOURCE_PASSWORD)
    target_session_key = _login(
        target_uri, TEST_TARGET_USERNAME, TEST_TARGET_PASSWORD, proxy=TEST_TARGET_PROXY
    )
    collection_name = f"ta_proxy_copy_{uuid.uuid4().hex[:8]}"
    sample_document = [{"name": "proxy-copy-document", "source": "copy-integration-test"}]

    _create_collection(source_uri, source_session_key, collection_name)
    _insert_documents(source_uri, source_session_key, collection_name, sample_document)
    _create_collection(target_uri, target_session_key, collection_name, proxy=TEST_TARGET_PROXY)

    stats = copyCollection(
        _EventWriterStub(),
        source_session_key,
        source_uri,
        target_session_key,
        target_uri,
        TEST_SPLUNK_APP,
        collection_name,
        TEST_TARGET_PROXY,
    )

    assert stats["result"] == "success", stats
    assert stats["download_count"] == 1, stats
    assert stats["upload_count"] == 1, stats

    target_collection_contents = _read_collection(
        target_uri, target_session_key, collection_name, proxy=TEST_TARGET_PROXY
    )
    assert len(target_collection_contents) == 1
    assert target_collection_contents[0]["name"] == "proxy-copy-document"
    assert target_collection_contents[0]["source"] == "copy-integration-test"


@pytest.mark.skipif(
    not TEST_TARGET_HOST
    or not TEST_TARGET_USERNAME
    or not TEST_TARGET_PASSWORD
    or not TEST_TARGET_PROXY,
    reason="Set target Splunk connection and KV_STORE_REPLICATION_PROXY to run proxy login integration tests.",
)
def test_login_through_proxy_returns_valid_session_key():
    # This test verifies the exact code path that was broken for the customer:
    # HF -> Proxy -> Splunk Cloud SHC login on port 8089.
    target_uri = _remote_uri(TEST_TARGET_SCHEME, TEST_TARGET_HOST, TEST_TARGET_PORT)

    # Login through proxy - this is the critical path the customer reported as broken.
    session_key = _login(
        target_uri, TEST_TARGET_USERNAME, TEST_TARGET_PASSWORD, proxy=TEST_TARGET_PROXY
    )

    assert session_key is not None
    assert len(session_key) > 0


@pytest.mark.skipif(
    not TEST_TARGET_HOST
    or not TEST_TARGET_USERNAME
    or not TEST_TARGET_PASSWORD
    or not TEST_TARGET_PROXY,
    reason="Set target Splunk connection and KV_STORE_REPLICATION_PROXY to run deleteCollection proxy tests.",
)
def test_delete_collection_uses_proxy_for_target():
    # This test verifies deleteCollection properly routes through proxy.
    target_uri = _remote_uri(TEST_TARGET_SCHEME, TEST_TARGET_HOST, TEST_TARGET_PORT)
    target_session_key = _login(
        target_uri, TEST_TARGET_USERNAME, TEST_TARGET_PASSWORD, proxy=TEST_TARGET_PROXY
    )
    collection_name = f"ta_proxy_delete_{uuid.uuid4().hex[:8]}"

    # Create and populate a test collection through proxy.
    _create_collection(target_uri, target_session_key, collection_name, proxy=TEST_TARGET_PROXY)
    _insert_documents(
        target_uri,
        target_session_key,
        collection_name,
        [{"name": "to-be-deleted"}],
        proxy=TEST_TARGET_PROXY,
    )

    # Verify data exists before delete.
    contents_before = _read_collection(
        target_uri, target_session_key, collection_name, proxy=TEST_TARGET_PROXY
    )
    assert len(contents_before) == 1

    # Delete collection contents through proxy.
    response_code = deleteCollection(
        _EventWriterStub(),
        target_uri,
        target_session_key,
        TEST_SPLUNK_APP,
        collection_name,
        proxy=TEST_TARGET_PROXY,
    )

    assert response_code == 200

    # Verify collection is empty after delete.
    contents_after = _read_collection(
        target_uri, target_session_key, collection_name, proxy=TEST_TARGET_PROXY
    )
    assert len(contents_after) == 0


@pytest.mark.skipif(
    not TEST_TARGET_HOST or not TEST_TARGET_USERNAME or not TEST_TARGET_PASSWORD,
    reason="Set target Splunk connection to run direct login test.",
)
def test_login_without_proxy_works_for_direct_connection():
    # Baseline test: direct login without proxy should work when network allows.
    # This test runs without proxy to verify the login mechanism itself works.
    target_uri = _remote_uri(TEST_TARGET_SCHEME, TEST_TARGET_HOST, TEST_TARGET_PORT)

    session_key = _login(target_uri, TEST_TARGET_USERNAME, TEST_TARGET_PASSWORD, proxy=None)

    assert session_key is not None
    assert len(session_key) > 0
