import json
import os
import sys
import tempfile
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
from illumio.kvstore_mgmt.kvstore_operations import getCollectionNamesToReplicate
from illumio.kvstore_mgmt.kvstore_operations import uploadCollection
from illumio_constants import KVSTORE_REPLICATION_COLLECTION_LIST


# This integration test is opt-in because it writes to a real Splunk KV-store collection.
TEST_SPLUNK_HOST = os.environ.get("KVSTORE_SPLUNK_HOST")
TEST_SPLUNK_PORT = os.environ.get("KVSTORE_SPLUNK_PORT", "8089")
TEST_SPLUNK_SCHEME = os.environ.get("KVSTORE_SPLUNK_SCHEME", "https")
TEST_SPLUNK_USERNAME = os.environ.get("KVSTORE_SPLUNK_USERNAME")
TEST_SPLUNK_PASSWORD = os.environ.get("KVSTORE_SPLUNK_PASSWORD")
TEST_SPLUNK_APP = os.environ.get("KVSTORE_SPLUNK_APP", "TA-Illumio")
TEST_SPLUNK_PROXY = os.environ.get("KV_STORE_REPLICATION_PROXY")


class _EventWriterStub:
    # This stub preserves the uploadCollection call shape without requiring a running modular-input context.
    def log(self, *_args, **_kwargs):
        return None


def _remote_uri():
    # Allow the integration test to run against either HTTP or HTTPS Splunk management endpoints.
    return f"{TEST_SPLUNK_SCHEME}://{TEST_SPLUNK_HOST}:{TEST_SPLUNK_PORT}"


def _login():
    login_url = f"{_remote_uri()}/services/auth/login"
    response_data, response_status = request(
        "POST",
        login_url,
        {"username": TEST_SPLUNK_USERNAME, "password": TEST_SPLUNK_PASSWORD},
        {"Content-Type": "application/x-www-form-urlencoded"},
        proxy=TEST_SPLUNK_PROXY,
    )
    assert response_status == 200
    session_key = ET.fromstring(response_data).findtext("./sessionKey")
    assert session_key
    return session_key


def _create_collection(session_key, collection_name):
    collection_url = (
        f"{_remote_uri()}/servicesNS/nobody/{TEST_SPLUNK_APP}"
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
        proxy=TEST_SPLUNK_PROXY,
    )
    assert response_status in (200, 201), response_data


def _delete_collection(session_key, collection_name):
    delete_url = (
        f"{_remote_uri()}/servicesNS/nobody/{TEST_SPLUNK_APP}"
        f"/storage/collections/config/{collection_name}?output_mode=json"
    )
    request(
        "DELETE",
        delete_url,
        "",
        {
            "Authorization": f"Splunk {session_key}",
            "Content-Type": "application/json",
        },
        proxy=TEST_SPLUNK_PROXY,
    )


def _delete_collection_data(session_key, collection_name):
    delete_url = (
        f"{_remote_uri()}/servicesNS/nobody/{TEST_SPLUNK_APP}"
        f"/storage/collections/data/{collection_name}/?output_mode=json"
    )
    request(
        "DELETE",
        delete_url,
        "",
        {
            "Authorization": f"Splunk {session_key}",
            "Content-Type": "application/json",
        },
        proxy=TEST_SPLUNK_PROXY,
    )


def _read_collection(session_key, collection_name):
    data_url = (
        f"{_remote_uri()}/servicesNS/nobody/{TEST_SPLUNK_APP}"
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
        proxy=TEST_SPLUNK_PROXY,
    )
    assert response_status == 200, response_data
    return json.loads(response_data)


@pytest.mark.skipif(
    not TEST_SPLUNK_HOST or not TEST_SPLUNK_USERNAME or not TEST_SPLUNK_PASSWORD,
    reason="Set KVSTORE_SPLUNK_HOST, KVSTORE_SPLUNK_USERNAME and KVSTORE_SPLUNK_PASSWORD to run KV-store upload integration tests.",
)
def test_upload_collection_writes_documents_to_real_splunk_kvstore():
    # This test creates a temporary collection, uploads one document through uploadCollection,
    # verifies the document was written, and then removes the temporary collection.
    session_key = _login()
    collection_name = f"ta_proxy_upload_{uuid.uuid4().hex[:8]}"
    sample_document = [{"name": "proxy-test-document", "source": "integration-test"}]
    temp_file_path = None

    try:
        _create_collection(session_key, collection_name)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_file:
            temp_file.write(json.dumps(sample_document))
            temp_file_path = temp_file.name

        result, message, posted = uploadCollection(
            _EventWriterStub(),
            _remote_uri(),
            session_key,
            TEST_SPLUNK_APP,
            collection_name,
            temp_file_path,
            TEST_SPLUNK_PROXY,
        )

        assert result == "success", message
        assert posted == 1

        collection_contents = _read_collection(session_key, collection_name)
        assert len(collection_contents) == 1
        assert collection_contents[0]["name"] == "proxy-test-document"
        assert collection_contents[0]["source"] == "integration-test"
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        # Keep the temporary collection on the SH after the test so the uploaded data can be inspected manually.


@pytest.mark.skipif(
    not TEST_SPLUNK_HOST or not TEST_SPLUNK_USERNAME or not TEST_SPLUNK_PASSWORD,
    reason="Set KVSTORE_SPLUNK_HOST, KVSTORE_SPLUNK_USERNAME and KVSTORE_SPLUNK_PASSWORD to run KV-store upload integration tests.",
)
def test_get_collections_only_returns_replication_collection_list_members():
    session_key = _login()
    allowlisted_collection = KVSTORE_REPLICATION_COLLECTION_LIST[0]
    extra_collection = f"ta_proxy_upload_{uuid.uuid4().hex[:8]}"

    try:
        _create_collection(session_key, extra_collection)
        _delete_collection_data(session_key, allowlisted_collection)

        collections = getCollectionNamesToReplicate(_remote_uri(), session_key, TEST_SPLUNK_APP)
        collection_names = {collection_name for app_name, collection_name in collections if app_name == TEST_SPLUNK_APP}

        assert allowlisted_collection in collection_names
        assert extra_collection not in collection_names
    finally:
        _delete_collection_data(session_key, allowlisted_collection)
        _delete_collection(session_key, extra_collection)
