"""This module provides kvstore support for the TA.

Copyright:
    © 2024 Illumio
License:
    Apache2, see LICENSE for more details.
"""

from future import standard_library

standard_library.install_aliases()
import sys
import urllib.error
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

# Add lib folders to import path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

from illumio.kvstore_mgmt.kvstore_helpers import request
from illumio.kvstore_mgmt.kvstore_operations import (
    getCollections,
    copyCollection,
)

from illumio_constants import ILLUMIO_TA
from illumio_splunk_utils import get_credentials_for_search_heads

from splunklib.modularinput import EventWriter


class KVStoreUpload:
    """
    ##Description

    Upload each collection in the KV Store to a remote Splunk Search Head/SHC instance

    """

    def __init__(self, service, ew, proxy=None, input_name=None) -> None:
        self.app = ILLUMIO_TA
        self.collection = None
        self.target = None  # either a list of SH nodes or a single SH node
        self.targetport = 8089
        self.ew = ew
        self.local_server_uri = f"{service.scheme}://{service.host}:{service.port}"
        self.service = service
        # Store the optional proxy so it can be passed to the KV-store upload request path.
        self.proxy = proxy
        # Keep the current input name so only this stanza's search head credentials are used.
        self.input_name = input_name

    def _login_remote(self, remote_uri, remote_user, remote_password):
        login_url = f"{remote_uri}/services/auth/login"
        response_data, response_status = request(
            "POST",
            login_url,
            {"username": remote_user, "password": remote_password},
            {"Content-Type": "application/x-www-form-urlencoded"},
            proxy=self.proxy,
        )
        if response_status != 200:
            raise Exception(f"unexpected response status {response_status} from {login_url}")

        session_key = ET.fromstring(response_data).findtext("./sessionKey")
        if not session_key:
            raise Exception(f"missing sessionKey in login response from {login_url}")
        return session_key

    def upload_collections(self):
        credentials = get_credentials_for_search_heads(self.service, self.input_name)
        input_name = (self.input_name or "").replace("illumio://", "")

        if not credentials:
            self.ew.log(
                EventWriter.INFO,
                f"KV-store replication skipped for input '{input_name}': no remote search head credentials found.",
            )
            return

        local_collection_list = getCollections(
            self.local_server_uri, self.service.token, self.app, self.ew
        )
        self.ew.log(EventWriter.INFO, f"Collections to push: {str(local_collection_list)}")
        self.ew.log(
            EventWriter.INFO,
            f"KV-store replication targets for input '{input_name}': {', '.join(sorted(credentials))}",
        )

        for host, cred in credentials.items():
            try:
                remote_user = cred["username"]
                remote_password = cred["password"]
                remote_port = cred.get("port") or self.targetport

            except KeyError as k:
                self.ew.log(
                    EventWriter.ERROR,
                    f"Skipping KV-store replication target '{host}' for input '{input_name}': malformed credential entry ({k}).",
                )
                continue

            try:
                remote_host = host
                remote_uri = "https://{}:{}".format(remote_host, remote_port)
                self.ew.log(
                    EventWriter.INFO,
                    f"Attempting KV-store replication login for input '{input_name}' to search head '{remote_host}:{remote_port}' as user '{remote_user}'.",
                )

                remote_session_key = self._login_remote(
                    remote_uri,
                    remote_user,
                    remote_password,
                )
                self.ew.log(
                    EventWriter.INFO,
                    f"Established KV-store replication session for input '{input_name}' to search head '{remote_host}:{remote_port}'.",
                )

            except (urllib.error.HTTPError, Exception) as e:
                self.ew.log(
                    EventWriter.ERROR,
                    f"Skipping KV-store replication for input '{input_name}' to search head '{remote_host}:{remote_port}': login failed ({e}).",
                )
                continue

            completion = 0
            expected = len(local_collection_list)
            for local_collection in local_collection_list:
                # Extract the app and collection name from the array
                collection_app = local_collection[0]
                collection_name = local_collection[1]
                self.ew.log(
                    EventWriter.INFO,
                    f"Replicating KV-store collection '{collection_app}/{collection_name}' for input '{input_name}' to search head '{remote_host}:{remote_port}'.",
                )

                copyCollection(
                    self.ew,
                    self.service.token,
                    self.local_server_uri,
                    remote_session_key,
                    remote_uri,
                    collection_app,
                    collection_name,
                    self.proxy,
                )
                completion += 1
                self.ew.log(
                    EventWriter.INFO,
                    f"Completed KV-store replication of collection '{collection_app}/{collection_name}' for input '{input_name}' to search head '{remote_host}:{remote_port}' ({completion}/{expected} collections replicated).",
                )
            
            


__all__ = ["KVStoreUpload"]
