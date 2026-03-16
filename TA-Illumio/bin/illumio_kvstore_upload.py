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
from pathlib import Path

# Add lib folders to import path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

from illumio.kvstore_mgmt.kvstore_operations import (
    getCollections,
    copyCollection,
)

import splunklib.client as client

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

    def upload_collections(self):
        credentials = get_credentials_for_search_heads(self.service, self.input_name)

        for host, cred in credentials.items():
            try:
                remote_user = cred["username"]
                remote_password = cred["password"]

            except KeyError as k:
                self.ew.log(EventWriter.ERROR, f"Credential is incorrectly processed {k}")

            try:
                remote_host = host
                remote_port = self.targetport
                remote_uri = "https://{}:{}".format(remote_host, remote_port)

                remote_service = client.connect(
                    host=remote_host,
                    port=remote_port,
                    username=remote_user,
                    password=remote_password,
                )
                remote_service.login()

                remote_session_key = remote_service.token.replace("Splunk ", "")

            except (urllib.error.HTTPError, BaseException) as e:
                self.ew.log(EventWriter.ERROR, f"Failed to login: {e}")

            local_collection_list = getCollections(
                self.local_server_uri, self.service.token, self.app, self.ew
            )
            self.ew.log(EventWriter.INFO, f"Collections to push: {str(local_collection_list)}")

            for local_collection in local_collection_list:
                # Extract the app and collection name from the array
                collection_app = local_collection[0]
                collection_name = local_collection[1]

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


__all__ = ["KVStoreUpload"]
