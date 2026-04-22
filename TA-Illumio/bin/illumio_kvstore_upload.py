"""This module provides kvstore support for the TA.

Copyright:
    © 2024 Illumio
License:
    Apache2, see LICENSE for more details.
"""

from future import standard_library

standard_library.install_aliases()
import base64
import json
import sys
import time
import urllib.error
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

# Add lib folders to import path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

from illumio.kvstore_mgmt.kvstore_helpers import request
from illumio.kvstore_mgmt.kvstore_operations import (
    getCollectionNamesToReplicate,
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
            self.ew.log(
                EventWriter.INFO,
                f"[KV Replication] Login failed with status {response_status} from {login_url} ({'via proxy' if self.proxy else 'direct'}). Response body: {response_data}",
            )
            raise Exception(f"unexpected response status {response_status} from {login_url}")

        session_key = ET.fromstring(response_data).findtext("./sessionKey")
        if not session_key:
            self.ew.log(
                EventWriter.ERROR,
                f"[KV Replication] Missing sessionKey in login response from {login_url}. Response body: {response_data}",
            )
            raise Exception(f"missing sessionKey in login response from {login_url}")
        return session_key

    def _decode_jwt_payload(self, token):
        """Decode JWT payload to extract expiry and other info. Returns None if decoding fails."""
        try:
            # JWT format: header.payload.signature
            parts = token.split(".")
            if len(parts) != 3:
                return None
            # Decode payload (second part), add padding if needed
            payload_b64 = parts[1]
            # Add padding to make it valid base64
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            payload_json = base64.urlsafe_b64decode(payload_b64)
            return json.loads(payload_json)
        except Exception:
            return None

    def _validate_and_log_token(self, token):
        """Validate token and log its details. Returns True if token appears valid."""
        payload = self._decode_jwt_payload(token)
        if not payload:
            self.ew.log(
                EventWriter.INFO,
                "[KV Replication] Could not decode auth token - will attempt to use it anyway.",
            )
            return True  # Still try to use it

        # Log token details
        subject = payload.get("sub", "unknown")
        audience = payload.get("aud", "unknown")
        token_type = payload.get("ttyp", "unknown")
        exp_timestamp = payload.get("exp")

        self.ew.log(
            EventWriter.INFO,
            f"[KV Replication] Token info: subject={subject}, audience={audience}, type={token_type}",
        )

        # Check expiry
        if exp_timestamp:
            current_time = int(time.time())
            if current_time >= exp_timestamp:
                self.ew.log(
                    EventWriter.ERROR,
                    f"[KV Replication] Auth token has EXPIRED (exp={exp_timestamp}, now={current_time}). Token-based auth will fail.",
                )
                return False
            else:
                remaining_seconds = exp_timestamp - current_time
                remaining_days = remaining_seconds // 86400
                self.ew.log(
                    EventWriter.INFO,
                    f"[KV Replication] Token expiry: {remaining_days} days remaining (exp={exp_timestamp}).",
                )
        return True

    def _get_session_info(self, remote_uri, session_key, is_bearer_token=False):
        """Query session info from Splunk to log session details."""
        # Use Bearer auth for tokens, Splunk auth for session keys
        auth_header = f"Bearer {session_key}" if is_bearer_token else f"Splunk {session_key}"
        auth_type = "Bearer" if is_bearer_token else "Splunk"
        self.ew.log(
            EventWriter.INFO,
            f"[KV Replication] Using {auth_type} auth header for session info queries",
        )
        try:
            # Query current user's session info
            info_url = f"{remote_uri}/services/authentication/current-context?output_mode=json"
            response_data, response_status = request(
                "GET",
                info_url,
                "",
                {
                    "Authorization": auth_header,
                    "Content-Type": "application/json",
                },
                proxy=self.proxy,
            )
            if response_status == 200:
                info = json.loads(response_data)
                entry = info.get("entry", [{}])[0].get("content", {})
                username = entry.get("username", "unknown")
                realname = entry.get("realname", "unknown")
                roles = entry.get("roles", [])
                capabilities = entry.get("capabilities", [])
                # Log KV store related capabilities specifically
                kvstore_caps = [c for c in capabilities if "kvstore" in c.lower() or c in ("admin_all_objects", "list_storage_passwords")]
                self.ew.log(
                    EventWriter.INFO,
                    f"[KV Replication] Session info: username={username}, realname={realname}, roles={roles}",
                )
                self.ew.log(
                    EventWriter.INFO,
                    f"[KV Replication] KV-store related capabilities: {kvstore_caps if kvstore_caps else 'none found (may lack capability to view)'}",
                )
            else:
                self.ew.log(
                    EventWriter.INFO,
                    f"[KV Replication] Could not fetch session info: status={response_status} (this may be normal if user lacks admin capabilities). Response: {response_data[:500] if response_data else 'empty'}",
                )

            # Also try to get httpauth-tokens info for more details
            tokens_url = f"{remote_uri}/services/authentication/httpauth-tokens?output_mode=json"
            response_data, response_status = request(
                "GET",
                tokens_url,
                "",
                {
                    "Authorization": auth_header,
                    "Content-Type": "application/json",
                },
                proxy=self.proxy,
            )
            if response_status == 200:
                tokens_info = json.loads(response_data)
                entries = tokens_info.get("entry", [])
                self.ew.log(
                    EventWriter.INFO,
                    f"[KV Replication] Active tokens count: {len(entries)}",
                )
                for entry in entries[:3]:  # Log first 3 tokens at most
                    content = entry.get("content", {})
                    time_accessed = content.get("timeAccessed", "unknown")
                    self.ew.log(
                        EventWriter.INFO,
                        f"[KV Replication] Token info: timeAccessed={time_accessed}, userName={content.get('userName', 'unknown')}",
                    )
        except Exception as e:
            self.ew.log(
                EventWriter.INFO,
                f"[KV Replication] Failed to get session info: {e}",
            )

    def upload_collections(self):
        credentials = get_credentials_for_search_heads(self.service, self.input_name)
        input_name = (self.input_name or "").replace("illumio://", "")

        if not credentials:
            self.ew.log(
                EventWriter.INFO,
                f"[KV Replication] KV-store replication skipped for input '{input_name}': no remote search head credentials found.",
            )
            return

        local_collection_list = getCollectionNamesToReplicate(
            self.local_server_uri, self.service.token, self.app, self.ew
        )
        self.ew.log(EventWriter.INFO, f"[KV Replication] Collections to push: {str(local_collection_list)}")
        self.ew.log(
            EventWriter.INFO,
            f"[KV Replication] KV-store replication targets for input '{input_name}': {', '.join(sorted(credentials))}",
        )

        # Process each SH
        for target, cred in credentials.items():
            remote_port = cred.get("port") or self.targetport
            remote_host = cred.get("host")
            if not remote_host:
                self.ew.log(
                    EventWriter.ERROR,
                    f"[KV Replication] Skipping KV-store replication target '{target}' for input '{input_name}': missing host in credential entry.",
                )
                continue
            remote_uri = "https://{}:{}".format(remote_host, remote_port)
            is_token = cred.get("is_token", False)

            if is_token:
                # Token-based auth: use password field as Bearer token, skip login
                remote_session_key = cred["password"]
                is_bearer_token = True
                self.ew.log(
                    EventWriter.INFO,
                    f"[KV Replication] Using token-based auth for input '{input_name}' to search head '{remote_host}:{remote_port}' ({'via proxy' if self.proxy else 'direct'}).",
                )
                # Validate and log token details
                if not self._validate_and_log_token(remote_session_key):
                    self.ew.log(
                        EventWriter.ERROR,
                        f"[KV Replication] Token validation failed for input '{input_name}' to '{remote_host}:{remote_port}'. Skipping this target.",
                    )
                    continue
                self._get_session_info(remote_uri, remote_session_key, is_bearer_token=True)
            else:
                # Standard username/password login
                is_bearer_token = False
                try:
                    remote_user = cred["username"]
                    remote_password = cred["password"]
                except KeyError as k:
                    self.ew.log(
                        EventWriter.ERROR,
                        f"[KV Replication] Skipping KV-store replication target '{target}' for input '{input_name}': malformed credential entry ({k}).",
                    )
                    continue

                try:
                    self.ew.log(
                        EventWriter.INFO,
                        f"[KV Replication] Attempting KV-store replication login for input '{input_name}' to search head '{remote_host}:{remote_port}' as user '{remote_user}' ({'via proxy' if self.proxy else 'direct'}).",
                    )

                    remote_session_key = self._login_remote(
                        remote_uri,
                        remote_user,
                        remote_password,
                    )
                    self.ew.log(
                        EventWriter.INFO,
                        f"[KV Replication] Established KV-store replication session for input '{input_name}' to search head '{remote_host}:{remote_port}' ({'via proxy' if self.proxy else 'direct'}).",
                    )
                    self._get_session_info(remote_uri, remote_session_key, is_bearer_token=False)

                except (urllib.error.HTTPError, Exception) as e:
                    self.ew.log(
                        EventWriter.ERROR,
                        f"[KV Replication] Skipping KV-store replication for input '{input_name}' to search head '{remote_host}:{remote_port}': login failed ({e}).",
                    )
                    continue

            # Auth probe: verify session is valid for KV-store operations before starting
            probe_url = f"{remote_uri}/servicesNS/nobody/{self.app}/storage/collections/config?output_mode=json&count=1"
            auth_header = f"Bearer {remote_session_key}" if is_bearer_token else f"Splunk {remote_session_key}"
            try:
                probe_response, probe_status = request(
                    "GET",
                    probe_url,
                    "",
                    {"Authorization": auth_header, "Content-Type": "application/json"},
                    proxy=self.proxy,
                )
                self.ew.log(
                    EventWriter.INFO,
                    f"[KV Replication] Auth probe (GET collections config): status={probe_status} ({'via proxy' if self.proxy else 'direct'})",
                )
                if probe_status != 200:
                    self.ew.log(
                        EventWriter.ERROR,
                        f"[KV Replication] Auth probe failed for input '{input_name}' to '{remote_host}:{remote_port}': status={probe_status}, response={probe_response[:500] if probe_response else 'empty'}. Session may be invalid or user lacks KV-store access.",
                    )
                    continue
            except Exception as e:
                self.ew.log(
                    EventWriter.ERROR,
                    f"[KV Replication] Auth probe failed for input '{input_name}' to '{remote_host}:{remote_port}': request error ({e}). Continuing to next search head.",
                )
                continue

            try:
                completion = 0
                expected = len(local_collection_list)
                for local_collection in local_collection_list:
                    # Extract the app and collection name from the array
                    collection_app = local_collection[0]
                    collection_name = local_collection[1]
                    self.ew.log(
                        EventWriter.INFO,
                        f"[KV Replication] Replicating KV-store collection '{collection_app}/{collection_name}' for input '{input_name}' to search head '{remote_host}:{remote_port}'.",
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
                        is_bearer_token,
                    )
                    completion += 1
                    self.ew.log(
                        EventWriter.INFO,
                        f"[KV Replication] Completed KV-store replication of collection '{collection_app}/{collection_name}' for input '{input_name}' to search head '{remote_host}:{remote_port}' ({completion}/{expected} collections replicated).",
                    )
            except Exception as e:
                self.ew.log(
                    EventWriter.ERROR,
                    f"[KV Replication] Replication failed for input '{input_name}' to search head '{remote_host}:{remote_port}' after {completion}/{expected} collections: {e}. Continuing to next search head.",
                )
                continue
            
            


__all__ = ["KVStoreUpload"]
