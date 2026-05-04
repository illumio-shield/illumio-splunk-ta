"""
Copyright:
    © 2024 Illumio
License:
    Apache2, see LICENSE for more details.
"""

import json
import sys
from pathlib import Path
from typing import Any, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

import splunklib.client as client

from illumio_constants import *
from illumio_pce_utils import *


def get_password(service: client.Service, name: str) -> str:
    """Retrieves a password from the Splunk storage/passwords endpoint.

    Args:
        service (client.Service): Splunk API client.
        name (str): the full stanza name of the password to retrieve.

    Returns:
        str: the plaintext password.
    """
    try:
        storage_passwords = service.storage_passwords
        resp = storage_passwords.get(name, output_mode="json")

        with resp.body as response_body:
            entries = json.loads(response_body.read())["entry"]
            return entries[0]["content"]["clear_password"]
    except Exception as e:
        raise Exception(f"Failed to retrieve password {name} from storage/passwords: {e}")


def get_credentials_for_search_heads(service: client.Service, input_name: str) -> dict:
    """_summary_

    Args:
        service (client.Service): _description_
        input_name (str): data input name used to scope the search head credential realm.

    Returns:
        dict: _description_
    """

    try:
        storage_passwords = service.storage_passwords
        credentials = {}
        # Scope the credential lookup to the current input so one stanza cannot pick up another stanza's
        # search head credentials from storage/passwords.
        credential_realm = f"{SEARCH_HEAD_CREDENTIALS_PREFIX}://{input_name.replace('illumio://', '')}"
        for entry in storage_passwords.list():
            # The reason SEARCH_HEAD_CREDENTIALS_PREFIX is used here, is kvstore is the prefix for storing search head credentials
            if entry["content"].get("realm") == credential_realm:
                user_fqdn = entry["content"]["username"]
                # Check for 'token:' prefix indicating auth token instead of password
                is_token = user_fqdn.startswith("token:")
                if is_token:
                    user_fqdn = user_fqdn[6:]  # Remove 'token:' prefix
                # Skip malformed search head credentials instead of failing the entire modular input run.
                if "@" not in user_fqdn:
                    continue
                user, fqdn = user_fqdn.split("@", 1)
                user = user.strip()
                fqdn = fqdn.strip().rstrip("/")
                if not user or not fqdn:
                    continue
                port = None
                if ":" in fqdn:
                    if fqdn.count(":") != 1:
                        continue
                    fqdn, port_text = fqdn.rsplit(":", 1)
                    if not fqdn or not port_text.isdigit():
                        continue
                    port = int(port_text)
                    if port < 1 or port > 65535:
                        continue
                effective_port = port or 8089
                target = f"{fqdn}:{effective_port}"
                credentials[target] = {
                    "host": fqdn,
                    "username": user,
                    "password": entry["content"]["clear_password"],
                    "port": port if port else None,
                    "is_token": is_token,
                }
        return credentials
    except Exception as e:
        raise Exception(f"Failed to retrieve from storage/passwords: {e}")


def update_kvstore(service: client.Service, name: str, objs: List[dict]) -> None:
    """Updates a specified KVStore with the given PCE objects.

    Any existing KVStore data is removed and replaced to avoid stale state.

    Args:
        service (client.Service): Splunk API client.
        name (str): the name of the KVStore to update.
        params (IllumioInputParameters): input parameter data object.
        objs (List[dict]): list of objects to save to the store.

    Raises:
        KeyError: if the specified KVStore doesn't exist.
    """
    if not objs:
        return  # no need to do anything if the collection is empty
    kvstores = service.kvstore
    kvstore = kvstores[name]

    # try to get the limits.conf/kvstore max batch size, falling back on
    # the Splunk default (1000 up until 9.1.0 when it was changed to 50000)
    try:
        kvstore_conf = service.confs["limits"]["kvstore"]
        batch_size = int(kvstore_conf["max_documents_per_batch_save"])
    except Exception:
        batch_size = KVSTORE_BATCH_DEFAULT

    while objs:
        kvstore.data.batch_save(*objs[:batch_size])
        objs = objs[batch_size:]


def get_tcp_input(service: client.Service, port_number: int) -> Any:
    """Retrieves a TCP input for the given syslog port from Splunk.

    Args:
        service (client.Service): Splunk API client.
        port_number (int): the port number configured for the TCP input.

    Returns:
        Any: the Input object, or None if the input is not defined.
    """
    try:
        return service.inputs[(str(port_number), "tcp")]
    except Exception:
        return None


def create_tcp_input(service: client.Service, app: str, params: IllumioInputParameters) -> None:
    """Creates a TCP input in the given app using the provided parameters.

    Args:
        service (client.Service): Splunk API client.
        app (str): the app to create the input in.
        params (IllumioInputParameters): input parameters.
    """
    stanza_type = "tcp-ssl" if params.enable_tcp_ssl else "tcp"

    # we can't use service.inputs here as it doesn't support tcp-ssl.
    # tcp inputs have an SSL property, but it's poorly documented and
    # not clear if it has the same effect
    service.post(
        client.PATH_CONF % "inputs",
        name=f"{stanza_type}://{params.port_number}",
        app=app,
        connection_host="dns",
        index=params.index,
        sourcetype=SYSLOG_SOURCETYPE,
        disabled=0,
    )


__all__ = [
    "get_password",
    "update_kvstore",
    "get_tcp_input",
    "create_tcp_input",
    "get_credentials_for_search_heads",
]
