# -*- coding: utf-8 -*-

"""This module provides the modular input for the Illumio TA.

The input accesses the Illumio API and retrieves data from the PCE.

Copyright:
    © 2023 Illumio
License:
    Apache2, see LICENSE for more details.
"""
import sys
import traceback
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

from illumio import validate_int, PORT_MAX, ACTIVE

import splunklib.client as client
from splunklib.modularinput import (
    Script,
    Scheme,
    Argument,
    EventWriter,
    Event,
    InputDefinition,
    ValidationDefinition,
)

from illumio_pce_utils import *

SYSLOG_SOURCETYPE = "illumio:pce"


class Illumio(Script):
    """Illumio Modular Input."""

    def get_scheme(self) -> Scheme:
        """Writes the scheme for the modular input.

        Returns:
            Scheme: the scheme for the modular input.
        """
        scheme = Scheme("Illumio")
        scheme.description = "Retrieves Illumio PCE objects and syslog data as Splunk events."

        scheme.add_argument(
            Argument(
                name="pce_url",
                title="PCE URL",
                description="Full URL of the PCE (or Supercluster leader) to connect to, including port. Example value: https://my.pce.com:8443",
                data_type=Argument.data_type_string,
                required_on_create=True,
                required_on_edit=True,
            )
        )

        scheme.add_argument(
            Argument(
                name="org_id",
                title="Organization ID",
                description="PCE Organization ID",
                data_type=Argument.data_type_number,
                required_on_create=True,
                required_on_edit=True,
            )
        )

        scheme.add_argument(
            Argument(
                name="api_key_id",
                title="API Authentication Username",
                description="Illumio API key username. Example value: 'api_145a5c788e63c30a3'",
                data_type=Argument.data_type_string,
                required_on_create=True,
                required_on_edit=True,
            )
        )

        scheme.add_argument(
            Argument(
                name="port_number",
                title="Port Number for syslogs (TCP)",
                description="Port for Splunk to receive traffic flows and events from the PCE. Not required if these events are being pulled from S3",
                data_type=Argument.data_type_number,
                required_on_create=False,
                required_on_edit=False,
            )
        )

        scheme.add_argument(
            Argument(
                name="port_scan_interval",
                title="Port Scan Interval",
                description="A port scan alert will be triggered if the scan threshold count is met during this interval (in seconds)",
                data_type=Argument.data_type_number,
                required_on_create=True,
                required_on_edit=True,
            )
        )

        scheme.add_argument(
            Argument(
                name="port_scan_threshold",
                title="Port Scan Threshold",
                description="Number of scanned ports that triggers a port scan alert",
                data_type=Argument.data_type_number,
                required_on_create=True,
                required_on_edit=True,
            )
        )

        scheme.add_argument(
            Argument(
                name="allowed_ips",
                title="Allowed Port Scan IPs",
                description="Comma-separated list of device IPs to be ignored by port scan alerts",
                data_type=Argument.data_type_string,
                required_on_create=False,
                required_on_edit=False,
            )
        )

        scheme.add_argument(
            Argument(
                name="quarantine_labels",
                title="Quarantine Label Dimensions",
                description="Comma-separated list of label names to define workload quarantine",
                data_type=Argument.data_type_string,
                required_on_create=False,
                required_on_edit=False,
            )
        )

        scheme.add_argument(
            Argument(
                name="self_signed_cert_path",
                title="Self-Signed Certificate Path",
                description="Path for the custom root certificate. Example value: '$SPLUNK_HOME/etc/apps/TA-Illumio/bin/cert.pem'",
                data_type=Argument.data_type_string,
                required_on_create=False,
                required_on_edit=False,
            )
        )

        scheme.add_argument(
            Argument(
                name="http_proxy",
                title="HTTP Proxy",
                description="Optional HTTP proxy address",
                data_type=Argument.data_type_string,
                required_on_create=False,
                required_on_edit=False,
            )
        )

        scheme.add_argument(
            Argument(
                name="https_proxy",
                title="HTTPS Proxy",
                description="Optional HTTPS proxy address",
                data_type=Argument.data_type_string,
                required_on_create=False,
                required_on_edit=False,
            )
        )

        scheme.add_argument(
            Argument(
                name="http_retry_count",
                title="HTTP Retry Count",
                description="Number of times to retry HTTP requests to the PCE",
                data_type=Argument.data_type_number,
                required_on_create=False,
                required_on_edit=False,
            )
        )

        scheme.add_argument(
            Argument(
                name="http_request_timeout",
                title="HTTP Request Timeout",
                description="Total HTTP request timeout (in seconds)",
                data_type=Argument.data_type_number,
                required_on_create=False,
                required_on_edit=False,
            )
        )

        return scheme

    def validate_input(self, definition: ValidationDefinition) -> None:
        """Validate arguments of the Illumio modular input.

        Args:
            definition: The validation definition containing input params.

        Raises:
            ValueError: If any input params are invalid.
        """
        for arg in self.get_scheme().arguments:
            if arg.name == "port_number":
                continue  # validated separately below
            if arg.data_type == Argument.data_type_number:
                try:
                    param = definition.parameters.get(arg.name)
                    if param is not None and str(param) != "":
                        validate_int(definition.parameters[arg.name], minimum=1)
                except Exception:
                    raise ValueError(f"{arg.title} must be a non-negative integer")

        # the Script service property isn't available during validation,
        # so initialize it using the session token in the input metadata
        self._service = client.connect(token=definition.metadata["session_key"])

        port_number = definition.parameters.get("port_number")
        if port_number is not None and str(port_number) != "":
            try:
                validate_int(port_number, minimum=1, maximum=PORT_MAX)
            except Exception:
                raise ValueError("Port Number must be an integer between 1 and 65535")

            tcp_input = self._get_tcp_input(port_number)

            if tcp_input and tcp_input.sourcetype != SYSLOG_SOURCETYPE:
                raise ValueError(f"Port Number: {str(port_number)} TCP is already in use")

        params = IllumioInputParameters(name=definition.metadata["name"], **definition.parameters)
        # lower the timeout and retry count for validation; Splunk will
        # time out the input after 30 seconds either way
        params.http_request_timeout = 5
        params.http_retry_count = 1

        # the API secret is stored in storage/passwords on the front-end,
        # so we need to fetch it to validate the PCE connection
        params.api_secret = self._get_password(params.api_secret_name)

        # test the connection to the PCE
        connect_to_pce(params)

        if params.allowed_ips:
            import ipaddress

            for ip in params.allowed_ips.split(","):
                ipaddress.ip_address(ip.strip())

        if params.quarantine_labels:
            parse_label_scope(params.quarantine_labels)

    def stream_events(self, inputs: InputDefinition, ew: EventWriter):
        """Modular input entry point.

        Streams objects retrieved from the PCE as events to Splunk.

        Args:
            inputs (any): script inputs and metadata.
            ew (EventWriter): Event writer object.
        """
        for input_name, input_item in inputs.inputs.items():
            # we can't pass the __app field to the dataclass as private member
            # variables are not allowed, so pop it out of the dict here
            app_name = input_item.pop("__app")
            params = IllumioInputParameters(name=input_name, **input_item)

            try:
                ew.log(EventWriter.INFO, f"Running input {app_name}/{params.stanza}")

                if params.port_number and params.port_number > 0:
                    # create the /tcp/raw input for the configured port if it doesn't exist
                    if self._get_tcp_input(params.port_number) is None:
                        self.service.inputs.create(
                            str(params.port_number),
                            "tcp",
                            connection_host="dns",
                            index=params.index,
                            sourcetype=SYSLOG_SOURCETYPE,
                        )

                # retrieve the API secret from storage/passwords
                params.api_secret = self._get_password(params.api_secret_name)

                pce = connect_to_pce(params)
                pce_fqdn = pce._hostname

                def _pce_event(data: dict, format: str = "metadata") -> Event:
                    return Event(
                        data=json.dumps(data),
                        host=pce_fqdn,
                        index=params.index,
                        source=params.source,
                        # XXX: there's probably a better way to handle the sourcetypes
                        sourcetype=f"illumio:pce:{format}",
                    )

                # write an event containing port scan details
                ew.log(EventWriter.INFO, f"Writing port scan settings to KVStore")
                self._update_kvstore("port_scan_settings", pce_fqdn, [params.port_scan_details()])

                # get PCE status and store each cluster in the response as a separate event
                resp = pce.get("/health", include_org=False)
                resp.raise_for_status()

                pce_status = resp.json()

                for cluster in pce_status:
                    ew.write_event(_pce_event(cluster, "health"))
                ew.log(EventWriter.INFO, f"Retrieved {pce_fqdn} PCE cluster status")

                def _store_pce_objects(api, illumio_type: str) -> Event:
                    if illumio_type == "workloads" and is_supercluster(pce_status):
                        # the PCE object isn't thread-safe, so create a second instance
                        # here as we will need to reassign the internal _hostname value
                        # to pull workloads from each Supercluster member
                        supercluster = Supercluster(connect_to_pce(params), pce_status)
                        pce_objects = supercluster.get_workloads()
                    else:
                        # fetch active versions of policy objects; the param is ignored
                        # for labels and workloads
                        endpoint = api._build_endpoint(ACTIVE, None)
                        response = api.pce.get_collection(endpoint, include_org=False)
                        pce_objects = response.json()

                    self._update_kvstore(illumio_type, pce_fqdn, pce_objects)
                    obj_count = len(pce_objects)

                    metadata = {
                        "pce_fqdn": pce_fqdn,
                        "illumio_type": f"illumio:pce:{illumio_type}",
                        # TODO: online/offline workloads count?
                        "total_objects": obj_count,
                    }

                    ew.log(EventWriter.INFO, f"Retrieved {obj_count} {illumio_type}")
                    return _pce_event(metadata)

                with ThreadPoolExecutor() as exec:
                    # XXX: should we be getting the active versions of
                    # services/IP lists here?
                    tasks = (
                        (_store_pce_objects, pce.labels, "labels"),
                        (_store_pce_objects, pce.ip_lists, "ip_lists"),
                        (_store_pce_objects, pce.services, "services"),
                        (_store_pce_objects, pce.workloads, "workloads"),
                        (_store_pce_objects, pce.rule_sets, "rule_sets"),
                    )
                    futures = (exec.submit(*task) for task in tasks)
                    for future in as_completed(futures):
                        ew.write_event(future.result())
            except Exception as e:
                ew.log(EventWriter.ERROR, f"Error while running Illumio PCE input: {e}")
                ew.log(EventWriter.ERROR, f"Traceback: {traceback.format_exc()}")

    def _get_password(self, name: str) -> str:
        """Retrieves a password from the Splunk storage/passwords endpoint.

        Args:
            name (str): the full stanza name of the password to retrieve.

        Returns:
            str: the plaintext password.
        """
        try:
            storage_passwords = self.service.storage_passwords
            resp = storage_passwords.get(name, output_mode="json")

            with resp.body as response_body:
                entries = json.loads(response_body.read())["entry"]
                return entries[0]["content"]["clear_password"]
        except Exception as e:
            raise Exception(f"Failed to retrieve password {name} from storage/passwords: {e}")

    def _update_kvstore(self, obj_type: str, pce_fqdn: str, pce_objs: List[dict]):
        """Updates a specified KVStore with the given PCE objects.

        Any existing KVStore data is removed and replaced to avoid stale state.

        Args:
            pce_fqdn (str): the PCE FQDN to append to each object's fields.
            pce_objs (List[dict]): list of PCE objects.
            obj_type (str): the type of object being stored.

        Raises:
            Exception: if the specified KVStore doesn't exist.
        """
        kvstore_name = f"illumio_{obj_type}"
        kvstores = self.service.kvstore
        if kvstore_name not in kvstores:
            # XXX: should we create the kvstore if it doesn't exist?
            raise Exception(f"Failed to find KV store for type: {kvstore_name}")
        kvstore = kvstores[kvstore_name]

        # delete all objects belonging to the given PCE in the KV store before
        # updating to avoid retaining objects that were removed from the PCE.
        # KVStores use mongodb under the hood, so the query is a stringified
        # mongo eq expression; URL encoding is handled by the Splunk client
        kvstore.data.delete(query=f'{{"pce_fqdn": "{pce_fqdn}"}}')

        for pce_obj in pce_objs:
            o = pce_obj
            o["pce_fqdn"] = pce_fqdn
            # prepend the PCE FQDN to ensure uniqueness across multiple PCEs
            o["_key"] = pce_fqdn + (":" + o["href"]) if "href" in o else ""
            # add convenience field indicating managed/unmanaged
            if "/workloads/" in o["_key"]:
                o["managed"] = o["ven"] is not None
            kvstore.data.insert(o)

    def _get_tcp_input(self, port_number: int) -> Any:
        """Retrieves a TCP input for the given syslog port from Splunk.

        Returns:
            Any: the Input object, or None if the input is not defined.
        """
        try:
            return self.service.inputs[(str(port_number), "tcp")]
        except Exception:
            raise None


if __name__ == "__main__":
    sys.exit(Illumio().run(sys.argv))
