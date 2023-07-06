# -*- coding: utf-8 -*-

"""This module provides the modular input for the Illumio TA.

The input accesses the Illumio API and retrieves data from the PCE.

Copyright:
    © 2023 Illumio
License:
    Apache2, see LICENSE for more details.
"""
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

from illumio import JsonObject, validate_int, PORT_MAX

import splunklib.client as client
from splunklib.binding import HTTPError
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
                required_on_create=False,
                required_on_edit=False,
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
                description="Port for Splunk to receive syslogs from the PCE. Not required syslogs are pulled from S3. Example value: 514",
                data_type=Argument.data_type_number,
                required_on_create=False,
                required_on_edit=False,
            )
        )

        scheme.add_argument(
            Argument(
                name="time_interval_port",
                title="Port Scan Interval",
                description="A port scan alert will be triggered if the scan threshold count is met during this interval (in seconds)",
                data_type=Argument.data_type_number,
                required_on_create=False,
                required_on_edit=False,
            )
        )

        scheme.add_argument(
            Argument(
                name="cnt_port_scan",
                title="Port Scan Threshold",
                description="Number of scanned ports that triggers a port scan alert",
                data_type=Argument.data_type_number,
                required_on_create=False,
                required_on_edit=False,
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
                description="Path for the custom root certificate, e.g. '$SPLUNK_HOME/etc/apps/TA-Illumio/bin/cert.pem'",
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

        return scheme

    def validate_input(self, definition: ValidationDefinition) -> None:
        """Validate arguments of the Illumio modular input.

        Args:
            definition: The validation definition containing input params.

        Raises:
            ValueError: If any input params are invalid.
        """
        params = IllumioInputParameters(name=definition.metadata["name"], **definition.parameters)

        # the Script service property isn't available during validation,
        # so initialize it using the session token in the input metadata
        self._service = client.connect(token=definition.metadata["session_key"])

        # the API secret is stored in storage/passwords on the front-end,
        # so we need to fetch it to validate the PCE connection
        params.api_secret = self._get_password(params.api_secret_name)

        # test the connection to the PCE
        connect_to_pce(params)

        if params.port_number:
            try:
                validate_int(params.port_number, maximum=PORT_MAX)
            except Exception:
                raise ValueError("Port Number must be an integer between 0 and 65535")

            port_available = self._syslog_port_available(params.port_number)

            if not port_available:
                raise ValueError(f"Port Number: {str(params.port_number)} TCP is already in use")

        if params.time_interval_port and params.time_interval_port < 0:
            raise ValueError("Port Scan Interval must be non negative integer")

        if params.cnt_port_scan and params.cnt_port_scan < 0:
            raise ValueError("Port Scan Threshold must be non negative integer")

        # TODO: test interval validation (it should already be validated by the UI)

        if params.allowed_ips:
            import ipaddress

            for ip in params.allowed_ips.split(","):
                ipaddress.ip_address(ip.strip())

        # TODO: reimplement quarantine label validation for MT4L
        # quarantine_labels = definition.parameters["quarantine_labels"]

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
                    self._create_syslog_input(params)
                # TODO: do we still need the port scan details event?

                # retrieve the API secret from storage/passwords
                params.api_secret = self._get_password(params.api_secret_name)

                pce = connect_to_pce(params)

                # get PCE health so we can determine if the PCE is part of a
                # Supercluster. we need to do this each time rather than
                # storing the cluster members as members may change over time,
                # the leader may change, or members may be unavailable
                resp = pce.get("/health", include_org=False)
                resp.raise_for_status()

                supercluster = Supercluster.from_status(resp.json())

                def _store_pce_objects(api, illumio_type: str) -> Event:
                    pce_objects = []

                    if illumio_type == "illumio_workloads" and supercluster:
                        # pass a deepcopy of the PCE client so we can update the
                        # hostname to call each cluster member without affecting
                        # other threads
                        pce_objects = get_supercluster_workloads(supercluster, params)

                    # if we can't connect to the Supercluster members, fall
                    # back on getting all workloads from the configured PCE
                    if not pce_objects:
                        pce_objects = api.get_async()

                    pce_fqdn = pce._hostname
                    self._update_kvstore(illumio_type, pce_fqdn, pce_objects)

                    metadata = {
                        "illumio_type": illumio_type,
                        # TODO: online/offline workloads count?
                        "total_objects": len(pce_objects),
                    }

                    ew.log(EventWriter.INFO, f"Retrieved {len(pce_objects)} {illumio_type}")
                    return Event(
                        data=json.dumps(metadata),
                        host=pce_fqdn,
                        source="Illumio PCE",
                        index=params.index,
                        sourcetype=params.sourcetype,
                    )

                with ThreadPoolExecutor() as exec:
                    tasks = (
                        (_store_pce_objects, pce.labels, "illumio_labels"),
                        (_store_pce_objects, pce.ip_lists, "illumio_ip_lists"),
                        (_store_pce_objects, pce.services, "illumio_services"),
                        (_store_pce_objects, pce.workloads, "illumio_workloads"),
                    )
                    futures = (exec.submit(*task) for task in tasks)
                    for future in as_completed(futures):
                        ew.write_event(future.result())
            except Exception as e:
                ew.log(EventWriter.ERROR, f"Error while running Illumio PCE input: {e}")

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

    def _update_kvstore(self, kvstore_name: str, pce_fqdn: str, pce_objs: List[JsonObject]):
        """Updates a specified KVStore with the given PCE objects.

        Any existing KVStore data is removed and replaced to avoid stale state.

        Args:
            pce_fqdn (str): the PCE FQDN to append to each object's fields.
            pce_objs (List[JsonObject]): list of PCE objects.
            kvstore_name (str): the name of the KVStore to update.

        Raises:
            Exception: if the specified KVStore doesn't exist.
        """
        kvstores = self.service.kvstore
        if kvstore_name not in kvstores:
            # XXX: should we create the kvstore if it doesn't exist?
            raise Exception(f"Failed to find KV store for type: {kvstore_name}")
        kvstore = kvstores[kvstore_name]

        # delete all existing objects in the KV store before
        # repopulating to avoid stale entries that have been
        # removed from the PCE
        kvstore.data.delete()

        for pce_obj in pce_objs:
            o = pce_obj.to_json()
            o["pce_fqdn"] = pce_fqdn
            o["_key"] = pce_obj.href
            kvstore.data.insert(o)

    def _create_syslog_input(self, params: IllumioInputParameters) -> None:
        """Creates a /tcp/raw input for the given port.

        Args:
            params (IllumioInputParameters): modinput configuration params.

        Raises:
            HTTPError: if an unexpected HTTP error code is returned.
            Exception: if the port is unavailable or another error occurs while
                trying to create the input.
        """
        if not self._syslog_port_available(params.port_number):
            raise Exception(f"Syslog port {params.port_number} is unavailable.")

        try:
            self.service.inputs.create(
                str(params.port_number),
                "tcp",
                index=params.index,
                # XXX: should this be the configured sourcetype instead?
                sourcetype="illumio:pce",
            )
        except HTTPError as e:
            if e.status == 409:
                return  # XXX: test this to make sure it works as expected
            raise e
        except Exception as e:
            raise Exception(f"Unable to create syslog input for port {params.port_number}: {e}")

    def _syslog_port_available(self, port_number: int) -> bool:
        """Checks if a TCP input has been created for the given syslog port.

        Returns:
            bool: True if the port is available or claimed by an illumio:pce
                input, otherwise False.

        Raises:
            HTTPError: if a non-404 response is returned from Splunk.
            Exception: if the response from Splunk can't be parsed.
        """
        try:
            resp = self.service.inputs.get(f"tcp/raw/{port_number}", output_mode="json")

            with resp.body as response_body:
                entries = json.loads(response_body.read())["entry"]
                return entries[0]["content"]["sourcetype"] == "illumio:pce"
        except HTTPError as e:
            if e.status == 404:
                return True
            raise e
        except Exception as e:
            raise Exception(f"Unable to determine if syslog port is available: {e}")


if __name__ == "__main__":
    sys.exit(Illumio().run(sys.argv))
