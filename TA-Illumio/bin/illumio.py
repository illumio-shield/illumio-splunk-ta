# -*- coding: utf-8 -*-

"""This module provides the modular input for the Illumio TA.

The input accesses the Illumio API and retrieves data from the PCE.

Copyright:
    © 2023 Illumio
License:
    Apache2, see LICENSE for more details.
"""
import os
import sys
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, fields
from urllib.error import HTTPError
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from illumio import PolicyComputeEngine

import splunklib.client as client
from splunklib.modularinput import Script, Scheme, Argument, EventWriter, Event


@dataclass
class IllumioInputParameters:
    """Dataclass to hold Illumio input parameters."""

    name: str = ""
    pce_url: str = ""
    pce_port: int = 443
    api_key_id: str = ""
    api_secret: str = ""
    org_id: int = 1
    port_number: int = -1
    time_interval_port: int = 60
    cnt_port_scan: int = 10
    allowed_ips: str = ""
    self_signed_cert_path: str = ""
    http_proxy: str = ""
    https_proxy: str = ""
    enable_data_collection: bool = True
    quarantine_labels: str = ""
    # extra setting fields
    host: str = ""
    interval: str = "3600"
    index: str = "default"
    _api_secret_name: str = ""
    _realm: str = ""

    def __post_init__(self):
        # handle type conversion for all fields, ignoring nulls
        for field in fields(self):
            value = getattr(self, field.name)
            if value is not None and not isinstance(value, field.type):
                setattr(self, field.name, field.type(value))

        parsed = urlparse(self.pce_url)
        if parsed.port:
            self.pce_port = parsed.port

        if self.org_id <= 0:
            raise ValueError("Invalid Organization ID: must be non-negative integer.")

    @property
    def api_secret_name(self) -> str:
        return f"{self.realm}:{self.api_key_id}"

    @property
    def realm(self) -> str:
        return f"illumio://{self.name}".replace(":", r"\:")


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
                description="PCE Organization ID. Defaults to 1",
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

        scheme.add_argument(
            Argument(
                name="enable_data_collection",
                title="Enable Data Collection",
                description="Enable data collection for this input",
                data_type=Argument.data_type_boolean,
                required_on_create=False,
                required_on_edit=False,
            )
        )

        return scheme

    def validate_input(self, definition) -> None:
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
        self._connect_to_pce(params)

        if params.port_number:
            port_check_regex = r"^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$"
            if not bool(re.search(port_check_regex, params.port_number)):
                raise ValueError("Port Number: Invalid port number. Must be between 0 and 65535.")

            port_available = self._syslog_port_available(params.port_number)

            if not port_available:
                raise ValueError(f"Port Number: {str(params.port_number)} TCP is already in use.")

        if params.time_interval_port and params.time_interval_port < 0:
            raise ValueError("Time interval for port scan: must be non negative integer.")

        if params.cnt_port_scan and params.cnt_port_scan < 0:
            raise ValueError("Count for port scan: must be non negative integer.")

        # TODO: test interval validation (it should already be validated by the UI)

        if params.allowed_ips:
            import ipaddress

            for ip in params.allowed_ips.split(","):
                ipaddress.ip_address(ip.strip())

        # TODO: reimplement quarantine label validation for MT4L
        # quarantine_labels = definition.parameters["quarantine_labels"]

    def stream_events(self, inputs, ew: EventWriter):
        """Modular input entry point.

        Streams objects retrieved from the PCE as events to Splunk.

        Args:
            inputs (any): script inputs and metadata.
            ew (EventWriter): Event writer object.
        """
        for input_name, input_item in inputs.inputs.items():
            # To ensure data collection is enabled only if chosen.
            if input_item["enable_data_collection"]:
                try:
                    ew.log("INFO", f"Starting data collection for {input_name}")
                    params = IllumioInputParameters(name=input_name, **input_item)

                    # retrieve the API secret from storage/passwords
                    params.api_secret = self._get_password(params.api_secret_name)

                    pce = self._connect_to_pce(params)

                    # TODO: supercluster handling - get supercluster members
                    # and states from each core server
                    # supercluster_info = get_pce_health(arg)

                    # Check PCE health
                    resp = pce.get("/health", include_org=False)
                    # FIXME:

                    # TODO: supercluster handling - get supercluster members
                    # if len(supercluster_info[2]) > 0:
                    #     last_index = arg[0].rindex(":")
                    #     port_number = str(arg[0][last_index:])
                    #     for index in range(len(supercluster_info[2])):
                    #         supercluster_info[2][index] = "https://" + supercluster_info[2][index] + port_number
                    #     supercluster_members = ",".join(supercluster_info[2])
                    #     writeconf("TA-Illumio", arg[5], "supercluster_members", supercluster_info[1],
                    #             {"supercluster_members": supercluster_members})

                    # if supercluster_info[0]:
                    #     try:
                    #         conf_value = cli.getConfStanza("supercluster_members", supercluster_info[1])
                    #         supercluster_info[2] = conf_value.get("supercluster_members", "")
                    #     except Exception:
                    #         logger.error("Illumio Error: {} stanza not found in supercluster_members.conf file.".format(
                    #             supercluster_info[1]))

                    # del arg[5]
                    # arg.extend(supercluster_info)

                    def _retrieve_objects(api, illumio_type: str):
                        objs = []
                        for pce_obj in api.get_async():
                            o = pce_obj.to_json()
                            o["illumio_type"] = illumio_type
                            objs.append(o)
                        ew.log("INFO", f"Retrieved {len(objs)} {illumio_type} objects")
                        return objs

                    with ThreadPoolExecutor() as exec:
                        tasks = (
                            (_retrieve_objects, pce.labels, "illumio:pce:label"),
                            (_retrieve_objects, pce.ip_lists, "illumio:pce:ip_lists"),
                            (_retrieve_objects, pce.services, "illumio:pce:services"),
                        )
                        futures = (exec.submit(*task) for task in tasks)
                        for future in as_completed(futures):
                            for o in future.result():
                                # TODO: ew.log() for debugging
                                ew.write_event(
                                    Event(
                                        data=o,
                                        host=pce._hostname,
                                        source="Illumio PCE",
                                        index=params.index,
                                        # sourcetype="",
                                    )
                                )
                except Exception as e:
                    ew.log("ERROR", f"Error while running Illumio PCE input: {str(e)}")

    def _get_password(self, name: str) -> str:
        """Retrieves a password from the Splunk storage/passwords endpoint.

        Returns:
            str: the plaintext password.
        """
        try:
            storage_passwords = self.service.storage_passwords
            resp = storage_passwords.get(name, output_mode="json")

            if resp.status != 200:
                raise Exception(f"HTTP error {resp.status}")

            with resp.body as response_body:
                entries = json.loads(response_body.read())["entry"]
                return entries[0]["content"]["clear_password"]
        except Exception as e:
            raise Exception(f"Failed to retrieve password {name} from storage/passwords: {str(e)}")

    def _connect_to_pce(self, params: IllumioInputParameters) -> PolicyComputeEngine:
        """Attempts to connect to the PCE.

        Args:
            params (IllumioInputParameters): script input parameters.

        Raises:
            Exception: if the connection could not be established.

        Returns:
            PolicyComputeEngine: the PCE client object.
        """
        try:
            # TODO: support configurable retry params
            pce = PolicyComputeEngine(params.pce_url, port=params.pce_port, org_id=params.org_id)
            pce.set_credentials(params.api_key_id, params.api_secret)
            pce.set_tls_settings(verify=params.self_signed_cert_path or True)
            pce.set_proxies(http_proxy=params.http_proxy, https_proxy=params.https_proxy)

            pce.must_connect()

            return pce
        except Exception as e:
            raise Exception(f"Failed to connect to PCE: {str(e)}")

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
            resp = self.service.inputs.get(f"tcp/raw/{str(port_number)}", output_mode="json")

            with resp.body as response_body:
                entries = json.loads(response_body.read())["entry"]
                return entries[0]["content"]["sourcetype"] == "illumio:pce"
        except HTTPError as e:
            if e.code == 404:
                return True
            raise e
        except Exception as e:
            raise Exception(f"Unable to determine if syslog port is available: {str(e)}")


if __name__ == "__main__":
    sys.exit(Illumio().run(sys.argv))
