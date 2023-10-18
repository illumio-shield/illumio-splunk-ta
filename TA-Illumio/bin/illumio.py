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
from datetime import datetime
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

from illumio import PolicyComputeEngine, validate_int, PORT_MAX, ACTIVE

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

from illumio_constants import *
from illumio_pce_utils import *
from illumio_splunk_utils import *


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
                title="Syslog Port (TCP)",
                description="Port for Splunk to receive traffic flows and events from the PCE. Not required if these events are being pulled from S3",
                data_type=Argument.data_type_number,
                required_on_create=False,
                required_on_edit=False,
            )
        )

        scheme.add_argument(
            Argument(
                name="enable_tcp_ssl",
                title="Enable TCP-SSL",
                description="Receive encrypted syslog events from the PCE. Requires [SSL] stanza to be configured in inputs.conf",
                data_type=Argument.data_type_boolean,
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
                name="ca_cert_path",
                title="CA Certificate Path",
                description="Optional path to a custom CA certificate bundle. Example value: '$SPLUNK_HOME/etc/apps/TA-Illumio/certs/ca.pem'",
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

        scheme.add_argument(
            Argument(
                name="quarantine_labels",
                title="Quarantine Labels",
                description="Labels to apply to workloads to put them into a quarantine zone. Must be of the form key1:value1,...,keyN:valueN",
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

            tcp_input = get_tcp_input(self.service, port_number)

            if tcp_input and tcp_input.sourcetype != SYSLOG_SOURCETYPE:
                raise ValueError(f"Port Number: {str(port_number)} TCP is already in use")

        quarantine_labels = definition.parameters.get("quarantine_labels")
        if quarantine_labels:
            try:
                parse_label_scope(quarantine_labels)
            except ValueError as e:
                raise ValueError(f"Quarantine Labels: {e}")

        params = IllumioInputParameters(name=definition.metadata["name"], **definition.parameters)
        # lower the timeout and retry count for validation; Splunk will
        # time out the input after 30 seconds either way
        params.http_request_timeout = 5
        params.http_retry_count = 1

        # the API secret is stored in storage/passwords on the front-end,
        # so we need to fetch it to validate the PCE connection
        params.api_secret = get_password(self.service, params.api_secret_name)

        # test the connection to the PCE
        connect_to_pce(params)

        if params.allowed_ips:
            import ipaddress

            for ip in params.allowed_ips:
                try:
                    if ip:
                        ipaddress.ip_address(ip)
                except ValueError as e:
                    raise ValueError(f"Allowed IPs: {e}")

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
                # set app context for the Splunk REST client
                self.service.namespace.app = app_name
                ew.log(EventWriter.INFO, f"Running input {app_name}/{params.stanza}")

                if params.port_number and params.port_number > 0:
                    # create the /tcp/raw input for the configured port if it doesn't exist
                    if get_tcp_input(self.service, params.port_number) is None:
                        create_tcp_input(self.service, app_name, params)

                # retrieve the API secret from storage/passwords
                params.api_secret = get_password(self.service, params.api_secret_name)

                pce = connect_to_pce(params)

                # write an event containing port scan details
                ew.log(EventWriter.INFO, "Writing port scan settings to KVStore")
                self._store_port_scan_settings(params)

                # get PCE status and store each cluster in the response as a separate event
                resp = pce.get("/health", include_org=False)
                resp.raise_for_status()

                pce_status = resp.json()

                for cluster in pce_status:
                    ew.write_event(self._pce_event(params, HEALTH_SOURCETYPE, **cluster))
                ew.log(EventWriter.INFO, f"Retrieved {params.pce_fqdn} PCE cluster status")

                # the PCE object isn't thread-safe, so create a second instance
                # here as we will need to reassign the internal _hostname value
                # to pull workloads from each Supercluster member
                supercluster = Supercluster(connect_to_pce(params), pce_status)

                with ThreadPoolExecutor() as exec:
                    tasks = (
                        (self._store_labels, pce, params),
                        (self._store_ip_lists, pce, params),
                        (self._store_services, pce, params),
                        (self._store_workloads, supercluster, params),
                        (self._store_rule_sets, pce, params),
                    )
                    futures = (exec.submit(*task) for task in tasks)
                    for future in as_completed(futures):
                        ew.write_event(future.result())
            except Exception as e:
                ew.log(EventWriter.ERROR, f"Error while running Illumio PCE input: {e}")
                ew.log(EventWriter.ERROR, f"Traceback: {traceback.format_exc()}")

    def _pce_event(self, params: IllumioInputParameters, sourcetype: str, **kwargs) -> Event:
        """Wraps the given metadata in an Event object.

        Args:
            params (IllumioInputParameters): input parameter data object.
            sourcetype (str, optional): event sourcetype.

        Returns:
            Event: the constructed Event object.
        """
        return Event(
            data=json.dumps(kwargs),
            host=params.pce_fqdn,
            index=params.index,
            source=params.source,
            sourcetype=sourcetype,
        )

    def _metadata_event(self, params: IllumioInputParameters, type_: str, object_count: int) -> Event:
        """Constructs a PCE metadata Event object.

        Args:
            params (IllumioInputParameters): input parameter data object.
            type_ (str): Illumio object type.
            object_count (int): total count of objects stored.

        Returns:
            Event: the constructed Event object.
        """
        return self._pce_event(
            params=params,
            sourcetype=SYSLOG_SOURCETYPE,
            pce_fqdn=params.pce_fqdn,
            org_id=params.org_id,
            illumio_type=type_,
            total_objects=object_count,
            timestamp=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        )

    def _store_port_scan_settings(self, params: IllumioInputParameters) -> None:
        """Stores port scan settings for the input in a KVStore.

        Args:
            params (IllumioInputParameters): input parameter data object.
        """
        port_scan_settings = params.port_scan_details()
        port_scan_settings["pce_fqdn"] = params.pce_fqdn
        # cast org_id to a string here - KVStore lookups can't use wildcards for number fields
        port_scan_settings["org_id"] = str(params.org_id)
        port_scan_settings["_key"] = f"{params.pce_fqdn}:{params.org_id}"
        update_kvstore(self.service, KVSTORE_PORT_SCAN, [port_scan_settings])

    def _store_labels(self, pce: PolicyComputeEngine, params: IllumioInputParameters) -> Event:
        """Fetches labels from the PCE and stores them in a KVStore.

        Args:
            pce (PolicyComputeEngine): the PCE API client.
            params (IllumioInputParameters): input parameter data object.

        Returns:
            Event: metadata Event to record the action in Splunk.
        """
        endpoint = pce.labels._build_endpoint(ACTIVE, None)
        response = pce.get_collection(endpoint, include_org=False)
        labels = response.json()

        for label in labels:
            flatten_refs(label, "created_by", "updated_by")

        update_set = self._kvstore_union(KVSTORE_LABELS, params, labels)
        update_kvstore(self.service, KVSTORE_LABELS, update_set)

        return self._metadata_event(params, ILO_TYPE_LABELS, len(labels))

    def _store_ip_lists(self, pce: PolicyComputeEngine, params: IllumioInputParameters) -> Event:
        """Fetches IP lists from the PCE and stores them in a KVStore.

        To avoid issues with nested structures, each IP range in the IP list
        definition is flattened into its own KVStore entry.

        Args:
            pce (PolicyComputeEngine): the PCE API client.
            params (IllumioInputParameters): input parameter data object.

        Returns:
            Event: metadata Event to record the action in Splunk.
        """
        endpoint = pce.ip_lists._build_endpoint(ACTIVE, None)
        response = pce.get_collection(endpoint, include_org=False)
        ip_lists = response.json()
        flattened_ip_lists = []

        for ip_list in ip_lists:
            flatten_refs(ip_list, "created_by", "updated_by")

            # convert IP list into multiple entries, one for each IP range
            flattened_ip_lists += flatten_ip_list(ip_list, params.pce_fqdn)

        update_set = self._kvstore_union(KVSTORE_IP_LISTS, params, flattened_ip_lists)
        update_kvstore(self.service, KVSTORE_IP_LISTS, update_set)

        return self._metadata_event(params, ILO_TYPE_IP_LISTS, len(ip_lists))

    def _store_services(self, pce: PolicyComputeEngine, params: IllumioInputParameters) -> Event:
        """Fetches services from the PCE and stores them in a KVStore.

        To avoid issues with nested structures, each service_port,
        windows_service, and windows_egress_service entry in the service
        definition is flattened into its own KVStore entry.

        Args:
            pce (PolicyComputeEngine): the PCE API client.
            params (IllumioInputParameters): input parameter data object.

        Returns:
            Event: metadata Event to record the action in Splunk.
        """
        endpoint = pce.services._build_endpoint(ACTIVE, None)
        response = pce.get_collection(endpoint, include_org=False)
        services = response.json()
        flattened_services = []

        for service in services:
            flatten_refs(service, "created_by", "updated_by")

            # convert service into multiple entries, one for each service definition
            flattened_services += flatten_service(service, params.pce_fqdn)

        update_set = self._kvstore_union(KVSTORE_SERVICES, params, flattened_services)
        update_kvstore(self.service, KVSTORE_SERVICES, update_set)

        return self._metadata_event(params, ILO_TYPE_SERVICES, len(services))

    def _store_workloads(self, sc: Supercluster, params: IllumioInputParameters) -> Event:
        """Fetches workloads from the PCE and stores them in a KVStore.

        Workload interfaces are pulled from the workload response and stored in
        a separate collection, `illumio_workload_interfaces`.

        Args:
            sc (Supercluster): wrapped PCE API client. Some workload
                metadata is not replicated on Superclusters, so we fetch from
                all clusters individually.
            params (IllumioInputParameters): input parameter data object.

        Returns:
            Event: metadata Event to record the action in Splunk.
        """
        # Supercluster is really just a wrapper around the PCE client
        # this call will work for SNC/MNC/SaaS architectures as well
        workloads = sc.get_workloads()

        interfaces = []

        for workload in workloads:
            # we discard the cluster name here, but can always add a lookup for
            # container clusters later
            flatten_refs(workload, "created_by", "updated_by", "container_cluster")

            # add convenience field indicating managed/unmanaged
            workload["managed"] = workload.get("ven") is not None

            # flatten labels array to simplify MV field name
            workload["labels"] = [label["href"] for label in workload.get("labels", [])]

            # workload interfaces are stored in a separate collection, so pop
            # them from the workload record and assign a unique key of the form
            # < pce_fqdn:workload_href:interface_name:interface_address >
            workload_href = workload["href"]
            for intf in workload.pop("interfaces", []):
                flatten_refs(intf, "network")
                key = f"{params.pce_fqdn}:{workload_href}:{intf['name']}:{intf['address']}"
                interfaces.append({**intf, "workload_href": workload_href, "_key": key})

        update_set = self._kvstore_union(KVSTORE_WORKLOADS, params, workloads)
        update_kvstore(self.service, KVSTORE_WORKLOADS, update_set)

        update_set = self._kvstore_union(KVSTORE_WORKLOAD_INTERFACES, params, interfaces)
        update_kvstore(self.service, KVSTORE_WORKLOAD_INTERFACES, update_set)

        return self._metadata_event(params, ILO_TYPE_WORKLOADS, len(workloads))

    def _store_rule_sets(self, pce: PolicyComputeEngine, params: IllumioInputParameters) -> Event:
        """Fetches rule sets from the PCE and stores them in a KVStore.

        All rules removed from the rule set response and stored in a separate
        collection with a reference back to the parent rule set.

        Args:
            pce (PolicyComputeEngine): the PCE API client.
            params (IllumioInputParameters): input parameter data object.

        Returns:
            Event: metadata Event to record the action in Splunk.
        """
        endpoint = pce.rule_sets._build_endpoint(ACTIVE, None)
        response = pce.get_collection(endpoint, include_org=False)
        rule_sets = response.json()
        rules = []

        for rule_set in rule_sets:
            flatten_refs(rule_set, "created_by", "updated_by")

            scopes = {}
            for i, scope in enumerate(rule_set.get("scopes", [])):
                scopes[i] = flatten_scope(scope)
            rule_set["scopes"] = scopes

            rules += flatten_rules(rule_set)

        update_set = self._kvstore_union(KVSTORE_RULE_SETS, params, rule_sets)
        update_kvstore(self.service, KVSTORE_RULE_SETS, update_set)

        update_set = self._kvstore_union(KVSTORE_RULES, params, rules)
        update_kvstore(self.service, KVSTORE_RULES, update_set)

        return self._metadata_event(params, ILO_TYPE_RULE_SETS, len(rule_sets))

    def _kvstore_union(self, name: str, params: IllumioInputParameters, new: List[dict]) -> List[dict]:
        """Unifies old KVStore records with the updated list from the PCE.

        Marks any objects in the KVStore that are no longer on the PCE as
        deleted to maintain a record of the object in Splunk.

        Args:
            name (str): the name of the KVStore to use.
            params (IllumioInputParameters): input parameter data object.
            new (List[dict]): list of objects from the PCE.

        Returns:
            List[dict]: the unified list of objects.
        """
        kvstores = self.service.kvstore
        kvstore = kvstores[name]
        old = kvstore.data.query(query={"pce_fqdn": params.pce_fqdn, "org_id": params.org_id})

        # cast org_id to a string here - KVStore lookups can't use wildcards for number fields
        fields = {"pce_fqdn": params.pce_fqdn, "org_id": str(params.org_id), "deleted": False}

        # build an index of all objects in the KVStore and mark them as deleted
        idx = {o["_key"]: {**o, "deleted": True} for o in old}

        for o in new:
            # prepend the PCE FQDN to the key to ensure uniqueness across multiple PCEs
            key = o.get("_key", f"{params.pce_fqdn}:{o.get('href', '')}")
            idx[key] = {**o, **fields, "_key": key}

        return list(idx.values())


if __name__ == "__main__":
    sys.exit(Illumio().run(sys.argv))
