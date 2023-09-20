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
from typing import List, Any
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

from illumio import PolicyComputeEngine, validate_int, href_from, PORT_MAX, ACTIVE

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
                    if self._get_tcp_input(params.port_number) is None:
                        self._create_tcp_input(app_name, params)

                # retrieve the API secret from storage/passwords
                params.api_secret = self._get_password(params.api_secret_name)

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

    def _pce_event(self, params: IllumioInputParameters, sourcetype: str = SYSLOG_SOURCETYPE, **kwargs) -> Event:
        """Wraps the given metadata in an Event object.

        Args:
            params (IllumioInputParameters): input parameter data object.
            sourcetype (str, optional): event sourcetype. Defaults to SYSLOG_SOURCETYPE.

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
        port_scan_settings["org_id"] = params.org_id
        port_scan_settings["_key"] = f"{params.pce_fqdn}:{params.org_id}"
        self._update_kvstore(KVSTORE_PORT_SCAN, [port_scan_settings])

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

        update_set = self._kvstore_union(KVSTORE_LABELS, params, labels)
        self._update_kvstore(KVSTORE_LABELS, update_set)

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
            flattened_ip_lists += self._flatten_ip_list(ip_list, params.pce_fqdn)

        update_set = self._kvstore_union(KVSTORE_IP_LISTS, params, flattened_ip_lists)
        self._update_kvstore(KVSTORE_IP_LISTS, update_set)

        return self._metadata_event(params, ILO_TYPE_IP_LISTS, len(ip_lists))

    def _flatten_ip_list(self, ip_list: dict, pce_fqdn: str) -> List[dict]:
        """Flattens a given IP list object into multiple entries.

        An entry is created for each IP range in the IP list object. Each entry
        has a unique key suffix of the form < from_ip:to_ip >.

        FQDNs are flattened into a list of strings and their descriptions are
        stripped from the resulting entries.

        Args:
            service (dict): PCE service object in JSON dict form.
            pce_fqdn (str): PCE FQDN to prefix the IP list entry keys.

        Returns:
            List[dict]: IP list entries flattened from the given object.
        """
        ip_list_entries = []

        # strip the FQDN descriptions and flatten them as an array of strings
        ip_list["fqdns"] = [fqdn["fqdn"] for fqdn in ip_list.pop("fqdns", [])]

        for ip_range in ip_list.pop("ip_ranges", []):
            key = f"{pce_fqdn}:{ip_list['href']}:{ip_range.get('from_ip')}:{ip_range.get('to_ip')}"
            # rename the IP range description field
            ip_range["ip_range_description"] = ip_range.get("description")
            ip_list_entries.append({**ip_list, **ip_range, "_key": key})

        return ip_list_entries

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
            flattened_services += self._flatten_service(service, params.pce_fqdn)

        update_set = self._kvstore_union(KVSTORE_SERVICES, params, flattened_services)
        self._update_kvstore(KVSTORE_SERVICES, update_set)

        return self._metadata_event(params, ILO_TYPE_SERVICES, len(services))

    def _flatten_service(self, service: dict, pce_fqdn: str) -> List[dict]:
        """Flattens a given service object into multiple entries.

        An entry is created for each service definition in the Service object.
        Each entry has a unique key suffix based on its metadata, of the form
        < port:to_port:icmp_type:icmp_code:proto:service_name:process_name >
        with any null or empty fields removed.

        Args:
            service (dict): PCE service object in JSON dict form.
            pce_fqdn (str): PCE FQDN to prefix the service entry keys.

        Returns:
            List[dict]: service entries flattened from the given object.
        """
        service_entries = []

        service_ports = service.pop("service_ports", [])
        windows_services = service.pop("windows_services", [])
        windows_egress_services = service.pop("windows_egress_services", [])

        for entry in service_ports + windows_services + windows_egress_services:
            # convert protocol numbers to their string equivalent
            if "proto" in entry:
                entry["proto"] = getprotobynum(entry["proto"])
            # construct a unique suffix for each service entry, made up of port
            # and proto (Linux service) and service/proc name (Windows service)
            # this lets us track each entry if it's removed from the service or
            # if the service itself is removed
            entry_key = ":".join([
                quote(str(k), safe="") for k in (
                    entry.get("port"),
                    entry.get("to_port"),
                    entry.get("icmp_type"),
                    entry.get("icmp_code"),
                    entry.get("proto"),
                    entry.get("service_name"),
                    entry.get("process_name"),
                ) if k
            ])
            key = f"{pce_fqdn}:{service['href']}:{entry_key}"
            # rename the top-level process_name field to avoid overwriting it
            service["spn"] = service.get("process_name")
            service_entries.append({**service, **entry, "_key": key})

        return service_entries

    def _store_workloads(self, supercluster: Supercluster, params: IllumioInputParameters) -> Event:
        """Fetches workloads from the PCE and stores them in a KVStore.

        Workload interfaces are pulled from the workload response and stored in
        a separate collection, `illumio_workload_interfaces`.

        Args:
            supercluster (Supercluster): wrapped PCE API client. Some workload
                metadata is not replicated on Superclusters, so we fetch from
                all clusters individually.
            params (IllumioInputParameters): input parameter data object.

        Returns:
            Event: metadata Event to record the action in Splunk.
        """
        # Supercluster is really just a wrapper around the PCE client
        # this call will work for SNC/MNC/SaaS architectures as well
        workloads = supercluster.get_workloads()

        interfaces = []

        for workload in workloads:
            # add convenience field indicating managed/unmanaged
            workload["managed"] = workload.get("ven") is not None

            # flatten labels array to simplify MV field name
            workload["labels"] = [label["href"] for label in workload.get("labels", [])]

            # workload interfaces are stored in a separate collection, so pop
            # them from the workload record and assign a unique key of the form
            # < pce_fqdn:workload_href:interface_name:interface_address >
            workload_href = workload["href"]
            for interface in workload.pop("interfaces", []):
                key = f"{params.pce_fqdn}:{workload_href}:{interface['name']}:{interface['address']}"
                interfaces.append({**interface, "workload_href": workload_href, "_key": key})

        update_set = self._kvstore_union(KVSTORE_WORKLOADS, params, workloads)
        self._update_kvstore(KVSTORE_WORKLOADS, update_set)

        update_set = self._kvstore_union(KVSTORE_WORKLOAD_INTERFACES, params, interfaces)
        self._update_kvstore(KVSTORE_WORKLOAD_INTERFACES, update_set)

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
            scopes = {}
            for i, scope in enumerate(rule_set.get("scopes", [])):
                scopes[i] = self._flatten_scope(scope)
            rules += self._flatten_rules(rule_set)

        update_set = self._kvstore_union(KVSTORE_RULE_SETS, params, rule_sets)
        self._update_kvstore(KVSTORE_RULE_SETS, update_set)

        update_set = self._kvstore_union(KVSTORE_RULES, params, rules)
        self._update_kvstore(KVSTORE_RULES, update_set)

        return self._metadata_event(params, ILO_TYPE_RULE_SETS, len(rule_sets))

    def _flatten_scope(self, scope: List[dict]) -> dict:
        """Given a rule set or rule scope, flattens it into a dictionary.

        Rule set scopes are lists of lists defining one or more sets of label
        dimensions the rule set is bounded by. In newer versions of the PCE,
        each dimension also includes an exclusion parameter:

        scopes = [
          [
            {
              "label": {
                "href": "/orgs/1/labels/9"
              },
              "exclusion": false
            },
            {
              "label_group": {
                "href": "/orgs/1/label_groups/13"
              },
              "exclusion": false
            }
          ],
          ...
        ]

        To avoid the relationships being lost when converted to multivalue
        fields, the structure is flattened as an enumerated dict:

        scopes: {"0": {"exclusions": ["a", "b"], "inclusions": ["c", "d"]}}
        scopes.0.exclusions = [a, b], scopes.0.inclusions = [c, d]

        Similarly, rule providers and consumers consist of actors that define
        the scope of the rule:

        "providers": [
          {
            "ip_list": {
              "href": "/orgs/1/sec_policy/active/ip_lists/9"
            }
          }
        ],
        "consumers": [
          {
            "actors": "ams"
          }
        ]

        These can be flattened in a similar manner:

        providers: {"exclusions": [], "inclusions": ["/orgs/1/sec_policy/..."]}
        consumers: {"exclusions": [], "inclusions": ["ams"]}

        Args:
            scope (List[dict]): list of scope dimensions or rule actors.

        Returns:
            dict: the flattened scope output.
        """
        flattened_actors = {}

        for dimension in scope:
            key = "exclusions" if dimension.pop("exclusion", False) else "inclusions"

            if "actors" in dimension:
                flattened_actors[key] = dimension["actors"]
                continue

            for k in dimension.keys():
                # rather than hardcode type checks, just iterate over all keys
                # and extract the first HREF
                try:
                    href = href_from(dimension[k])
                    flattened_actors[key] = flattened_actors.get(key, []).append(href)
                    continue
                except Exception:
                    pass

        return flattened_actors

    def _flatten_rules(self, rule_set: dict) -> List[dict]:
        """Given a rule set object, extracts and flattens all contained rules.

        Rules, IP tables rules, and deny rules are combined in a single KVStore
        collection. Fields with nested values (services, consumers, providers)
        are flattened to avoid loss of cohesion when converted to MV fields.

        Args:
            rule_set (dict): the rule set object to extract from.

        Returns:
            List[dict]: the flattened rule objects.
        """
        rules = []

        for rule_type in ("rules", "ip_tables_rules", "deny_rules"):
            for rule in rule_set.pop(rule_type, []):
                rule["type"] = rule_type
                rule["rule_set_href"] = rule_set["href"]
                # rules and deny rules share the same attributes
                rule["ingress_services"] = self._flatten_ingress_services(
                    rule.get("ingress_services", [])
                )
                rule["egress_services"] = [href_from(s) for s in rule.get("egress_services", [])]
                rule["providers"] = self._flatten_scope(rule.get("providers", []))
                rule["consumers"] = self._flatten_scope(rule.get("consumers", []))
                rule["consuming_security_principals"] = [
                    href_from(s) for s in rule.get("consuming_security_principals", [])
                ]
                # IP tables rules fields
                rule["statements"] = [
                    f"{s['table_name']} {s['chain_name']} {s['parameters']}"
                    for s in rule.get("statements", [])
                ]
                rule["actors"] = self._flatten_scope(rule.get("actors", []))

                rules.append(rule)

        return rules

    def _flatten_ingress_services(self, services: List[dict]) -> List[str]:
        """Flattens the given ingress service entries into a string list.

        Service HREF objects simplify to the HREF string, and port ranges are
        changed to a string representation, for example:

        "ingress_services": [
          {
            "href": "/orgs/1/sec_policy/active/services/19"
          },
          {
            "port": 443,
            "proto": 6
          },
          {
            "port": 127,
            "to_port": 128,
            "proto": 17
          }
        ]

        becomes

        [ "/orgs/1/sec_policy/active/services/19", "443 tcp", "127-128 udp" ]

        Args:
            services (List[dict]): list of ingress service entries.

        Returns:
            List[str]: flattened list of services.
        """
        flattened_services = []

        for service in services:
            # services can be either an HREF object or a port range
            try:
                flattened_services.append(href_from(service))
                continue
            except Exception:
                if not "proto" in service:
                    continue
            flattened_services.append(service_port_to_string(service))

        return flattened_services

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
        old = kvstore.data.query(pce_fqdn=params.pce_fqdn, org_id=params.org_id)

        # additional fields to append to all objects in the set
        fields = {"pce_fqdn": params.pce_fqdn, "org_id": params.org_id, "deleted": False}

        # build an index of all objects in the KVStore and mark them as deleted
        idx = {o["_key"]: {**o, "deleted": True} for o in old}

        for o in new:
            # prepend the PCE FQDN to the key to ensure uniqueness across multiple PCEs
            key = o.get("_key", f"{params.pce_fqdn}:{o.get('href', '')}")
            idx[key] = {**o, **fields, "_key": key}

        return list(idx.values())

    def _update_kvstore(self, name: str, objs: List[dict]) -> None:
        """Updates a specified KVStore with the given PCE objects.

        Any existing KVStore data is removed and replaced to avoid stale state.

        Args:
            name (str): the name of the KVStore to update.
            params (IllumioInputParameters): input parameter data object.
            objs (List[dict]): list of objects to save to the store.

        Raises:
            KeyError: if the specified KVStore doesn't exist.
        """
        if not objs:
            return  # no need to do anything if the collection is empty
        kvstores = self.service.kvstore
        kvstore = kvstores[name]
        kvstore.data.batch_save(*objs)

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

    def _get_tcp_input(self, port_number: int) -> Any:
        """Retrieves a TCP input for the given syslog port from Splunk.

        Returns:
            Any: the Input object, or None if the input is not defined.
        """
        try:
            return self.service.inputs[(str(port_number), "tcp")]
        except Exception:
            return None

    def _create_tcp_input(self, app: str, params: IllumioInputParameters) -> None:
        """Creates a TCP input in the given app using the provided parameters.

        Args:
            app (str): the app to create the input in.
            params (IllumioInputParameters): input parameters.
        """
        stanza_type = "tcp-ssl" if params.enable_tcp_ssl else "tcp"

        # we can't use service.inputs here as it doesn't support tcp-ssl.
        # tcp inputs have an SSL property, but it's poorly documented and
        # not clear if it has the same effect
        self.service.post(
            client.PATH_CONF % "inputs",
            name=f"{stanza_type}://{params.port_number}",
            app=app,
            connection_host="dns",
            index=params.index,
            sourcetype=SYSLOG_SOURCETYPE,
            disabled=0,
        )


if __name__ == "__main__":
    sys.exit(Illumio().run(sys.argv))
