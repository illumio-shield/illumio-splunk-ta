# -*- coding: utf-8 -*-

"""This module provides helper utilities for the Illumio TA.

Copyright:
    © 2023 Illumio
License:
    Apache2, see LICENSE for more details.
"""
import re
import socket
from typing import List
from urllib.parse import urlparse, quote

from illumio import PolicyComputeEngine, href_from

REALM = "illumio://"


class PCEConnectionConfig:
    """Config class to hold PCE client connecton details."""

    def __init__(self, **kwargs):
        self.pce_url = kwargs.get("pce_url")
        self.pce_fqdn, self.pce_port = self._parse_url(self.pce_url)
        self.api_key_id = kwargs.get("api_key_id")
        self.api_secret = kwargs.get("api_secret")
        self.org_id = int(kwargs.get("org_id") or 1)
        self.self_signed_cert_path = kwargs.get("self_signed_cert_path")
        self.http_proxy = kwargs.get("http_proxy")
        self.https_proxy = kwargs.get("https_proxy")
        self.http_retry_count = int(kwargs.get("http_retry_count") or 5)
        self.http_request_timeout = int(kwargs.get("http_request_timeout") or 30)

    def _parse_url(self, url: str) -> tuple:
        """Parses the given URL, returning a tuple containing the FQDN and port.

        Unless specified in the URL, the port value defaults to 80 or 443 are
        for scheme values of http:// and https:// respectively. Any other
        scheme value will default to 443.

        Args:
            url (str): the URL to parse.

        Returns:
            tuple: of the form (fqdn, port)
        """
        pattern = re.compile("^\w+://")
        if not re.match(pattern, url):
            url = f"https://{url}"
        parsed = urlparse(url)
        port = parsed.port or (80 if parsed.scheme == "http" else 443)
        return parsed.hostname, port


class IllumioInputParameters(PCEConnectionConfig):
    """Config class to hold Illumio input parameters."""

    _api_secret_name: str
    _stanza: str

    def __init__(self, *, name: str, **kwargs):
        # not using a dataclass to avoid errors on undefined attributes
        self.name = name
        self.index = kwargs.get("index")
        self.source = kwargs.get("source")
        self.sourcetype = kwargs.get("sourcetype")
        self.port_number = int(kwargs.get("port_number") or -1)
        self.enable_tcp_ssl = kwargs.get("enable_tcp_ssl", True)
        self.port_scan_interval = int(kwargs.get("port_scan_interval") or 0)
        self.port_scan_threshold = int(kwargs.get("port_scan_threshold") or 0)
        allowed_ips = kwargs.get("allowed_ips") or ""
        self.allowed_ips = [ip.strip() for ip in allowed_ips.split(",")]
        super().__init__(**kwargs)

    @property
    def api_secret_name(self) -> str:
        return f"{self.stanza}:{self.api_key_id}"

    @property
    def stanza(self) -> str:
        if self.name.startswith(REALM):
            return self.name.replace(":", r"\:")
        return f"{REALM}{self.name}".replace(":", r"\:")

    def port_scan_details(self) -> dict:
        return {
            "threshold": self.port_scan_threshold,
            "interval": self.port_scan_interval,
            "allowed_ips": self.allowed_ips,
        }


class Supercluster(PolicyComputeEngine):
    def __init__(self, pce: PolicyComputeEngine, pce_status: List[dict]):
        """PolicyComputeEngine subclass representing an Illumio Supercluster.

        Inherits from an existing PCE instance and determines the Supercluster
        leader and members based on the given status information.

        Args:
            pce (PolicyComputeEngine): PCE API client to wrap.
            pce_status (List[dict]): PCE /health endpoint status response.
        """
        self.leader = ""
        self.members = []

        for cluster in pce_status:
            cluster_type = cluster.get("type")

            if cluster_type == "leader":
                self.leader = cluster["fqdn"]
            elif cluster_type == "member":
                self.members.append(cluster["fqdn"])

    def __new__(cls, pce: PolicyComputeEngine, sc_status: List[dict]):
        """Wrap the passed PolicyComputeEngine instance."""
        pce.__class__ = cls
        return pce

    def get_workloads(self) -> List[dict]:
        """Retrieves workloads from all Supercluster members.

        VEN uptime and last_heartbeat_at metadata is not replicated across the
        Supercluster (as of PCE v23.1), so we need to call each SC member
        individually to get paired workloads.

        Since the Supercluster leader can change at any time, this function
        must work when the input is configured for any cluster member.

        Raises:
            Exception: if the PCE connection to the leader and configured FQDN
                both fail.

        Returns:
            List[dict]: workloads retrieved from the Supercluster.
        """
        _configured_hostname = self._hostname
        endpoint = self.workloads._build_endpoint(None, None)

        try:
            self._hostname = self.leader

            # start by getting all workloads from the leader. this way, if a member
            # cluster is down we still get the workload metadata even if we're
            # missing some uptime/last_heartbeat_at values
            resp = self.get_collection(endpoint, include_org=False)
            mw_map = {}

            # index workloads so we can update them with missing metadata
            for workload in resp.json():
                mw_map[workload["href"]] = workload
        except Exception:
            # if we can't connect to the leader, fall back on the configured FQDN
            self._hostname = _configured_hostname
            resp = self.get_collection(endpoint, include_org=False)
            return resp.json()

        for member_fqdn in self.members:
            self._hostname = member_fqdn
            # filtering by active_pce_fqdn gets all managed workloads paired to
            # the specified cluster
            paired_mw_query = {"managed": True, "agent.active_pce_fqdn": member_fqdn}
            try:
                resp = self.get_collection(endpoint, include_org=False, params=paired_mw_query)
                for mw in resp.json():
                    mw_map[mw["href"]] = mw
            except Exception:
                continue  # if a member is unreachable, still try the others

        return list(mw_map.values())


def connect_to_pce(config: PCEConnectionConfig) -> PolicyComputeEngine:
    """Attempts to connect to the PCE.

    Args:
        config (PCEConnectionConfig): script input parameters.

    Raises:
        Exception: if the connection could not be established.

    Returns:
        PolicyComputeEngine: the PCE client object.
    """
    try:
        pce = PolicyComputeEngine(
            config.pce_url,
            port=config.pce_port,
            org_id=config.org_id,
            retry_count=config.http_retry_count,
            request_timeout=config.http_request_timeout,
        )
        pce.set_credentials(config.api_key_id, config.api_secret)
        pce.set_tls_settings(verify=config.self_signed_cert_path or True)
        pce.set_proxies(http_proxy=config.http_proxy, https_proxy=config.https_proxy)

        pce.must_connect()

        return pce
    except Exception as e:
        raise Exception(f"Failed to connect to PCE: {e}")


def is_supercluster(pce_status: List[dict]) -> bool:
    """Checks if the given PCE status response describes a Supercluster.

    Args:
        pce_status (List[dict]): PCE status response object.

    Returns:
        bool: True if the PCE is a Supercluster, otherwise False.
    """
    if len(pce_status) < 2:
        return False

    leader = None
    members = []

    for cluster in pce_status:
        cluster_type = cluster.get("type")

        if cluster_type == "leader":
            if leader is not None:
                return False
            leader = cluster["fqdn"]
        elif cluster_type == "member":
            members.append(cluster["fqdn"])

    return leader is not None and len(members) > 0


def parse_label_scope(scope: str) -> dict:
    """Parse label scopes passed as a string of the form k1:v1,k2:v2,...

    Args:
        scope (str): Policy scope as a comma-separated key:value pair list.

    Raises:
        ValueError: if the given scope format is invalid.

    Returns:
        dict: dict containing label key:value pairs.
    """
    label_dimensions = scope.split(",")
    labels = {}
    for label in label_dimensions:
        if not label.strip():
            continue

        try:
            k, v = label.split(":")
        except Exception:
            raise ValueError("Invalid format: must be key1:value1,key2:value2...")

        if k.strip() in labels:
            raise ValueError("Label scope keys must be unique")

        labels[k.strip()] = v.strip()
    if not labels:
        raise ValueError("Empty label scope provided")
    return labels


def getprotobynum(proto_num: int) -> str:
    """Looks up protocol name based on its IANA number.

    Follows the socket lib naming convention.

    Args:
        proto_num (int): the protocol IANA number.

    Raises:
        ValueError: if the protocol name can't be identified.

    Returns:
        str: the protocol name.
    """
    if proto_num == -1:  # special case: -1 indicates all services
        return "all"
    for name, num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:].lower()
    raise ValueError(f"Couldn't find name for protocol number: {proto_num}")


def service_port_to_string(service_port: dict) -> str:
    """Converts service port range object dict to string.

    {
        "port": 443,
        "proto": 6
    }

    will be converted to "443 TCP"

    Args:
        service (dict): the port range object.

    Returns:
        str: string representation of the port range.
    """
    proto = getprotobynum(service_port["proto"])
    port_range = f"{service_port.get('port', '')}-{service_port.get('to_port', '')}"

    return f"{port_range.strip('-')} {proto}".strip()


def flatten_refs(o: dict, *keys: str):
    """Flattens HREF objects for specified keys in the given object.

    Takes any number of additional string arguments as keys to flatten.

    Args:
        o (dict): object to flatten.
    """
    for k in keys:
        if k in o and type(o[k]) is dict:
            o[k] = href_from(o[k])


def flatten_ingress_services(services: List[dict]) -> List[str]:
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


def flatten_scope(scope: List[dict]) -> dict:
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
                flattened_actors[key] = flattened_actors.get(key, []) + [href]
                continue
            except Exception:
                pass

    return flattened_actors


def flatten_rules(rule_set: dict) -> List[dict]:
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
            rule["rule_set_name"] = rule_set["name"]
            # rules and deny rules share the same attributes
            rule["ingress_services"] = flatten_ingress_services(rule.get("ingress_services", []))
            rule["egress_services"] = [href_from(s) for s in rule.get("egress_services", [])]
            rule["providers"] = flatten_scope(rule.get("providers", []))
            rule["consumers"] = flatten_scope(rule.get("consumers", []))
            rule["consuming_security_principals"] = [
                href_from(s) for s in rule.get("consuming_security_principals", [])
            ]
            # IP tables rules fields
            rule["statements"] = [
                f"{s['table_name']} {s['chain_name']} {s['parameters']}"
                for s in rule.get("statements", [])
            ]
            rule["actors"] = flatten_scope(rule.get("actors", []))

            rules.append(rule)

    return rules


def flatten_ip_list(ip_list: dict, pce_fqdn: str) -> List[dict]:
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
    # start by flattening the created_by/updated_by HREF objects for each entry
    flatten_refs(ip_list, "created_by", "updated_by")
    ip_list_entries = []

    # strip the FQDN descriptions and flatten them as an array of strings
    ip_list["fqdns"] = [fqdn["fqdn"] for fqdn in ip_list.pop("fqdns", [])]

    for ip_range in ip_list.pop("ip_ranges", []):
        key = f"{pce_fqdn}:{ip_list['href']}:{ip_range.get('from_ip')}:{ip_range.get('to_ip')}"
        # rename the IP range description field
        ip_range["ip_range_description"] = ip_range.get("description")
        ip_list_entries.append({**ip_list, **ip_range, "_key": key})

    return ip_list_entries


def flatten_service(service: dict, pce_fqdn: str) -> List[dict]:
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
    # start by flattening the created_by/updated_by HREF objects for each entry
    flatten_refs(service, "created_by", "updated_by")
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


__all__ = [
    "PCEConnectionConfig",
    "IllumioInputParameters",
    "Supercluster",
    "connect_to_pce",
    "is_supercluster",
    "parse_label_scope",
    "getprotobynum",
    "service_port_to_string",
    "flatten_refs",
    "flatten_ingress_services",
    "flatten_scope",
    "flatten_rules",
    "flatten_ip_list",
    "flatten_service",
]
