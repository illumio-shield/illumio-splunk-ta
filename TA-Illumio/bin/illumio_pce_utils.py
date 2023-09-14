# -*- coding: utf-8 -*-

"""This module provides helper utilities for the Illumio TA.

Copyright:
    © 2023 Illumio
License:
    Apache2, see LICENSE for more details.
"""
from typing import List
from urllib.parse import urlparse

from illumio import PolicyComputeEngine, Workload

REALM = "illumio://"


class PCEConnectionConfig:
    """Config class to hold PCE client connecton details."""

    def __init__(self, **kwargs):
        self.pce_url = kwargs.get("pce_url")
        parsed = urlparse(self.pce_url)
        scheme = str(parsed.scheme) if parsed.scheme else "https"
        default_port = 80 if scheme == "http" else 443
        self.pce_port = parsed.port if parsed.port else int(kwargs.get("pce_port", default_port))

        self.api_key_id = kwargs.get("api_key_id")
        self.api_secret = kwargs.get("api_secret")
        self.org_id = int(kwargs.get("org_id") or 1)
        self.self_signed_cert_path = kwargs.get("self_signed_cert_path")
        self.http_proxy = kwargs.get("http_proxy")
        self.https_proxy = kwargs.get("https_proxy")
        self.http_retry_count = int(kwargs.get("http_retry_count") or 5)
        self.http_request_timeout = int(kwargs.get("http_request_timeout") or 30)


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
        self.allowed_ips = kwargs.get("allowed_ips")
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

        Inherits from an existing PCE instance and checks the PCE status
        endpoint to determine if it is a Supercluster.

        Raises:
            Exception: if a non-Supercluster PCE instance is provided.
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

    def get_workloads(self) -> List[Workload]:
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
            List[Workload]: workloads retrieved from the Supercluster.
        """
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
        # TODO: support configurable retry params

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


__all__ = [
    "PCEConnectionConfig",
    "IllumioInputParameters",
    "Supercluster",
    "connect_to_pce",
    "is_supercluster",
    "parse_label_scope",
]
