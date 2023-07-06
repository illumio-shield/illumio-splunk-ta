# -*- coding: utf-8 -*-

"""This module provides helper utilities for the Illumio TA.

Copyright:
    © 2023 Illumio
License:
    Apache2, see LICENSE for more details.
"""
import time
from dataclasses import dataclass, fields, field
from typing import List
from urllib.parse import urlparse

from illumio import PolicyComputeEngine, Workload


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
    quarantine_labels: str = ""
    # extra setting fields
    host: str = ""
    interval: str = "3600"
    index: str = "default"
    sourcetype: str = "illumio:pce:metadata"
    disabled: bool = True
    _api_secret_name: str = ""
    _stanza: str = ""

    def __post_init__(self):
        # handle type conversion for all fields, ignoring nulls
        for field in fields(self):
            value = getattr(self, field.name)
            if value is not None and not isinstance(value, field.type):
                try:
                    setattr(self, field.name, field.type(value))
                except ValueError:
                    raise ValueError(f"{field.name}: invalid value {value}")

        parsed = urlparse(self.pce_url)
        if parsed.port:
            self.pce_port = parsed.port

        if self.org_id <= 0:
            raise ValueError("Organization ID must be non-negative integer")

    @property
    def api_secret_name(self) -> str:
        return f"{self.stanza}:{self.api_key_id}"

    @property
    def stanza(self) -> str:
        realm = "illumio://"
        if self.name.startswith(realm):
            return self.name.replace(":", r"\:")
        return f"{realm}{self.name}".replace(":", r"\:")


@dataclass
class Supercluster:
    """Dataclass to hold PCE Supercluster member information."""

    leader: str = ""
    members: List[str] = field(default_factory=list)

    @staticmethod
    def from_status(clusters: List[dict]) -> "Supercluster":
        """Parses PCE nodes and returns an `Supercluster` object.

        If a non-Supercluster PCE status is provided, returns None.

        Args:
            clusters (List[dict]): list of cluster metadata objects.

        Raises:
            Exception: if more than one or no Supercluster leader is defined.

        Returns:
            Supercluster: Supercluster dataclass object.
        """
        if len(clusters) < 2:
            return None

        supercluster = Supercluster()

        for cluster in clusters:
            cluster_type = cluster.get("type")
            if not cluster_type:
                continue

            if cluster_type == "standalone":
                continue

            if cluster_type == "leader":
                if supercluster.leader:
                    raise Exception("More than one Supercluster leader is defined.")
                supercluster.leader = cluster["fqdn"]
            else:
                supercluster.members.append(cluster["fqdn"])

        if not supercluster.members:
            return None

        if not supercluster.leader:
            raise Exception("Supercluster provided but no leader is defined.")

        return supercluster


def connect_to_pce(params: IllumioInputParameters) -> PolicyComputeEngine:
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


def get_supercluster_workloads(sc: Supercluster, params: IllumioInputParameters) -> List[Workload]:
    """Retrieves workloads from all Supercluster members.

    VEN uptime and last_heartbeat_at metadata is not replicated across the
    Supercluster (as of PCE v23.1), so we need to call each SC member
    individually to get paired workloads.

    Since the Supercluster leader can change at any time, this function
    must work when the input is configured for any cluster member.

    Args:
        pce (PolicyComputeEngine): PCE connection client.
        supercluster (Supercluster): Supercluster dataclass object.

    Returns:
        List[Workload]: workloads retrieved from the Supercluster.
    """
    params.pce_url = sc.leader
    pce = connect_to_pce(params)

    # start by getting all workloads from the leader. this way, if a member
    # cluster is down we still get the workload metadata even if we're
    # missing some uptime/last_heartbeat_at values. unmanaged workloads
    # are pulled in a separate request so that we have a smaller set to
    # iterate over
    managed_workloads = pce.workloads.get_async(params={"managed": True})
    mw_map = {mw.hostname: mw for mw in managed_workloads}
    unmanaged_workloads = pce.workloads.get_async(params={"managed": False})

    for member_fqdn in sc.members:
        pce._hostname = member_fqdn
        # filtering by last_heartbeat_at < now gets all managed workloads
        # paired to the requested cluster, as other MWs will have null
        # uptime/last_heartbeat_at values
        paired_mw_query = {"managed": True, "last_heartbeat_at[lte]": time.time()}
        for mw in pce.workloads.get_async(params=paired_mw_query):
            mw_map[mw.hostname].agent.status.last_heartbeat_on = mw.agent.status.last_heartbeat_on
            mw_map[mw.hostname].agent.status.uptime_seconds = mw.agent.status.uptime_seconds

    return list(mw_map.values()) + unmanaged_workloads


__all__ = [
    "IllumioInputParameters",
    "Supercluster",
    "connect_to_pce",
    "get_supercluster_workloads",
]
