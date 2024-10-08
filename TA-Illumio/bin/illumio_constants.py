# -*- coding: utf-8 -*-

"""This module provides constant values for the TA.

Copyright:
    © 2023 Illumio
License:
    Apache2, see LICENSE for more details.
"""
# sourcetypes
SYSLOG_SOURCETYPE = "illumio:pce"
HEALTH_SOURCETYPE = "illumio:pce:health"
QUARANTINE_ACTION_SOURCETYPE = "illumio:pce:quarantine"

# KVStore names
KVSTORE_IP_LISTS = "illumio_ip_lists"
KVSTORE_LABELS = "illumio_labels"
KVSTORE_RULE_SETS = "illumio_rule_sets"
KVSTORE_RULES = "illumio_rules"
KVSTORE_SERVICES = "illumio_services"
KVSTORE_WORKLOADS = "illumio_workloads"
KVSTORE_WORKLOAD_INTERFACES = "illumio_workload_interfaces"
KVSTORE_PORT_SCAN = "illumio_port_scan_settings"

# KVStore limits
KVSTORE_BATCH_DEFAULT = 1000

# illumio types
ILO_TYPE_IP_LISTS = "illumio:pce:ip_lists"
ILO_TYPE_LABELS = "illumio:pce:labels"
ILO_TYPE_RULE_SETS = "illumio:pce:rule_sets"
ILO_TYPE_SERVICES = "illumio:pce:services"
ILO_TYPE_WORKLOADS = "illumio:pce:workloads"

# CAM constants
QUARANTINE_ACTION_NAME = "illumio_quarantine"
QUARANTINE_ACTION_ROLE = "illumio_quarantine_workload"
SUCCESS_STATUS = "success"
FAILURE_STATUS = "failure"

ILLUMIO_APP = "IllumioAppforSplunk"
ILLUMIO_TA = "TA-Illumio"

SEARCH_HEAD_CREDENTIALS_PREFIX = "kvstore"
