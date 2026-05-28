"""Tests for the paginated KV store query fix in _kvstore_union().

Verifies that _kvstore_union() correctly paginates kvstore.data.query()
using limit/skip parameters to fetch all records, regardless of
Splunk's max_rows_per_query limit.

See: APPS-2403 (Stale workloads visible on Search Head after VEN unpair)
"""
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "bin" / "illumio.py"

PCE_FQDN = "test-pce.example.com"
ORG_ID = "1"
TOTAL_OLD_RECORDS = 100
QUERY_PAGE_SIZE = 60
PCE_RETURNS = 80  # PCE returns workloads 0-79; workloads 80-99 were unpaired


def _make_workload_record(index: int, deleted: bool = False) -> dict:
    href = f"/orgs/1/workloads/{index:04d}"
    key = f"{PCE_FQDN}:{href}"
    return {
        "_key": key,
        "href": href,
        "hostname": f"host-{index:04d}",
        "pce_fqdn": PCE_FQDN,
        "org_id": ORG_ID,
        "managed": True,
        "deleted": deleted,
    }


def _make_pce_workload(index: int) -> dict:
    return {
        "href": f"/orgs/1/workloads/{index:04d}",
        "hostname": f"host-{index:04d}",
    }


def _load_illumio_module():
    illumio_lib = types.ModuleType("illumio")
    illumio_lib.PolicyComputeEngine = Mock
    illumio_lib.validate_int = Mock()
    illumio_lib.PORT_MAX = 65535
    illumio_lib.ACTIVE = "active"

    splunklib = types.ModuleType("splunklib")
    splunklib_client = types.ModuleType("splunklib.client")
    splunklib_client.Service = Mock

    modularinput = types.ModuleType("splunklib.modularinput")
    modularinput.Script = type("Script", (), {"run": lambda self, args: None})
    modularinput.Scheme = Mock
    modularinput.Argument = Mock
    modularinput.Argument.data_type_string = "string"
    modularinput.Argument.data_type_number = "number"
    modularinput.Argument.data_type_boolean = "boolean"
    modularinput.EventWriter = Mock
    modularinput.Event = Mock
    modularinput.InputDefinition = Mock
    modularinput.ValidationDefinition = Mock

    constants = types.ModuleType("illumio_constants")
    constants.KVSTORE_WORKLOADS = "illumio_workloads"
    constants.KVSTORE_WORKLOAD_INTERFACES = "illumio_workload_interfaces"
    constants.KVSTORE_IP_LISTS = "illumio_ip_lists"
    constants.KVSTORE_LABELS = "illumio_labels"
    constants.KVSTORE_SERVICES = "illumio_services"
    constants.KVSTORE_RULE_SETS = "illumio_rule_sets"
    constants.KVSTORE_RULES = "illumio_rules"
    constants.KVSTORE_PORT_SCAN_SETTINGS = "illumio_port_scan_settings"
    constants.KVSTORE_COLLECTIONS = [
        constants.KVSTORE_WORKLOADS,
        constants.KVSTORE_WORKLOAD_INTERFACES,
        constants.KVSTORE_IP_LISTS,
        constants.KVSTORE_LABELS,
        constants.KVSTORE_SERVICES,
        constants.KVSTORE_RULE_SETS,
        constants.KVSTORE_RULES,
    ]
    constants.KVSTORE_BATCH_DEFAULT = 1000
    constants.KVSTORE_QUERY_BATCH_DEFAULT = 50000
    constants.ILLUMIO_TA = "TA-Illumio"
    constants.ILO_TYPE_WORKLOADS = "workloads"
    constants.ILO_TYPE_LABELS = "labels"
    constants.ILO_TYPE_IP_LISTS = "ip_lists"
    constants.ILO_TYPE_SERVICES = "services"
    constants.ILO_TYPE_RULE_SETS = "rule_sets"

    pce_utils = types.ModuleType("illumio_pce_utils")
    pce_utils.IllumioInputParameters = type(
        "IllumioInputParameters", (), {"pce_fqdn": PCE_FQDN, "org_id": ORG_ID}
    )
    pce_utils.Supercluster = Mock
    pce_utils.flatten_refs = Mock

    splunk_utils = types.ModuleType("illumio_splunk_utils")
    splunk_utils.update_kvstore = Mock()
    splunk_utils.get_tcp_input = Mock()
    splunk_utils.get_credentials_for_search_heads = Mock()

    kvstore_upload = types.ModuleType("illumio_kvstore_upload")
    kvstore_upload.KVStoreUpload = Mock

    stubbed = {
        "illumio": illumio_lib,
        "illumio_kvstore_upload": kvstore_upload,
        "splunklib": splunklib,
        "splunklib.client": splunklib_client,
        "splunklib.modularinput": modularinput,
        "illumio_constants": constants,
        "illumio_pce_utils": pce_utils,
        "illumio_splunk_utils": splunk_utils,
    }

    with patch.dict(sys.modules, stubbed):
        spec = importlib.util.spec_from_file_location("illumio_under_test", MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

    return module, constants, pce_utils


def _make_paginated_query_mock(all_records, page_size):
    """Returns a mock query() that returns paginated results based on limit/skip."""
    def paginated_query(query=None, limit=None, skip=None, sort=None):
        s = skip or 0
        l = limit or len(all_records)
        return all_records[s:s + l]
    return paginated_query


class TestKVStoreUnionPagination:
    """Verifies that _kvstore_union() paginates queries to fetch all records."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.module, self.constants, self.pce_utils = _load_illumio_module()

        self.all_old_records = [
            _make_workload_record(i) for i in range(TOTAL_OLD_RECORDS)
        ]
        self.new_from_pce = [_make_pce_workload(i) for i in range(PCE_RETURNS)]

        self.illumio_instance = self.module.Illumio.__new__(self.module.Illumio)
        self.illumio_instance.service = Mock()

        # Mock limits.conf to return a page size of 60
        mock_limits_kvstore = {"max_rows_per_query": str(QUERY_PAGE_SIZE)}
        self.illumio_instance.service.confs = {"limits": {"kvstore": mock_limits_kvstore}}

        # Mock kvstore.data.query() to return paginated results
        mock_kvstore_data = Mock()
        mock_kvstore_data.query.side_effect = _make_paginated_query_mock(
            self.all_old_records, QUERY_PAGE_SIZE
        )

        self.illumio_instance.service.kvstore = {
            self.constants.KVSTORE_WORKLOADS: Mock(data=mock_kvstore_data)
        }
        self.mock_kvstore_data = mock_kvstore_data

        self.params = self.pce_utils.IllumioInputParameters()
        self.params.pce_fqdn = PCE_FQDN
        self.params.org_id = ORG_ID

    def test_pagination_fetches_all_records(self):
        """The paginated query fetches all 100 records across multiple pages."""
        result = self.illumio_instance._kvstore_union(
            self.constants.KVSTORE_WORKLOADS,
            self.params,
            self.new_from_pce,
        )

        assert len(result) == TOTAL_OLD_RECORDS

    def test_query_called_multiple_times_with_skip(self):
        """query() is called with increasing skip values to paginate."""
        self.illumio_instance._kvstore_union(
            self.constants.KVSTORE_WORKLOADS,
            self.params,
            self.new_from_pce,
        )

        calls = self.mock_kvstore_data.query.call_args_list
        assert len(calls) == 2  # 60 + 40 records = 2 pages
        assert calls[0].kwargs["skip"] == 0
        assert calls[0].kwargs["limit"] == QUERY_PAGE_SIZE
        assert calls[0].kwargs["sort"] == "_key:1"
        assert calls[1].kwargs["skip"] == 60
        assert calls[1].kwargs["limit"] == QUERY_PAGE_SIZE
        assert calls[1].kwargs["sort"] == "_key:1"

    def test_all_unpaired_workloads_marked_deleted(self):
        """Workloads 80-99 are not in PCE and are correctly marked deleted=True."""
        result = self.illumio_instance._kvstore_union(
            self.constants.KVSTORE_WORKLOADS,
            self.params,
            self.new_from_pce,
        )

        result_by_key = {r["_key"]: r for r in result}

        for i in range(PCE_RETURNS, TOTAL_OLD_RECORDS):
            key = f"{PCE_FQDN}:/orgs/1/workloads/{i:04d}"
            assert key in result_by_key, f"Workload {i} missing from union output"
            assert result_by_key[key]["deleted"] is True, (
                f"Workload {i} was unpaired but not marked deleted"
            )

    def test_active_workloads_not_marked_deleted(self):
        """Workloads 0-79 are in PCE and have deleted=False."""
        result = self.illumio_instance._kvstore_union(
            self.constants.KVSTORE_WORKLOADS,
            self.params,
            self.new_from_pce,
        )

        result_by_key = {r["_key"]: r for r in result}

        for i in range(PCE_RETURNS):
            key = f"{PCE_FQDN}:/orgs/1/workloads/{i:04d}"
            assert result_by_key[key]["deleted"] is False

    def test_no_stale_records_after_batch_save(self):
        """After upsert, no unpaired workloads remain with deleted=False."""
        result = self.illumio_instance._kvstore_union(
            self.constants.KVSTORE_WORKLOADS,
            self.params,
            self.new_from_pce,
        )

        kvstore_state = {r["_key"]: dict(r) for r in self.all_old_records}
        for record in result:
            kvstore_state[record["_key"]] = record

        for i in range(PCE_RETURNS, TOTAL_OLD_RECORDS):
            key = f"{PCE_FQDN}:/orgs/1/workloads/{i:04d}"
            assert kvstore_state[key]["deleted"] is True, (
                f"Workload {i} is stale (deleted=False) after batch_save"
            )

    def test_falls_back_to_default_when_limits_conf_unavailable(self):
        """Uses KVSTORE_QUERY_BATCH_DEFAULT when limits.conf is unreadable."""
        self.illumio_instance.service.confs = Mock(
            __getitem__=Mock(side_effect=Exception("no limits.conf"))
        )

        # With default batch size of 50000 and only 100 records,
        # a single page should fetch everything
        result = self.illumio_instance._kvstore_union(
            self.constants.KVSTORE_WORKLOADS,
            self.params,
            self.new_from_pce,
        )

        assert len(result) == TOTAL_OLD_RECORDS
        calls = self.mock_kvstore_data.query.call_args_list
        assert len(calls) == 1
        assert calls[0].kwargs["limit"] == 50000
