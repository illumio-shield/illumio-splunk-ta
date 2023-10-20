# -*- coding: utf-8 -*-

"""This module provides a ModularAction for quarantining workloads in the PCE.

Copyright:
    © 2023 Illumio
License:
    Apache2, see LICENSE for more details.
"""
from builtins import str
import csv
import codecs
import gzip
import logging
import sys
from pathlib import Path
from time import sleep
from typing import List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

import splunklib.client as client
from splunklib.results import JSONResultsReader, Message
from cim_actions import ModularAction

from illumio import PolicyComputeEngine

from illumio_constants import *
from illumio_pce_utils import *
from illumio_splunk_utils import *

logger = ModularAction.setup_logger(f"{QUARANTINE_ACTION_NAME}_modalert")


class IllumioQuarantineAction(ModularAction):
    """Illumio alert action for marking quarantine."""

    _params: IllumioInputParameters = None
    _service: client.Service = None

    def __init__(self, settings, logger, action_name="unknown"):
        super().__init__(settings, logger, action_name)
        self.workload_href = self.configuration.get("workload_href")
        self.pce_fqdn = self.configuration.get("pce_fqdn")
        self.org_id = self.configuration.get("org_id")

    def run(self, result) -> int:
        self.update(result)
        self.invoke()
        self.validate()
        self.dowork()

    def validate(self):
        """Validate quarantine action configuration.

        The PCE API is called with the configuration in the input that matches
        the PCE FQDN and org ID provided when calling the action. Since this
        configuration is already validated in the modular input script, there
        is no need to check it again here. The same logic applies to the
        configured quarantine label pairs.
        """
        # search to check if the calling user has the quarantine role
        query = f"""| rest splunk_server=local /services/authentication/current-context
| eval show_quarantine=if(roles="{QUARANTINE_ACTION_ROLE}",1,0)
| table show_quarantine"""

        for result in self._get_search_results(query):
            if isinstance(result, Message):
                continue  # skip any diagnostic messages
            if not result or str(list(result.values())[0]) == "0":
                raise Exception(f'user does not have the required "{QUARANTINE_ACTION_ROLE}" role')
            break

        if not self.workload_href:
            raise ValueError("missing or empty parameter: workload_href")

        if not self.pce_fqdn:
            raise ValueError("missing or empty parameter: pce_fqdn")

        if self.org_id is None:
            raise ValueError("missing or empty parameter: org_id")
        else:
            try:
                self.org_id = int(self.org_id)
                if self.org_id < 1:
                    raise Exception()
            except Exception:
                raise ValueError("org ID value must be an integer greater than or equal to 1")

    def dowork(self):
        """Connects to the PCE and updates the given workload's labels to put it in Quarantine"""
        pce = connect_to_pce(self.params)
        labels = self._get_label_hrefs(pce)
        if not labels:
            raise Exception("no Quarantine labels provided")
        pce.workloads.update(self.workload_href, {"labels": [{"href": l} for l in labels]})

        msg = f'Workload "{self.workload_href}" successfully quarantined'

        self.message(msg, status=SUCCESS_STATUS)
        self.addevent(msg, sourcetype=QUARANTINE_ACTION_SOURCETYPE)

    def _get_search_results(self, query: str) -> JSONResultsReader:
        """Runs a search job and returns the result stream wrapped in a JSONResultsReader object"""
        job = self.service.search(query)
        while not job.is_done():
            sleep(.2)
        return JSONResultsReader(job.results(output_mode="json"))

    def _get_illumio_input_stanza(self) -> Tuple[str, dict]:
        """Returns the illumio modinput stanza matching the configured pce_fqdn and org_id"""
        for conf in self.service.confs["inputs"]:
            if conf.name.startswith("illumio://"):
                if self.pce_fqdn in conf["pce_url"] and conf["org_id"] == str(self.org_id):
                    return conf.name, conf.content
        raise Exception(f"no input stanza with pce_fqdn={self.pce_fqdn} and org_id={self.org_id}")

    def _get_label_hrefs(self, pce: PolicyComputeEngine) -> List[str]:
        """Retrieves HREFs for configured label key:value pairs"""
        label_hrefs = []
        kv_pairs = parse_label_scope(self.params.quarantine_labels)

        for k, v in kv_pairs.items():
            label_href = None
            labels = pce.labels.get(params={"key": k, "value": v})
            for label in labels:
                # verify the value since the API default is fuzzy matching
                if label.value == v:
                    label_href = label.href
            if not label_href:
                raise Exception(f"failed to find label with key {k} and value {v}")
            label_hrefs.append(label_href)

        return label_hrefs

    @property
    def service(self) -> client.Service:
        if not self._service:
            self._service = client.connect(token=self.session_key, owner=self.user)
        return self._service

    @property
    def params(self) -> IllumioInputParameters:
        if not self._params:
            input_name, input_conf = self._get_illumio_input_stanza()
            self._params = IllumioInputParameters(name=input_name, **input_conf)
            self._params.api_secret = get_password(self.service, self._params.api_secret_name)
        return self._params


if __name__ == "__main__":
    exit_code = 0
    action = None

    try:
        action = IllumioQuarantineAction(sys.stdin.read(), logger, QUARANTINE_ACTION_NAME)
        if not action.session_key:
            raise Exception("no Splunk session key found")

        # process the action results file and run for each result
        with gzip.open(action.results_file, "rb") as fh:
            textfile = codecs.getreader("utf-8")(fh)
            for num, result in enumerate(csv.DictReader(textfile)):
                # set the result ID default to the index in case it's absent
                result.setdefault("rid", str(num))
                action.run(result)
    except Exception as e:
        exit_code = 1
        msg = f"Failed to run {action.action_name} action: {str(e)}"

        if action:
            action.message(msg, status=FAILURE_STATUS, level=logging.ERROR)
            action.addevent(msg, sourcetype=QUARANTINE_ACTION_SOURCETYPE)
    finally:
        action and action.writeevents(index=action.params.index, source=action.action_name)
        sys.exit(exit_code)
