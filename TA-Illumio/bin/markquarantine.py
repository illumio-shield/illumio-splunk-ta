# -*- coding: utf-8 -*-

"""This module provides a ModularAction for quarantining workloads in the PCE.

Copyright:
    © 2023 Illumio
License:
    Apache2, see LICENSE for more details.
"""
from __future__ import absolute_import

import sys
import os
sys.path.append(os.path.abspath(os.path.join(__file__, '..', 'lib')))

from future import standard_library
standard_library.install_aliases()
from builtins import str
import base64
import csv
import codecs
import gzip
import requests
import json
import re
import logging
import splunk
import splunk.version as ver
import splunk.search as splunkSearch
from splunk.clilib import cli_common as cli

from IllumioUtil import get_logger, get_credentials
app_name = __file__.split(os.sep)[-3]
version = float(re.search(r"(\d+.\d+)", ver.__version__).group(1))

# Importing the cim_actions.py library
# A.  Import make_splunkhome_path
# B.  Append your library path to sys.path
# C.  Import ModularAction from cim_actions

try:
    if version >= 6.4:
        from splunk.clilib.bundle_paths import make_splunkhome_path
    else:
        from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
except ImportError:
    sys.exit(3)

sys.path.append(make_splunkhome_path(["etc", "apps", app_name, "bin", "lib"]))
from cim_actions import ModularAction

logger = get_logger("ILLUMIOALERT", "ta_illumio_mark_quarantine_alert.log")
logger1 = ModularAction.setup_logger('markquarantine_modalert')


class IllumioAction(ModularAction):
    """Illumio alert action for marking quarantine."""

    def handle_response(self, workload_uuid, fqdn):
        """Handle Response."""
        response = quarantine_workload(workload_uuid, fqdn, self.session_key)
        if response == "false":
            self.message('Quarantine Workload was unsuccessful', status='failure')
            self.addevent("Quarantine Workload was unsuccessful status=2", sourcetype="markquarantineResponse")

        elif response == "noLabelFound":
            self.message('Quarantine Workload was unsuccessful, Labels Configuration not found', status='failure')
            self.addevent(
                "Quarantine Workload was unsuccessful, Labels Configuration not found status=2",
                sourcetype="markquarantineResponse")

        elif response == "noSetupFound":
            self.message(
                'Illumio credentials not found for ' + str(fqdn) + ', please complete Illumio setup',
                status='failure')
            self.addevent(
                "Illumio credentials not found for " + str(fqdn) + ", please complete Illumio setup status=2",
                sourcetype="markquarantineResponse")

        elif response.status_code == 201 or response.status_code == 200:
            message = json.loads(response.text)
            if message[0]["status"] == "updated":
                self.message('Quarantine workload was successful', status='success')
                self.addevent(
                    response.text + " status=" + str(response.status_code),
                    sourcetype="markquarantineResponse")
            else:
                self.message('Quarantine Workload was unsuccessful', status='failure')
                self.addevent(
                    response.text + " status=" + str(response.status_code),
                    sourcetype="markquarantineResponse")

        else:
            self.message('Quarantine Workload was unsuccessful', status='failure')
            self.addevent(response.text + " status=" + str(response.status_code), sourcetype="markquarantineResponse")

    def dowork(self):
        """Actual processing of marking quarantine."""
        try:
            capability = None
            workload_uuid = self.configuration.get("workload_uuid")
            fqdn = ""
            fqdn = self.configuration.get("fqdn")

            search_capability = "| rest splunk_server=local /services/authentication/current-context | eval show_quarantine=if(roles=\"illumio_quarantine_workload\",1,0) | table show_quarantine"    # noqa: E501

            result = splunkSearch.searchOne(
                search_capability, sessionKey=self.session_key, namespace=app_name, owner='nobody')

            if not result:
                self.addevent(
                    'Required capability not assigned, Quarantine Workload was unsuccessful',
                    status='failure')
                self.addevent(
                    "Required capability not assigned, Quarantine Workload was unsuccessful status=2",
                    sourcetype="markquarantineResponse")
                return 0

            logger.info("Result of capability check:::" + str(list(result.values())[0]))
            if str(list(result.values())[0]) == "0":
                self.message(
                    'Required capability not assigned, Quarantine Workload was unsuccessful',
                    status='failure')
                self.addevent(
                    "Required capability not assigned, Quarantine Workload was unsuccessful status=2",
                    sourcetype="markquarantineResponse")
            else:
                capability = True

            if capability and workload_uuid and fqdn:
                self.handle_response(workload_uuid, fqdn)

            else:
                self.message(
                    'Quarantine Workload was unsuccessful, workload_uuid or pce_fqdn parameter not found',
                    status='failure')
                self.addevent(
                    "Quarantine Workload was unsuccessful, workload_uuid or pce_fqdn parameter not found status=2",
                    sourcetype="markquarantineResponse")

        except Exception as e:
            logger.exception("Error in MarkQuarantine action")
            self.message('Quarantine Workload was unsuccessful', status='failure')
            self.addevent(
                "Quarantine Workload was unsuccessful exception=" + str(e) + " status=2",
                sourcetype="markquarantineResponse")


def set_labels(labels, labels_list, app, env, loc, role):
    """Set labels."""
    type_label = []
    for label in labels:
        href = str(label["href"])
        if str(label["type"]) == "app" and len(app) > 1:
            type_label.append("app:" + app[1] + ":" + app[0])
            href = app[0]

        elif str(label["type"]) == "loc" and len(loc) > 1:
            type_label.append("loc:" + loc[1] + ":" + loc[0])
            href = loc[0]

        elif str(label["type"]) == "env" and len(env) > 1:
            type_label.append("env:" + env[1] + ":" + env[0])
            href = env[0]

        labels_list.append({"href": href})

    if len(app) > 1 and {"href": app[0]} not in labels_list:
        type_label.append("app:" + app[1] + ":" + app[0])
        labels_list.append({"href": app[0]})

    if len(loc) > 1 and {"href": loc[0]} not in labels_list:
        type_label.append("loc:" + loc[1] + ":" + loc[0])
        labels_list.append({"href": loc[0]})

    if len(env) > 1 and {"href": env[0]} not in labels_list:
        type_label.append("env:" + env[1] + ":" + env[0])
        labels_list.append({"href": env[0]})
    return type_label, labels_list


def request_quarantine(cred_list, workload_uuid, labels_list, type_label, session_key):
    """Send requests for marking quarantine."""
    pce_url, org_id, api_key_id, api_secret = cred_list[0], cred_list[1], cred_list[2], cred_list[3]
    if pce_url:
        url = pce_url + "/api/v2/orgs/" + str(org_id) + "/workloads/bulk_update"
        auth = "Basic " + base64.b64encode(('%s:%s' % (api_key_id, api_secret)).encode()).decode().replace('\n', '')
        headers = {"Authorization": auth, "Content-Type": "application/json", "Accept": "text/plain"}
        if not workload_uuid.startswith("/orgs/" + str(org_id) + "/workloads/"):
            workload_uuid = "/orgs/" + str(org_id) + "/workloads/" + workload_uuid

        data = [{"href": workload_uuid, "labels": labels_list}]

        try:
            response = requests.put(url, headers=headers, data=json.dumps(data))
            response.raise_for_status()
            if response.status_code == 201 or response.status_code == 200:
                message = json.loads(response.text)
                if message[0]["status"] == "updated":
                    type_label_list = ",".join(type_label)
                    if workload_uuid.startswith("/orgs/" + str(org_id) + "/workloads/"):
                        workload_uuid = workload_uuid.replace("/orgs/" + str(org_id) + "/workloads/", "")
                    query = '| makeresults | eval type_label=split("' + type_label_list + '",",") | mvexpand type_label | eval type_label=split(type_label,":") | eval label = mvindex(type_label,1) | eval type=mvindex(type_label,0) | eval href=mvindex(type_label,2) | eval type_label=mvjoin(mvindex(type_label,0,1),":") | eval workload_uuid = "' + workload_uuid + '" | lookup illumio_workload_mapping_lookup workload_uuid OUTPUT hostname | eval hostname=mvindex(hostname,0) | table hostname href label type type_label workload_uuid | eval key=workload_uuid+"-"+type | outputlookup append=T illumio_workload_mapping_lookup key_field=key'     # noqa: E501
                    splunkSearch.searchAll(query, sessionKey=session_key, namespace=app_name, owner='nobody')
            return response
        except Exception as e:
            logger.exception("Error in quarantine workload: " + str(e))
            return "false"


'''
    This method is used to update workload in Illumio. It takes one arguments which is required:
    @workload_uuid: Workload UUID, its mandatory parameter.
'''


def quarantine_workload(workload_uuid, fqdn, session_key):
    """Quarantine the given workload."""
    try:
        rest_end_point = "/services/data/inputs/illumio/?output_mode=json"
        illumio_modinput = splunk.rest.simpleRequest(rest_end_point, sessionKey=session_key, raiseAllErrors=True)
        illumio_modinput = json.loads(illumio_modinput[1])
        inputs = illumio_modinput["entry"]
        url = "https://" + str(fqdn)
        org_id = 1
        if len(inputs) == 0:
            return "noSetupFound"

        pce_url = None
        for data in inputs:
            if url in data["content"]["pce_url"]:
                pce_url = data["content"]["pce_url"]
                org_id = data["content"].get("org_id", 1)
                modinput_name = data["name"]
                _, api_key_id = get_credentials(modinput_name + "_key", session_key)
                _, api_secret = get_credentials(modinput_name + "_secret", session_key)
                break

        if not pce_url:
            return "noSetupFound"

    except Exception:
        logger.exception("Error while fetching details for org")
        return "noSetupFound"

    labels = splunkSearch.searchAll('| inputlookup illumio_workload_mapping_lookup | search workload_uuid="%s" hostname = "*" | dedup type | table href type' % workload_uuid, sessionKey=session_key, namespace=app_name, owner='nobody')      # noqa: E501
    labels_list = []

    try:
        conf_value = cli.getConfStanza("illumio", pce_url)
        app = conf_value.get("app", "").split(":")
        env = conf_value.get("env", "").split(":")
        loc = conf_value.get("loc", "").split(":")
        role = conf_value.get("role", "").split(":")
        if len(app) == 1 and len(env) == 1 and len(loc) == 1 and len(role) == 1:
            logger.error('Labels Configuration not found.')
            return "noLabelFound"

    except Exception:
        logger.exception('Labels Configuration not found.')
        return "noLabelFound"

    type_label, labels_list = set_labels(labels, labels_list, app, env, loc, role)

    response = request_quarantine(
        [pce_url, org_id, api_key_id, api_secret],
        workload_uuid, labels_list,
        type_label, session_key)
    return response


if __name__ == '__main__':
    modaction = None
    try:
        modaction = IllumioAction(sys.stdin.read(), logger1, 'markquarantine')
        if modaction.session_key:
            '''
            Process the result set by opening results_file with gzip
            '''
            with gzip.open(modaction.results_file, 'rb') as fh:
                '''
                ## Iterate the result set using a dictionary reader
                ## We also use enumerate which provides "num" which
                ## can be used as the result ID (rid)
                '''
                textfile = codecs.getreader("utf-8")(fh)
                for num, result in enumerate(csv.DictReader(textfile)):
                    result.setdefault('rid', str(num))
                    modaction.update(result)
                    modaction.invoke()
                    modaction.dowork()

        else:
            modaction.message("Can not execute this script outside Splunk", status='failure', level=logging.CRITICAL)
            modaction.addevent(
                "Can not execute this script outside Splunk status=2",
                sourcetype="markquarantineResponse")
            modaction.writeevents(index="main", source='markquarantine')
            sys.exit(3)

        modaction.writeevents(index="main", source='markquarantine')

    except Exception as e:
        # adding additional logging since adhoc search invocations do not write to stderr
        try:
            logger.exception("Error in main")
            modaction.message(e, status='failure', level=logging.CRITICAL)
        except Exception:
            logger.critical(e)
        logger.exception("ERROR Unexpected error")
        sys.exit(3)
