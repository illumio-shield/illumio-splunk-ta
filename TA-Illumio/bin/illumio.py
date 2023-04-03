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
import xml.dom.minidom
import xml.sax.saxutils
import json
import re
from threading import Thread
from urllib.parse import urlparse

from illumio import PolicyComputeEngine

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import splunk.rest
from splunk.clilib import cli_common as cli

import splunklib.client as client # import Service, StoragePassword
from splunklib.modularinput import (
    Script,
    Scheme,
    Argument,
    EventWriter,
    Event
)

import urllib.request
import urllib.parse
import urllib.error


class Illumio(Script):
    """Illumio Modular Input."""

    def get_scheme(self):
        scheme = Scheme("Illumio")
        scheme.description = "Enable data inputs for splunk add-on for Illumio"
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True

        name_arg = Argument("name")
        name_arg.title = "Name"
        name_arg.required_on_create = True
        name_arg.required_on_edit = True
        scheme.add_argument(name_arg)

        pce_url_arg = Argument("pce_url")
        pce_url_arg.title = "Supercluster Leader / PCE URL"
        pce_url_arg.required_on_create = True
        pce_url_arg.required_on_edit = True
        scheme.add_argument(pce_url_arg)

        org_id_arg = Argument("org_id")
        org_id_arg.title = "Organization ID"
        org_id_arg.description = "Organization ID. Defaults to 1"
        org_id_arg.required_on_create = False
        org_id_arg.required_on_edit = False
        org_id_arg.data_type = Argument.data_type_number
        scheme.add_argument(org_id_arg)

        api_key_id_arg = Argument("api_key_id")
        api_key_id_arg.title = "API Authentication Username"
        api_key_id_arg.description = "Illumio API key username. e.g. 'api_1234567890'"
        api_key_id_arg.required_on_create = True
        api_key_id_arg.required_on_edit = True
        scheme.add_argument(api_key_id_arg)

        api_secret_arg = Argument("api_secret")
        api_secret_arg.title = "API Authentication Secret"
        api_secret_arg.description = "Illumio API key secret"
        api_secret_arg.required_on_create = True
        api_secret_arg.required_on_edit = True
        scheme.add_argument(api_secret_arg)

        port_number_arg = Argument("port_number")
        port_number_arg.title = "Port Number for syslogs (TCP)"
        port_number_arg.description = "Only required when receiving syslog directly. Not required when getting syslog from S3. Example value: 514"
        port_number_arg.required_on_create = False
        port_number_arg.required_on_edit = False
        port_number_arg.data_type = Argument.data_type_number
        scheme.add_argument(port_number_arg)

        time_interval_port_arg = Argument("time_interval_port")
        time_interval_port_arg.title = "Port Scan configuration: scan interval in seconds"
        time_interval_port_arg.description = "Interval during which the Port Scan Threshold is exceeded"
        time_interval_port_arg.required_on_create = False
        time_interval_port_arg.required_on_edit = False
        time_interval_port_arg.data_type = Argument.data_type_number
        scheme.add_argument(time_interval_port_arg)

        cnt_port_scan_arg = Argument("cnt_port_scan")
        cnt_port_scan_arg.title = "Port Scan Configuration: Unique ports threshold"
        cnt_port_scan_arg.description = "Minimum number of ports scanned by a port-scan"
        cnt_port_scan_arg.required_on_create = False
        cnt_port_scan_arg.required_on_edit = False
        cnt_port_scan_arg.data_type = Argument.data_type_number
        scheme.add_argument(cnt_port_scan_arg)

        allowed_ip_arg = Argument("allowed_ips")
        allowed_ip_arg.title = "Allowed IPs"
        allowed_ip_arg.description = "Comma-separated list of Source IPs to be ignored in port scans"
        allowed_ip_arg.required_on_create = False
        allowed_ip_arg.required_on_edit = False
        scheme.add_argument(allowed_ip_arg)

        self_signed_cert_path_arg = Argument("self_signed_cert_path")
        self_signed_cert_path_arg.title = "Self Signed Certificate Path"
        self_signed_cert_path_arg.description = "Path for the custom root certificate. e.g. '/opt/splunk/etc/apps/TA-Illumio/bin/cert.pem'"
        self_signed_cert_path_arg.required_on_create = False
        self_signed_cert_path_arg.required_on_edit = False
        scheme.add_argument(self_signed_cert_path_arg)

        enable_data_collection_arg = Argument("enable_data_collection")
        enable_data_collection_arg.title = "Enable Data Collection"
        enable_data_collection_arg.description = "Enable data collection for Illumio"
        enable_data_collection_arg.required_on_create = False
        enable_data_collection_arg.required_on_edit = False
        enable_data_collection_arg.data_type = Argument.data_type_boolean
        scheme.add_argument(enable_data_collection_arg)

        quarantine_label_arg = Argument("quarantine_labels")
        quarantine_label_arg.title = "Quarantine Labels"
        quarantine_label_arg.description = "Comma Separated list of label names to define workload quarantine"
        quarantine_label_arg.required_on_create = False
        quarantine_label_arg.required_on_edit = False
        scheme.add_argument(quarantine_label_arg)

        return scheme

    def validate_input(self, definition) -> None:
        """
        Validate arguments of the Illumio modular input.

        Args:
            definition: The validation definition containing input params.

        Raises:
            ValueError: If any input params are invalid.
        """
        # TODO: log definition.parameters and definition.metadata
        session_key = definition.parameters["session_key"]
        pce_url = definition.parameters["pce_url"]
        org_id = definition.parameters["org_id"]
        api_key_id = definition.parameters["api_key_id"]
        # FIXME: retrieve the secret via Splunk API
        api_secret = definition.parameters["api_secret"]
        port_number = definition.parameters["port_number"]
        mod_input_name = definition.parameters["stanza"]
        cert_path = definition.parameters["self_signed_cert_path"]
        time_interval_port = definition.parameters["time_interval_port"]
        cnt_port_scan = definition.parameters["cnt_port_scan"]
        allowed_ip = definition.parameters["allowed_ips"]

        parsed = urlparse(pce_url)
        pce_port = parsed.port or 443

        org_id = int(org_id) if org_id else 1

        if org_id <= 0:
            raise ValueError("Invalid Organization ID: must be non-negative integer.")

        # FIXME: do we need to store the secret here?
        storage_passwords = self.service.storage_passwords
        self.service
        storage_password = storage_passwords.create(api_secret, "user1", "realm1")

        # TODO: support configurable retry params
        pce = PolicyComputeEngine(pce_url, port=pce_port, org_id=org_id)
        pce.set_credentials(api_key_id, api_secret)
        # TODO: support proxy configuration
        pce.set_tls_settings(verify=cert_path or True)

        pce.must_connect()

        if port_number:
            port_check_regex = r'^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$'
            if not bool(re.search(port_check_regex, port_number)):
                raise ValueError("Port Number: Invalid port number.")

        if time_interval_port and int(time_interval_port) < 0:
            raise ValueError("Time interval for syslog port scan: Time Interval must be non negative integer.")

        if cnt_port_scan and int(cnt_port_scan) < 0:
            raise ValueError("Count for port scan: must be non negative integer.")

        # FIXME: refactor this syslog port status check
        port_status = syslog_port_status(port_number, mod_input_name, session_key)

        if port_status == 2:
            raise ValueError(str(port_number) + " TCP is not available as the port already in use.")

        # TODO: test interval validation

        if allowed_ip:
            import ipaddress
            for ip in allowed_ip.split(","):
                ipaddress.ip_address(ip.strip())

        # TODO: reimplement quarantine label validation for MT4L
        # quarantine_labels = definition.parameters["quarantine_labels"]

    def stream_events(self, inputs, ew):
        # Splunk Enterprise calls the modular input,
        # streams XML describing the inputs to stdin,
        # and waits for XML on stdout describing events.
        pass

    def update_mod_inputs(self, config):
        """Update modular inputs."""
        path = urllib.parse.quote(self.mod_input_name, safe='')
        try:
            r = splunk.rest.simpleRequest("/data/inputs/illumio?search=" + path + "&output_mode=json",
                                          self.session_key, method='GET', raiseAllErrors=True)

            result_storage_password = json.loads(r[1])
            if (200 <= int(r[0]["status"]) < 300) and (len(result_storage_password["entry"]) > 0):
                for ele in result_storage_password["entry"]:
                    if ele["name"] == self.mod_input_name:
                        url = "/servicesNS/nobody/" + ele["acl"]["app"] + "/data/inputs/illumio/" + path

                        try:
                            interval = int(float(ele["content"]["interval"]))
                        except Exception:
                            interval = ele["content"]["interval"]
                        post_param = {
                            "api_secret": config["api_secret"],
                            "api_key_id": config["api_key_id"],
                            "cnt_port_scan": ele["content"]["cnt_port_scan"],
                            "pce_url": ele["content"]["pce_url"],
                            "interval": interval,
                            "time_interval_port": int(ele["content"]["time_interval_port"].split(".")[0])
                        }
                        r = splunk.rest.simpleRequest(
                            url, self.session_key,
                            postargs=post_param,
                            method='POST',
                            raiseAllErrors=True)

                        break

        except Exception:
            logger.exception("Error in updating modular inputs")
            raise Exception

    def print_ps_details(self):
        """Print ps details."""
        pce_url = self.pce_url
        port_scan = self.config.get("cnt_port_scan", "")
        interval = self.config.get("time_interval_port", "")
        allowed_ip = self.config.get("allowed_ip", "")
        res = {
            "pce_url": pce_url,
            "port_scan": port_scan,
            "interval": interval,
            "illumio_type": "illumio:pce:ps_details",
        }
        if allowed_ip:
            res["allowed_ip"] = allowed_ip
        res = json.dumps(res)
        print_xml_stream(res)


def syslog_port_status(port_number, mod_input_name, session_key):
    """Load syslog port status."""
    mod_input_name = mod_input_name.rstrip()

    url = "/data/inputs/tcp/raw/?search=" + str(port_number) + "&output_mode=json"

    try:
        r = splunk.rest.simpleRequest(
            url,
            sessionKey=session_key, method='GET', raiseAllErrors=True)
    except Exception:
        logger.exception("Unable to load all TCP endpoint in validate_arguments")
        raise Exception

    json_res = json.loads(r[1])

    entries = json_res.get("entry", "")

    for entry in entries:
        source = entry.get("content", "")
        if str(entry.get("name", "")) == str(port_number):
            if source.get("sourcetype", "") == "illumio:pce":
                return 1
            else:
                return 2
    return 0


def run_script():
    """Run script."""
    illumio = Illumio()

    # To ensure data collection is enabled only if chosen.
    if illumio.enable_data_collection == 1:
        illumio.print_ps_details()

        # FIXME: fix all this garbage
        supercluster_info = get_pce_health(arg)

        if len(supercluster_info[2]) > 0:
            last_index = arg[0].rindex(":")
            port_number = str(arg[0][last_index:])
            for index in range(len(supercluster_info[2])):
                supercluster_info[2][index] = "https://" + supercluster_info[2][index] + port_number
            supercluster_members = ",".join(supercluster_info[2])
            writeconf("TA-Illumio", arg[5], "supercluster_members", supercluster_info[1],
                      {"supercluster_members": supercluster_members})

        if supercluster_info[0]:
            try:
                conf_value = cli.getConfStanza("supercluster_members", supercluster_info[1])
                supercluster_info[2] = conf_value.get("supercluster_members", "")
            except Exception:
                logger.error("Illumio Error: {} stanza not found in supercluster_members.conf file.".format(
                    supercluster_info[1]))

        del arg[5]
        arg.extend(supercluster_info)

        sys.stdout.flush()

        t1 = Thread(target=get_label, args=(arg,))
        t2 = Thread(target=get_workload, args=(arg,))
        t3 = Thread(target=get_ip_lists, args=(arg,))
        t4 = Thread(target=get_services, args=(arg,))

        t1.start()
        t2.start()
        t3.start()
        t4.start()

        t1.join()
        t2.join()
        t3.join()
        t4.join()


if __name__ == '__main__':
    sys.exit(Illumio().run(sys.argv))
