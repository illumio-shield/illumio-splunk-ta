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
import base64
import re
from threading import Thread

import requests

import splunk.rest
import splunk.search as splunk_search
import splunk.version as ver
from splunk.clilib import cli_common as cli

from splunklib.modularinput import Script, Scheme, Argument, EventWriter, Event


version = float(re.search(r"(\d+.\d+)", ver.__version__).group(1))

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import urllib.request
import urllib.parse
import urllib.error

SCHEME = r"""<scheme>
    <title>Illumio</title>
    <description>Enable data inputs for splunk add-on for Illumio</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>xml</streaming_mode>

    <endpoint>
        <args>
        </args>
    </endpoint>
</scheme>
"""     # noqa: E501


class Illumio(Script):
    """Illumio Modular Input."""

    def __init__(self):
        """Initialize environment."""
        self.config = self.get_mod_input_configs()
        self.session_key = self.config.get("session_key", "")
        self.mod_input_name = self.config.get("name", "").split("://", 1)[1]
        self.api_secret = self.config.get("api_secret", "")
        self.api_key = self.config.get("api_key_id", "")
        self.stanza_name = self.config.get("name", "")
        self.pce_url = self.config.get("pce_url", "")
        self.cert_path = self.config.get("self_signed_cert_path", "")
        self.enable_data_collection = self.flag.get((self.config.get("enable_data_collection", "disabled").lower()), 0)
        self.qurantine_label = self.config.get("qurantine_label", "")
        self.config["protocol"] = self.config.get("protocol", "").lower()
        self.allowed_ip = self.config.get("allowed_ip", "")
        self.hostname = self.config.get("hostname", "")
        self.org_id = self.config.get("org_id", 1)

        if self.api_key and self.api_secret:

            store_password(self.mod_input_name + "_secret", self.config["api_secret"], self.session_key)
            store_password(self.mod_input_name + "_key", self.config["api_key_id"], self.session_key)

            self.config["api_key_id"] = ""
            self.config["api_secret"] = ""
            input_config = self.config
            self.update_mod_inputs(input_config)
        else:
            logger.debug("Scheduled Modular Input")
            self.config["api_secret"] = get_credentials(self.mod_input_name + "_secret", self.session_key)
            self.config["api_key_id"] = get_credentials(self.mod_input_name + "_key", self.session_key)
            self.api_secret = self.config["api_secret"][1]
            self.api_key = self.config["api_key_id"][1]

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
        pce_url_arg.validation = "validate(match(pce_url, '^(https://)\S+'), 'PCE URL: PCE URL must begin with ''https://''')"
        scheme.add_argument(pce_url_arg)

        org_id_arg = Argument("org_id")
        org_id_arg.title = "Organization ID"
        org_id_arg.description = "Organization ID"
        org_id_arg.required_on_create = False
        org_id_arg.required_on_edit = False
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
        api_secret_arg.data_type = Argument.data_type_password
        scheme.add_argument(api_secret_arg)

        port_number_arg = Argument("port_number")
        port_number_arg.title = "Port Number for syslogs (TCP)"
        port_number_arg.description = "Only required when receiving syslog directly. Not required when getting syslog from S3. Example value: 514"
        port_number_arg.required_on_create = False
        port_number_arg.required_on_edit = False

        time_interval_port_arg = Argument("time_interval_port")
        time_interval_port_arg.title = "Port Scan configuration: scan interval in seconds"
        time_interval_port_arg.description = "Interval during which the Port Scan Threshold is exceeded"
        time_interval_port_arg.required_on_create = False
        time_interval_port_arg.required_on_edit = False
        time_interval_port_arg.validation = "validate(is_nonneg_int(time_interval_port), 'Time interval for syslog port scan: Time Interval must be non negative integer.')"
        scheme.add_argument(time_interval_port_arg)

        cnt_port_scan_arg = Argument("cnt_port_scan")
        cnt_port_scan_arg.title = "Port Scan Configuration: Unique ports threshold"
        cnt_port_scan_arg.description = "Minimum number of ports scanned by a port-scan"
        cnt_port_scan_arg.required_on_create = False
        cnt_port_scan_arg.required_on_edit = False
        cnt_port_scan_arg.validation = "validate(is_nonneg_int(cnt_port_scan), 'Count for port scan: must be non negative integer.')"
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

        qurantine_label_arg = Argument("quarantine_labels")
        qurantine_label_arg.title = "Quarantine Labels"
        qurantine_label_arg.description = "Comma Separated list of label names to define workload quarantine"
        qurantine_label_arg.required_on_create = False
        qurantine_label_arg.required_on_edit = False
        scheme.add_argument(qurantine_label_arg)

        return scheme

    def validate_input(self, validation_definition):
        """
        Validate different input arguments of Modular Input page.

        If the value is invalid, appropriate message is displayed on screen.
        """
        session_key = validation_definition.parameters["session_key"]
        pce_url = validation_definition.parameters["pce_url"]
        org_id = int(validation_definition.parameters["org_id"])
        api_key_id = validation_definition.parameters["api_key_id"]
        api_secret = validation_definition.parameters["api_secret"]
        port_number = validation_definition.parameters["port_number"]
        mod_input_name = validation_definition.parameters["stanza"]
        cert_path = validation_definition.parameters["self_signed_cert_path"]
        time_interval_port = validation_definition.parameters["time_interval_port"]
        cnt_port_scan = validation_definition.parameters["cnt_port_scan"]
        interval = validation_definition.parameters["interval"]
        qurantine_label = validation_definition.parameters["quarantine_labels"]
        allowed_ip = validation_definition.parameters["allowed_ips"]

        syslog_protocol = "tcp"
        stanza = syslog_protocol + "://" + str(port_number)

        if api_key_id and api_secret:

            validate_pce_url(pce_url, session_key)
            validate_port_number(port_number, session_key)
            validate_time_interval_port(time_interval_port, session_key)
            validate_cnt_port_scan(cnt_port_scan, session_key)
            validate_org_id(org_id, session_key)
            validate_interval(interval, session_key)
            validate_allowed_ip(allowed_ip, session_key)

            validate_connection(pce_url, api_key_id, api_secret, cert_path, session_key)

            if port_number != "":
                port_status = syslog_port_status(syslog_protocol, port_number, mod_input_name, session_key)

                validate_port_status(port_status, syslog_protocol, port_number, session_key)

                if port_status == 0:
                    inputdata = {"index": [validation_definition.get("index", "")],
                                "sourcetype": ["illumio:pce"],
                                "source": ["syslog-" + mod_input_name],
                                "disabled": ["false"],
                                "name": stanza}

                    try:
                        splunk.rest.simpleRequest(
                            "/servicesNS/nobody/" + app_name + "/configs/conf-inputs",
                            session_key, postargs=inputdata, method='POST', raiseAllErrors=True)
                    except Exception:
                        logger.exception("Unable to create input")
                        raise Exception

                    try:
                        splunk.rest.simpleRequest(
                            "/admin/raw/_reload",
                            session_key, method='POST', raiseAllErrors=True)
                    except Exception:
                        logger.exception("Unable to reload TCP endpoint")

            validate_qurantine_label(qurantine_label, pce_url, api_key_id, api_secret, org_id, session_key)

    def stream_events(self, inputs, ew):
        # Splunk Enterprise calls the modular input,
        # streams XML describing the inputs to stdin,
        # and waits for XML on stdout describing events.
        pass

    @staticmethod
    def get_mod_input_configs():
        """Return modular input configs."""
        config = {}
        try:
            config_str = sys.stdin.read()
            doc = xml.dom.minidom.parseString(config_str)
            root = doc.documentElement
            config["session_key"] = root.getElementsByTagName("session_key")[0].firstChild.data
            conf_node = root.getElementsByTagName("configuration")[0]
            conf_node_flag = False
            stanza_flag = False
            param = {}
            if conf_node:
                stanza = conf_node.getElementsByTagName("stanza")[0]
                conf_node_flag = True
            if conf_node_flag and stanza:
                stanza_name = stanza.getAttribute("name")
                stanza_flag = True
            if stanza_flag and stanza_name:
                config["name"] = stanza_name
                params = stanza.getElementsByTagName("param")
            for param in params:
                param_name = param.getAttribute("name")
                logger.debug("XML: found param '%s'" % param_name)
                if param_name and param.firstChild and param.firstChild.nodeType == \
                        param.firstChild.TEXT_NODE:
                    data = param.firstChild.data
                    config[param_name] = data
                    if(param_name != "api_secret"):
                        logger.debug("XML: '%s' -> '%s'" % (param_name, data))

            checkpnt_node = root.getElementsByTagName("checkpoint_dir")[0]
            if checkpnt_node and checkpnt_node.firstChild and checkpnt_node.firstChild.nodeType == \
                    checkpnt_node.firstChild.TEXT_NODE:
                config["checkpoint_dir"] = checkpnt_node.firstChild.data

            if not config:
                raise Exception("Invalid configuration received from Splunk.")

                # just some validation: make sure these keys are present (required)
            config["protocol"] = "tcp"
            config["time_interval_port"] = config["time_interval_port"].split(".")[0]
            config["cnt_port_scan"] = config["cnt_port_scan"].split(".")[0]

        except Exception as e:
            raise Exception("Error getting Splunk configuration via STDIN: %s" % str(e))

        return config

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

    def rest_help(self):
        """Rest helper."""
        return [self.pce_url, self.api_key, self.api_secret, self.cert_path, self.org_id, self.session_key]

    def print_ps_details(self):
        """Print ps details."""
        pce_url = self.pce_url
        port_scan = self.config.get("cnt_port_scan", "")
        interval = self.config.get("time_interval_port", "")
        allowed_ip = self.config.get("allowed_ip", "")
        if allowed_ip:
            res = {
                "pce_url": pce_url,
                "port_scan": port_scan,
                "interval": interval,
                "illumio_type": "illumio:pce:ps_details",
                "allowed_ip": allowed_ip
            }
        else:
            res = {
                "pce_url": pce_url,
                "port_scan": port_scan,
                "interval": interval,
                "illumio_type": "illumio:pce:ps_details"
            }
        res = json.dumps(res)
        print_xml_stream(res)


def do_scheme():
    """Do scheme."""
    print(SCHEME)


def get_notification_message(message, session_key):
    """Get notification message."""
    postargs = {'severity': 'error', 'name': app_name,
                'value': app_name + ' modular input validation failed: ' + message
                }
    try:
        splunk.rest.simpleRequest('/services/messages', session_key,
                                  postargs=postargs)
    except Exception:
        logger.exception("Failed to give notification message")


def print_error(message, session_key):
    """Print error message."""
    get_notification_message(message, session_key)
    print("<error><message>%s</message></error>" % xml.sax.saxutils.escape(message))
    logger.error(message)
    sys.exit(1)


def syslog_port_status(protocol, port_number, mod_input_name, session_key):
    """Load syslog port status."""
    mod_input_name = mod_input_name.rstrip()

    url = "/data/inputs/tcp/raw/?search=" + str(port_number) + "&&output_mode=json"

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


def get_validation_data():
    """Fetch configuration parameters as passed by Splunk as XML when executing this Modular Input."""
    val_data = {}

    val_str = sys.stdin.read()

    doc = xml.dom.minidom.parseString(val_str)
    root = doc.documentElement
    val_data["session_key"] = root.getElementsByTagName("session_key")[0].firstChild.data
    item_node = root.getElementsByTagName("item")[0]

    if item_node:
        name = item_node.getAttribute("name")
        val_data["stanza"] = name

        params_node = item_node.getElementsByTagName("param")
        for param in params_node:
            name = param.getAttribute("name")
            logger.debug("Found param %s" % name)
            if name and param.firstChild and param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                val_data[name] = param.firstChild.data

    val_data["protocol"] = "tcp-ssl"
    val_data["time_interval_port"] = val_data["time_interval_port"].split(".")[0]
    val_data["cnt_port_scan"] = val_data["cnt_port_scan"].split(".")[0]

    return val_data


def validate_interval(interval, session_key):
    """Validate Interval."""
    try:
        interval = int(float(interval))
        if interval < 3600:
            print_error(
                "Interval: Enter a non negative interval greater than equal to 3600 seconds or a valid cron schedule",
                session_key)
    except Exception:
        logger.debug("Interval: An cron expression was entered")


def validate_pce_url(pce_url, session_key):
    """Validate PCE Url."""
    if not bool(re.search(r'^(https://)\S+', pce_url)):
        print_error("PCE URL: PCE URL must begin with 'https://'", session_key)


def validate_port_number(port_number, session_key):
    """Validate Port Number."""
    if port_number != "":
        port_check_regex = r'^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-3][0-9]|6553[0-5])$'
        if not bool(re.search(port_check_regex, port_number)):
            print_error("Port Number: Invalid port number", session_key)


def validate_time_interval_port(time_interval_port, session_key):
    """Validate Time Interval Port."""
    if int(time_interval_port) < 0:
        print_error("Time interval for syslog port scan: Time Interval must be non negative integer", session_key)


def validate_cnt_port_scan(cnt_port_scan, session_key):
    """Validate CNT Port Scan."""
    if int(cnt_port_scan) < 0:
        print_error("Count for port scan: must be non negative integer.", session_key)


def validate_port_status(port_status, protocol, port_number, session_key):
    """Validate Port Status."""
    if port_status == 2:
        err_msg = str(protocol) + ": " + str(port_number) + " is not available as it is already in use."
        print_error(err_msg, session_key)


def validate_connection(pce_url, api_key_id, api_secret, cert_path, session_key):
    """Validate the connection."""
    url = pce_url + resource.get("api_version", "") + resource.get("product_version", "")
    health_url = pce_url + resource.get("api_version", "")
    auth = "Basic " + base64.b64encode(('%s:%s' % (api_key_id, api_secret)).encode()).decode().replace('\n', '')
    headers = {"Authorization": auth, "Accept": "application/json"}

    if cert_path == "":
        cert_path = True

    try:
        r = requests.get(url, headers=headers, verify=cert_path, timeout=10)
        if r.status_code == 401:
            logger.debug(r.status_code)
            print_error("Authentication failed: API key id and/or API Secret were incorrect.", session_key)
        if r.status_code == 403:
            logger.debug(r.status_code)
            print_error(
                "Authorization failed: user is not authorized, the incorrect Organization ID parameter was used.",
                session_key)
        if r.status_code != 200:
            logger.debug(r.status_code)
            print_error("Connection Failed.", session_key)
        r = requests.get(health_url + resource.get("pce_health", ""), headers=headers, verify=cert_path)
        if len(r.content):
            events = json.loads(r.content)
            if events[0].get("type") == "member":
                logger.debug(
                    "Supercluster Leader / PCE URL: Please enter supercluster leader PCE URL "
                    "instead of supercluster member PCE URL.")
                print_error(
                    "Supercluster Leader / PCE URL: Please enter supercluster leader PCE URL "
                    "instead of supercluster member PCE URL.", session_key)
    except Exception as e:
        print_error("Illumio Error: Error while validating credentials " + str(e), session_key)


def validate_org_id(org_id, session_key):
    """Validate organization id."""
    if org_id < 0 and org_id % 1 != 0:
        print_error("Organization ID: Invalid organization ID, Only non-negative integer allowed.", session_key)


def validate_qurantine_label(qurantine_label, pce_url, api_key_id, api_secret, org_id, session_key):
    """Validate quarantine label."""
    try:

        """
            To validate if user has entered correct labels of type app, loc and env.
            It also adds this information into Illumio.conf file which is used for markQuarantine action.
        """
        if not qurantine_label:
            writeconf("TA-Illumio", session_key, "illumio", pce_url, {"app": "", "env": "", "loc": ""})
            return

        labels = qurantine_label.split(",")
        if len(labels) == 3:

            app_label = check_label_exists(pce_url, labels[0], "app", api_key_id, api_secret, org_id)
            if app_label:
                app_label = app_label + ":" + labels[0]
            else:
                print_error("First label should be of type app. ", session_key)

            env_label = check_label_exists(pce_url, labels[1], "env", api_key_id, api_secret, org_id)
            if env_label:
                env_label = env_label + ":" + labels[1]
            else:
                print_error("Second label should be of type env. ", session_key)

            loc_label = check_label_exists(pce_url, labels[2], "loc", api_key_id, api_secret, org_id)

            if loc_label:
                loc_label = loc_label + ":" + labels[2]
            else:
                print_error("Third label should be of type loc. ", session_key)

            if app_label and env_label and loc_label:
                writeconf(
                    "TA-Illumio",
                    session_key,
                    "illumio",
                    pce_url,
                    {"app": app_label, "env": env_label, "loc": loc_label})
        else:
            print_error("One label each of type app,env and loc are required. ", session_key)

    except Exception:
        logger.exception("Error in Validating Label")


def validate_hostname(hostname, pce_url, session_key):
    """Validate Hostname."""
    if hostname:
        try:
            hostname_list = hostname.split(",")
            for host_name in hostname_list:
                if not is_hostname(host_name):
                    print_error("Invalid value for Hostname", session_key)

            search_query = "| makeresults  | eval hostname=\"" + hostname + "\", fqdn=\"" + re.match(r"https?:\/\/([a-zA-Z0-9.\-_~]*):?", pce_url).group(1) + "\" | makemv delim=\",\" hostname | mvexpand hostname | append [| inputlookup illumio_host_details_lookup] | dedup fqdn hostname | eval _key = hostname +\"_\"+ fqdn | table _key hostname fqdn | outputlookup illumio_host_details_lookup"    # noqa: E501

            splunk_search.searchAll(
                search_query, earliest_time="-60m", latest_time="+5m", sessionKey=session_key,
                namespace="IllumioAppforSplunk")

        except Exception:
            logger.exception("Error in Validating Hostname")


def validate_allowed_ip(allowed_ip, session_key):
    """
    Validate allowed_ip field. If the value is not valid than error message is displayed.

    Arguments:
        allowed_ip {string} -- list of Allowed port scanner IP addresses
        session_key {type} -- Session Key
    """
    if allowed_ip:
        try:
            for ip in allowed_ip.strip().split(","):
                if not is_ip(ip):
                    print_error(
                        "Please enter comma separated valid Allowed port scanner Source IP addresses.",
                        session_key)
        except Exception:
            logger.exception("Error in Validating Allowed port scanner Source IP addresses")


def run_script():
    """Run script."""
    illumio = Illumio()

    # To ensure data collection is enabled only if chosen.
    if illumio.enable_data_collection == 1:
        illumio.print_ps_details()

        arg = illumio.rest_help()

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
