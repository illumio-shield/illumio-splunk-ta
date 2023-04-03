# -*- coding: utf-8 -*-

"""This module provides the modular input for the Illumio TA.

The input accesses the Illumio API and retrieves data from the PCE.

Copyright:
    © 2023 Illumio
License:
    Apache2, see LICENSE for more details.
"""
from __future__ import print_function
from __future__ import absolute_import

import sys
import xml.dom.minidom
import xml.sax.saxutils
import json
import base64
import re
from threading import Thread
import splunk.search as splunk_search
from splunk.clilib import cli_common as cli

import requests
import splunk.rest
import splunk.version as ver

version = float(re.search(r"(\d+.\d+)", ver.__version__).group(1))

try:
    if version >= 6.4:
        from splunk.clilib.bundle_paths import make_splunkhome_path
    else:
        from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
except ImportError:
    sys.exit(3)

sys.path.append(make_splunkhome_path(["etc", "apps", "TA-Illumio", "bin", "lib"]))
from future import standard_library
from builtins import str
from builtins import object
standard_library.install_aliases()
import urllib.request
import urllib.parse
import urllib.error
from IllumioUtil import get_logger, writeconf
from IllumioUtil import store_password
from IllumioUtil import get_credentials
from IllumioUtil import app_name
from IllumioUtil import resource
from IllumioUtil import check_label_exists
from IllumioUtil import is_ip
from IllumioUtil import is_hostname
from get_data import get_label, get_workload, print_xml_stream, get_pce_health, get_ip_lists, get_services

logger = get_logger("Illumio_MODINPUT")


class Illumio(object):
    """Illumio Modular Input."""

    session_key = ""
    mod_input_name = ""
    api_secret = ""
    api_key = ""
    stanza_name = ""
    pce_url = ""
    cert_path = ""
    enable_data_collection = 0
    qurantine_label = ""
    flag = {"enabled": 1, "disabled": 0, "1": 1, "0": 0}
    config = {}
    hostname = ""
    org_id = 1

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


SCHEME = r"""<scheme>
    <title>Illumio</title>
    <description>Enable data inputs for splunk add-on for Illumio</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>xml</streaming_mode>

    <endpoint>
        <args>
            <arg name="name">
                <title>Name</title>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg>
            <arg name="pce_url">
                <title>Supercluster Leader / PCE URL</title>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
                <validation>
                    validate(match(pce_url, '^(https://)\S+'), "PCE URL: PCE URL must begin with 'https://'")
                </validation>
            </arg>
            <arg name="api_key_id">
                <title>API Authentication Username</title>
                <description>e.g. 'api_1234567890'</description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg>
            <arg name="api_secret">
                <title>API Secret</title>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg>
            <arg name="port_number">
                <title>Port Number for syslogs (TCP)</title>
                <description>Only required when receiving syslog directly. Not required when getting syslog from S3. Example value: 514</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="time_interval_port">
                <title>Port Scan configuration: scan interval in seconds</title>
                <description>Interval during which the Port Scan Threshold is exceeded</description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
                <validation>
                    validate(is_nonneg_int(time_interval_port), "Time interval for syslog port scan: Time Interval must be non negative integer.")
                </validation>
            </arg>
            <arg name="cnt_port_scan">
                <title>Port Scan Configuration: Unique ports threshold</title>
                <description>Minimum number of ports scanned by a port-scan</description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
                <validation>
                    validate(is_nonneg_int(cnt_port_scan), "Count for port scan: must be non negative integer.")
                </validation>
            </arg>
            <arg name="self_signed_cert_path">
                <title>Certificate Path</title>
                <description>Path for the custom root certificate</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="qurantine_label">
                <title>Labels to quarantine workloads</title>
                <description>Comma Separated list of three labels of type app, location and environment.</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
                <validation>
                    validate(match(qurantine_label, '(\S+,\S+,\S+)'), "Enter three labels of type app, env and loc")
                </validation>
            </arg>
            <arg name="allowed_ip">
                <title>Comma Separated list of Source IPs, which will be ignored in Port scans</title>
                <description>Port scans from these Source IPs are ignored</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="private_ip">
                <title>(This field is removed from UI but keeping it here to avoid error logs on upgrade) Private IP address of Illumio Nodes</title>
                <description>Comma Separated IP address of all the nodes managed by this PCE instance.</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="hostname">
                <title>Hostnames of Illumio Nodes</title>
                <description>Comma Separated Hostnames of all the nodes managed by this PCE instance.</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="enable_data_collection">
                <title>Data Collection</title>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="org_id">
                <title>Organization ID</title>
                <description>This Org-ID will be used for making REST API calls to PCE.</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
                <validation>
                    validate(is_nonneg_int(org_id), "Organization ID: Must be non-negative integer.")
                </validation>
            </arg>
        </args>
    </endpoint>
</scheme>
"""     # noqa: E501


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


def validate_arguments():
    """
    Validate different input arguments of Modular Input page.

    If the value is invalid, appropriate message is displayed on screen.
    """
    val_data = get_validation_data()

    api_key_id = val_data.get("api_key_id", "")
    api_secret = val_data.get("api_secret", "")
    pce_url = val_data.get("pce_url", "")
    session_key = val_data.get("session_key", "")
    protocol = val_data.get("protocol", "").lower()
    port_number = val_data.get("port_number", "")
    mod_input_name = val_data.get("stanza", "")
    cert_path = val_data.get("self_signed_cert_path", "")
    time_interval_port = val_data.get("time_interval_port", "")
    cnt_port_scan = val_data.get("cnt_port_scan", "")
    interval = val_data.get("interval", "")
    qurantine_label = val_data.get("qurantine_label", "")
    hostname = val_data.get("hostname", "")
    org_id = int(val_data.get("org_id", 1))
    allowed_ip = val_data.get("allowed_ip", "")

    stanza = protocol + "://" + str(port_number)

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
            port_status = syslog_port_status(protocol, port_number, mod_input_name, session_key)

            validate_port_status(port_status, protocol, port_number, session_key)

            if port_status == 0:
                inputdata = {"index": [val_data.get("index", "")],
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
        validate_hostname(hostname, pce_url, session_key)


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
    if len(sys.argv) > 1:
        if sys.argv[1] == "--scheme":
            do_scheme()
        elif sys.argv[1] == "--validate-arguments":
            validate_arguments()
    else:
        run_script()

    sys.exit(0)
