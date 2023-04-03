from future import standard_library
standard_library.install_aliases()

from builtins import str
from logging.handlers import RotatingFileHandler

import logging
import os
import urllib.request
import urllib.parse
import urllib.error
import splunk.entity as entity
import splunk.rest
import splunk.version as ver
import re
import sys
import base64
import requests
import json

version = float(re.search(r"(\d+.\d+)", ver.__version__).group(1))

try:
    if version >= 6.4:
        from splunk.clilib.bundle_paths import make_splunkhome_path
    else:
        from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
except ImportError:
    sys.exit(3)


resource = {
    "orgs": "/orgs/",
    "api_version": "/api/v2",
    "label": "/labels/",
    "workload": "/workloads/",
    "ip_lists": "/sec_policy/draft/ip_lists",
    "services": "/sec_policy/draft/services",
    "pce_health": "/health",
    "product_version": "/product_version"

}

app_name = __file__.split(os.sep)[-3]


def get_logger(logger_id, file_name='ta-illumio.log'):
    """Return logger."""
    log_path = make_splunkhome_path(["var", "log", app_name])

    maxbytes = 2000000

    if not os.path.isdir(log_path):
        os.makedirs(log_path)

    handler = RotatingFileHandler(os.path.join(log_path, file_name), maxBytes=maxbytes, backupCount=20)

    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger = logging.getLogger(logger_id)
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger


logger = get_logger("ILLUMIOUTIL")


def get_credentials(user_name, session_key):
    """Return Illumio Credentials."""
    myapp = app_name
    try:
        # list all credentials
        entities = entity.getEntities(["admin", "passwords"], search=myapp, namespace=myapp, owner="nobody",
                                      sessionKey=session_key)
    except Exception as e:
        logger.error("TA Illumio Error: Could not get %s credentials from splunk : %s" % (myapp, str(e)))

    # return first set of credentials
    username = ""
    password = ""
    for _, value in list(entities.items()):
        if str(value["eai:acl"]["app"]) == myapp and (user_name and value.get("username", "") == user_name):
            username = value["username"]
            password = value["clear_password"]
            break

    return username, password


def store_password(user_name, password, session_key):
    """
    Store password using Splunk's /storage/passwords endpoint.

    :param user_name:  Name of the user
    :param password:  Password
    :param session_key:  Session Key
    :return:
    """
    user, old_password = get_credentials(user_name, session_key)
    '''
    Store password into passwords.conf file. Following are different scenarios
    1. Enters credentials for first time, use REST call to store it in passwords.conf
    2. Updates password. Use REST call to update existing password.
    3. Updates Username. Delete existing User entry and insert new entry.
    '''

    if old_password and user == user_name:
        postargs = {
            "password": password
        }
        user_name = user_name.replace(":", r"\:")
        realm = urllib.parse.quote(app_name + ":" + user_name + ":", safe='')
        r = splunk.rest.simpleRequest(
            "/servicesNS/nobody/" + app_name + "/storage/passwords/" + realm + "?output_mode=json",
            session_key, postargs=postargs, method='POST')

        if not (200 <= int(r[0]["status"]) <= 300):
            logger.error("Unable to update password")
            raise Exception

    else:
        logger.debug("Password not found")
        postargs = {
            "name": user_name,
            "password": password,
            "realm": app_name
        }
        r = splunk.rest.simpleRequest("/servicesNS/nobody/" + app_name + "/storage/passwords/?output_mode=json",
                                      session_key, postargs=postargs, method='POST')

        if not (200 <= int(r[0]["status"]) <= 300):
            logger.error("Unable to create password")
            raise Exception
    '''
        Remove AUTHKEY from custom configuration.
    '''


def writeconf(app_name, session_key, conf_name, stanza_name, settings_dict):
    """
    Write configuration file using Splunk's REST endpoints.

    :param app_name:  Name of the app under which the file will be written
    :param session_key: Session key to make REST call.
    :param conf_name: Name of the configuration file. i.e For illumio.conf, pass illumio
    :param stanza_name: Stanza name.
    :param settings_dict: Values in form of key value pairs.
    :return:
    """
    import splunk.bundle as bundle

    # always save things to SOME app context.
    app = app_name
    user = "nobody"

    try:
        conf_obj = bundle.getConf(
            conf_name, sessionKey=session_key, namespace=app, owner=user, overwriteStanzas=True)
    except splunk.ResourceNotFound:
        conf_obj = bundle.createConf(conf_name, sessionKey=session_key, namespace=app, owner=user)

    conf_obj.beginBatch()
    for k, v in list(settings_dict.items()):
        if isinstance(v, list):
            conf_obj[stanza_name][k] = str.join(",", v)
        else:
            conf_obj[stanza_name][k] = v
    conf_obj.commitBatch()


def check_label_exists(url, label, type, api_key, secret, org_id=1):
    """
    Use REST API to verify if the label exist.

    :param url: PCE URL
    :param label: Label
    :param type: Label type
    :param api_key: api key
    :param secret: secret
    :return:
    """
    try:
        auth_str = "Basic " + base64.b64encode(('%s:%s' % (api_key, secret)).encode()).decode().replace('\n', '')
        headers = {"Authorization": auth_str, "Accept": "application/json", 'Content-Type': 'application/json'}

        url = url + resource.get("api_version", "") + resource.get("orgs", "") + str(org_id) + resource["label"] \
            + "?value=" + label + "&key=" + type + ""
        r = requests.get(url, headers=headers)

        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            logger.error("Illumio Error: Error while checking label with REST API: " + str(e))

        if len(json.loads(r.content)):
            return json.loads(r.content)[0]["href"]

    except Exception:
        logger.exception("Exception in checking label with REST API")

    return ""


def is_ip(ip_str):
    """
    Validate if the provided value is ipv4 or not.

    :param ip_str: input value
    :return: True/False
    """
    ip_rex = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'   # noqa: E501

    m = re.match(ip_rex, ip_str)
    if m is None:
        return False
    else:
        return True


def is_hostname(hostname_str):
    """
    Validate if the provided value is valid hostname or not.

    :param hostname_str: input value
    :return: True/False
    """
    hostname_str.strip()

    if len(hostname_str) > 255:
        return False

    hostname_regex = r'^(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])$' if '.' in hostname_str else r'^(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,253}[a-zA-Z0-9])$'     # noqa: E501

    for host_name in hostname_str.split("."):
        match_hostname = re.match(hostname_regex, host_name)
        if match_hostname is None:
            return False

    return True
