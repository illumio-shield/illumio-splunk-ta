from __future__ import print_function
from __future__ import absolute_import
from builtins import str
import json
import time
import requests
import base64
import re
import copy
from urllib.parse import urlparse
from IllumioUtil import get_logger
from IllumioUtil import resource
from splunk.clilib import cli_common as cli

logger = get_logger("Illumio_Get_Data")

RETRY_AFTER_IF_503 = 60   # In Seconds
MAX_RETRY_IF_503 = 5


def encode_xml_text(text):
    """Encode the given xml text."""
    text = text.replace("&", "&amp;")
    text = text.replace("\"", "&quot;")
    text = text.replace("'", "&apos;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace("\n", "")
    return text


def print_xml_stream(s):
    """Print xml stream."""
    print("<stream><event unbroken=\"1\"><data>%s</data><done/></event></stream>" % encode_xml_text(s))


def get_details(option, rest_help):
    """Get details from Illumio using API."""
    try:
        url = rest_help[0] + resource.get("api_version", "")
        api_key_id = rest_help[1]
        api_secret = rest_help[2]
        cert_path = rest_help[3]
        supercluster_members = rest_help[7].split(",") if len(rest_help[7]) > 0 else []
        remaining_members = copy.deepcopy(supercluster_members)
        is_member = 0

        # Submit Async Job Request & Get Retry-After and Polling URL location from Response
        autho = "Basic " + base64.b64encode(('%s:%s' % (api_key_id, api_secret)).encode()).decode().replace('\n', '')
        headers = {"Authorization": autho, "Accept": "application/json", "Content-Type": "application/json",
                   "Prefer": "respond-async"}

        if cert_path == "":
            cert_path = True

        try:
            r = requests.get(
                url + resource.get("orgs", "") + str(rest_help[4]) + resource.get(option, ""),
                headers=headers,
                verify=cert_path)
            r.raise_for_status()
        except (requests.HTTPError, requests.exceptions.ConnectionError) as e:
            logger.error("Illumio Error: Error while fetching data of " + str(option) + " Error: " + str(e))
            for member in supercluster_members:
                is_member = 1
                try:
                    logger.info("Illumio Info: Trying with another PCE member: " + str(member))
                    url = member.strip() + resource.get("api_version", "")
                    r = requests.get(url + resource.get("orgs", "")
                                     + str(rest_help[4]) + resource.get(option, ""), headers=headers, verify=cert_path)
                    r.raise_for_status()
                    break
                except (requests.HTTPError, requests.exceptions.ConnectionError) as e:
                    logger.error("Illumio Error: Error while fetching data of PCE. Error: " + str(e))
                del remaining_members[0]
            if len(remaining_members) == 0:
                logger.error(
                    ("Illumio Error: Ending the '{}' data fetching process as "
                     "any of the PCE in cluster is not available.").format(option))
                return None

        retry_after = float(r.headers["Retry-After"])
        location = r.headers["Location"]

        time.sleep(retry_after)

        # Poll the job status until its done
        res = None
        headers = {"Authorization": autho, "Accept": "application/json", "Content-Type": "application/json"}
        while True:
            try:
                r = requests.get(url + location, headers=headers, verify=cert_path)

                # Handle "503, Service Unavailable" error, if occured in rare synario
                retry_count = 1
                while r.status_code == 503:
                    if retry_count == MAX_RETRY_IF_503:
                        break

                    # Log only for first time about 503 status code
                    if retry_count == 1:
                        logger.warning(
                            ("Illumio Warning: Response with status code 503 while fetching data of '{}'"
                                ", will retry after {} seconds.").format(option, RETRY_AFTER_IF_503))

                    time.sleep(RETRY_AFTER_IF_503)
                    r = requests.get(url + location, headers=headers, verify=cert_path)
                    retry_count += 1

                r.raise_for_status()
            except (requests.HTTPError, requests.exceptions.ConnectionError) as e:
                logger.error("Illumio Error: Error while fetching data of " + str(option) + " Error: " + str(e))
                if is_member:
                    del remaining_members[0]

                if len(remaining_members) == 0:
                    logger.error(
                        ("Illumio Error: Ending the '{}' data fetching process as "
                         "any of the PCE in cluster is not available.").format(option))
                    return None
                else:
                    rest_help[0] = remaining_members[0]
                    del remaining_members[0]
                    rest_help[7] = ",".join(remaining_members)
                    return get_details(option, rest_help)

            if len(r.content):
                res = json.loads(r.content)
                if res["status"] in ["running", "pending"]:
                    retry_after = float(r.headers["Retry-After"])
                    time.sleep(retry_after)
                else:
                    break
            else:
                break

        # Process response, if job status is "done"
        if res["status"] == "done" and len(r.content) > 0:
            location = res["result"]["href"]
            try:
                r = requests.get(url + location, headers=headers, verify=cert_path)
                r.raise_for_status()
                return r
            except (requests.HTTPError, requests.exceptions.ConnectionError) as e:
                logger.error("Illumio Error: Error while fetching data of " + str(option) + " Error: " + str(e))
                if is_member:
                    del remaining_members[0]

                if len(remaining_members) == 0:
                    logger.error(
                        ("Illumio Error: Ending the '{}' data fetching process as "
                         "any of the PCE in cluster is not available.").format(option))
                    return None
                else:
                    rest_help[0] = remaining_members[0]
                    del remaining_members[0]
                    rest_help[7] = ",".join(remaining_members)
                    return get_details(option, rest_help)

    except Exception as e:
        logger.exception("Error Trace for failed {} request: {}".format(option, str(e)))
        return None


def get_label(rest_help):
    """Get label data from Illumio."""
    r = get_details("label", rest_help)
    if r is not None:
        events = json.loads(r.content)
        for subevents in events:
            subevents["illumio_type"] = "illumio:pce:label"
            if rest_help[5]:
                subevents["leader_fqdn"] = rest_help[6]
            s = json.dumps(subevents)
            print_xml_stream(s)


def get_workload(rest_help):
    """Get workload data from Illumio."""
    r = get_details("workload", rest_help)
    if r is not None:
        events = json.loads(r.content)
        workloads_metadata = {}
        online = offline = 0

        for subevents in events:
            workload_status = subevents.get("online", None)
            if workload_status:
                online += 1

            elif workload_status is not None:
                offline += 1

            else:
                logger.warning("Status can't be derived of workload having href: {}".format(subevents.get("href", "")))

            subevents["illumio_type"] = "illumio:pce:workload"
            subevents["fqdn"] = re.match(r"https?:\/\/([a-zA-Z0-9.\-_~]*):?", rest_help[0]).group(1)
            if rest_help[5]:
                subevents["leader_fqdn"] = rest_help[6]
            s = json.dumps(subevents)
            print_xml_stream(s)

        workloads_metadata["illumio_type"] = "illumio:pce:workload"
        workloads_metadata["online_workloads"] = online
        workloads_metadata["offline_worloads"] = offline
        workloads_metadata["total_workloads"] = online + offline
        print_xml_stream(json.dumps(workloads_metadata))


def get_ip_lists(rest_help):
    """Get IP list from Illumio."""
    r = get_details("ip_lists", rest_help)
    if r is not None:
        events = json.loads(r.content)
        for subevents in events:
            subevents["illumio_type"] = "illumio:pce:ip_lists"
            if rest_help[5]:
                subevents["leader_fqdn"] = rest_help[6]
            s = json.dumps(subevents)
            print_xml_stream(s)


def get_services(rest_help):
    """Get services data from Illumio."""
    r = get_details("services", rest_help)
    if r is not None:
        events = json.loads(r.content)
        for subevents in events:
            subevents["illumio_type"] = "illumio:pce:services"
            if rest_help[5]:
                subevents["leader_fqdn"] = rest_help[6]
            s = json.dumps(subevents)
            print_xml_stream(s)


def get_pce_health(rest_help):
    """Get PCE Health data from Illumio."""
    url = rest_help[0] + resource.get("api_version", "")
    api_key_id = rest_help[1]
    api_secret = rest_help[2]
    cert_path = rest_help[3]
    supercluster_members = []
    # supercluster_url is used to ingest in events not for API calls
    supercluster_url = urlparse(rest_help[0]).hostname
    is_supercluster = 0

    autho = "Basic " + base64.b64encode(('%s:%s' % (api_key_id, api_secret)).encode()).decode().replace('\n', '')
    headers = {"Authorization": autho, "Accept": "application/json", "Content-Type": "application/json"}

    if cert_path == "":
        cert_path = True

    try:
        r = requests.get(url + resource.get("pce_health", ""), headers=headers, verify=cert_path)
        r.raise_for_status()
        if len(r.content):
            events = json.loads(r.content)
            for subevents in events:
                subevents["illumio_type"] = "illumio:pce:health"
                if subevents.get("type") == "leader" or subevents.get("type") == "member":
                    subevents["leader_fqdn"] = supercluster_url
                    is_supercluster = 1
                    if subevents.get("type") == "member":
                        supercluster_members.append(subevents["fqdn"])

                res = json.dumps(subevents)
                print_xml_stream(res)

    except (requests.HTTPError, requests.exceptions.ConnectionError) as e:
        logger.error("Illumio Error: Error while fetching health data of PCE. Error: " + str(e))
        try:
            conf_value = cli.getConfStanza("supercluster_members", supercluster_url)
            supercluster_members = conf_value.get("supercluster_members", "")
        except Exception:
            logger.error("Illumio Error: {} stanza not found in supercluster_members.conf "
                         "file.".format(supercluster_url))
        else:
            supercluster_members = supercluster_members.split(",")
            is_supercluster = 1
            for member in supercluster_members:
                url = member + resource.get("api_version", "")
                try:
                    r = requests.get(url + resource.get("pce_health", ""), headers=headers, verify=cert_path)
                    r.raise_for_status()
                    break
                except (requests.HTTPError, requests.exceptions.ConnectionError) as e:
                    logger.error("Illumio Error: Error while fetching health data of PCE. Error: " + str(e))
            supercluster_members = []
            if len(r.content):
                events = json.loads(r.content)
                for subevents in events:
                    subevents["illumio_type"] = "illumio:pce:health"
                    if subevents.get("type") == "leader" or subevents.get("type") == "member":
                        subevents["leader_fqdn"] = supercluster_url
                        if subevents.get("type") == "member":
                            supercluster_members.append(subevents["fqdn"])

                    res = json.dumps(subevents)
                    print_xml_stream(res)
    except Exception:
        logger.exception("Error Trace for failed pce health request")
    return [is_supercluster, supercluster_url, supercluster_members]
