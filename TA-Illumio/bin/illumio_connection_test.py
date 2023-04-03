# -*- coding: utf-8 -*-

"""This module is used to test connectivity to the Illumio PCE.

Copyright:
    © 2023 Illumio
License:
    Apache2, see LICENSE for more details.
"""
from __future__ import print_function
from builtins import input
import requests
import base64


def test_connection(pce_url, api_key_id, api_secret, cert_path):
    """Test conncection."""
    url = "{}/api/v2/product_version/".format(pce_url)
    auth = "Basic {}".format(
        base64.b64encode(("%s:%s" % (api_key_id, api_secret)).encode())
        .decode()
        .replace("\n", "")
    )
    headers = {"Authorization": auth, "Accept": "application/json"}

    if cert_path == "":
        cert_path = True

    try:
        r = requests.get(url, headers=headers, verify=cert_path, timeout=10)
        if r.status_code == 401:
            print(
                "Authentication failed: API key id and/or API Secret were incorrect. Status Code: {}".format(
                    r.status_code
                )
            )
        elif r.status_code == 403:
            print(
                "Authorization failed: user is not authorized. Status Code: {}".format(
                    r.status_code
                )
            )
        elif r.status_code != 200:
            print("Connection Failed. Status Code: {}".format(r.status_code))
        else:
            print("Connection successful. Status Code: {}".format(r.status_code))
    except requests.exceptions.SSLError as exc:
        print("SSLError: Invalid certificate file or certificate not found. {}".format(exc))
    except requests.exceptions.ConnectionError as exc:
        print(
            "Connection Error: Please enter valid URL or Check the network connection. {}".format(
                exc
            )
        )
    except requests.exceptions.Timeout as exc:
        print("Request timed out while trying to connect to the remote server. {}".format(exc))
    except Exception as exc:
        print("Connection Failed: {}".format(exc))


if __name__ == "__main__":
    pce_url = input("Enter PCE URL: ")
    api_key_id = input("Username: ")
    api_secret = input("Secret Key: ")
    cert_path = input("Cert Path: ")
    test_connection(pce_url, api_key_id, api_secret, cert_path)
