# -*- coding: utf-8 -*-

"""This module is used to test connectivity to the Illumio PCE.

Copyright:
    © 2023 Illumio
License:
    Apache2, see LICENSE for more details.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from illumio import PolicyComputeEngine


if __name__ == "__main__":
    pce_hostname = os.getenv("ILLUMIO_PCE_HOST") or input("Enter PCE hostname: ")
    pce_port = os.getenv("ILLUMIO_PCE_PORT") or input("Enter PCE port: ")
    org_id = os.getenv("ILLUMIO_PCE_ORG_ID") or input("Enter PCE org ID: ")
    username = os.getenv("ILLUMIO_API_KEY_USERNAME") or input("Username or API key ID: ")
    password = os.getenv("ILLUMIO_API_KEY_SECRET") or input("Password or API key secret: ")
    cert_path = input("CA cert path (leave blank if not applicable): ")

    pce = PolicyComputeEngine(pce_hostname, port=pce_port, org_id=org_id)
    pce.set_credentials(username, password)
    pce.set_tls_settings(verify=cert_path or True)

    pce.must_connect()

    print("Connection successful!")
