# -*- coding: utf-8 -*-

"""
Copyright:
    © 2024 Illumio
License:
    Apache2, see LICENSE for more details.
"""

from __future__ import print_function
from array import array
from builtins import str
from future import standard_library

standard_library.install_aliases()
import sys
import os
import urllib.request
import urllib.parse
import urllib.error
import http.client as httplib
import ssl

# Add lib folders to import path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))


# HTTP request wrapper
def request(method, url, data, headers, conn=None, verify=None):
    """Helper function to fetch data from the given URL"""
    # See if this is utf-8 encoded already
    try:
        data.decode("utf-8")
    except AttributeError:
        try:
            data = urllib.parse.urlencode(data).encode("utf-8")
        except:
            data = data.encode("utf-8")
    url_tuple = urllib.parse.urlparse(url)
    if conn is None:
        close_conn = True
        if url_tuple.scheme == "https":
            # If verify was set explicitly, OR it's not set to False and env[PYTHONHTTPSVERIFY] is set
            env_verify_set = os.environ.get("PYTHONHTTPSVERIFY", default=False)
            if verify or (string_to_bool(env_verify_set) and not verify == False):
                conn = httplib.HTTPSConnection(
                    url_tuple.netloc, context=ssl.create_default_context()
                )
            else:
                conn = httplib.HTTPSConnection(
                    url_tuple.netloc, context=ssl._create_unverified_context()
                )
        elif url_tuple.scheme == "http":
            conn = httplib.HTTPConnection(
                url_tuple.netloc, context=ssl._create_unverified_context()
            )
    else:
        close_conn = False
    try:
        conn.request(method, url, data, headers)
        response = conn.getresponse()
        response_data = response.read()
        response_status = response.status
        if close_conn:
            conn.close()
        return response_data, response_status
    except BaseException as e:
        raise Exception("URL Request Error: " + str(e))


def string_to_bool(v):
    if isinstance(v, bool):
        return v
    else:
        return str(v).lower() in ("yes", "y", "true", "t", "1")


__all__ = ["request", "string_to_bool"]
