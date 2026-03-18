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
import base64
import urllib.request
import urllib.parse
import urllib.error
import http.client as httplib
import ssl

# Add lib folders to import path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))


# HTTP request wrapper
def request(method, url, data, headers, conn=None, verify=None, proxy=None):
    """Helper function to fetch data from the given URL"""
    # See if this is utf-8 encoded already
    try:
        data.decode("utf-8")
    except AttributeError:
        try:
            data = urllib.parse.urlencode(data).encode("utf-8")
        except:
            data = data.encode("utf-8")
    try:
        url_tuple = urllib.parse.urlparse(url)
        if conn is None:
            close_conn = True
            # When a proxy is configured, open the connection to the proxy and tunnel to the target host.
            if proxy:
                proxy_tuple = urllib.parse.urlparse(proxy)
                # Build the proxy host:port without embedded credentials before opening the socket.
                proxy_netloc = proxy_tuple.hostname
                if proxy_tuple.port:
                    proxy_netloc = "%s:%s" % (proxy_tuple.hostname, proxy_tuple.port)
                # Add Host for the tunnel target so the proxy CONNECT request includes the target authority.
                proxy_headers = {"Host": url_tuple.netloc}
                # If proxy credentials are present in the proxy URL, send them as Proxy-Authorization.
                if proxy_tuple.username or proxy_tuple.password:
                    proxy_auth = "%s:%s" % (
                        urllib.parse.unquote(proxy_tuple.username or ""),
                        urllib.parse.unquote(proxy_tuple.password or ""),
                    )
                    proxy_headers["Proxy-Authorization"] = "Basic %s" % (
                        base64.b64encode(proxy_auth.encode("utf-8")).decode("ascii")
                    )

                # Keep the existing TLS verification behavior for HTTPS targets when tunneling through the proxy.
                env_verify_set = os.environ.get("PYTHONHTTPSVERIFY", default=False)
                if url_tuple.scheme == "https":
                    # Use HTTPSConnection for HTTPS targets so the tunneled socket is wrapped with TLS
                    # after CONNECT succeeds and before the request is sent to the target server.
                    if verify or (string_to_bool(env_verify_set) and not verify == False):
                        conn = httplib.HTTPSConnection(
                            proxy_netloc, context=ssl.create_default_context()
                        )
                    else:
                        conn = httplib.HTTPSConnection(
                            proxy_netloc, context=ssl._create_unverified_context()
                        )
                elif url_tuple.scheme == "http":
                    if proxy_tuple.scheme == "https":
                        conn = httplib.HTTPSConnection(
                            proxy_netloc, context=ssl._create_unverified_context()
                        )
                    else:
                        conn = httplib.HTTPConnection(proxy_netloc)

                # Only HTTPS targets need CONNECT tunneling through the proxy. Plain HTTP targets are sent as normal
                # proxy requests using the absolute URL.
                if url_tuple.scheme == "https":
                    # Use the default port for the target scheme when the URL does not include an explicit port.
                    tunnel_port = url_tuple.port
                    if tunnel_port is None:
                        tunnel_port = 443

                    conn.set_tunnel(url_tuple.hostname, tunnel_port, headers=proxy_headers)
            elif url_tuple.scheme == "https":
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
        # For plain HTTP requests through a proxy, send Proxy-Authorization on the request itself.
        request_headers = headers.copy()
        if proxy and url_tuple.scheme == "http":
            proxy_tuple = urllib.parse.urlparse(proxy)
            if proxy_tuple.username or proxy_tuple.password:
                proxy_auth = "%s:%s" % (
                    urllib.parse.unquote(proxy_tuple.username or ""),
                    urllib.parse.unquote(proxy_tuple.password or ""),
                )
                request_headers["Proxy-Authorization"] = "Basic %s" % (
                    base64.b64encode(proxy_auth.encode("utf-8")).decode("ascii")
                )

        # Send only the path when going through a proxy tunnel; otherwise preserve the existing request target.
        request_target = url
        if proxy and url_tuple.scheme == "https":
            request_target = url_tuple.path or "/"
            if url_tuple.query:
                request_target = "%s?%s" % (request_target, url_tuple.query)
        conn.request(method, request_target, data, request_headers)
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
