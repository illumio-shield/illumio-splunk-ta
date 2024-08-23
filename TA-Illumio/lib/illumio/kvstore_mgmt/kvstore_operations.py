# -*- coding: utf-8 -*-

"""
Copyright:
    © 2024 Illumio
License:
    Apache2, see LICENSE for more details.
"""

from __future__ import print_function
from builtins import str
from future import standard_library

standard_library.install_aliases()
import os
import sys
import json
import time
from datetime import datetime, timedelta
import gzip
import re
from .kvstore_helpers import request
from pathlib import Path
from splunk.clilib import cli_common as cli

# Add lib folders to import path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from splunklib.modularinput import EventWriter

TA_PATH = "$SPLUNK_HOME/etc/apps/TA-Illumio"


def getCollections(uri, session_key, selected_app, ew=None) -> list:
    """
    Retrieve all collections for given app

    Args:
        uri (_type_): uri to connect to
        session_key (_type_): session_key for connecting
        selected_app (_type_): This is TA-Illumio app
        ew (_type_, optional): Eventwriter log. Defaults to None.

    Raises:
        Exception:

    Returns:
        _type_: List of collections
    """

    url_tmpl_app = "%(server_uri)s/servicesNS/%(owner)s/%(app)s/storage/collections/config?output_mode=json&count=0"

    # Enumerate all collections in the apps list
    collections = []
    collections_url = url_tmpl_app % dict(server_uri=uri, owner="nobody", app=selected_app)
    headers = {"Authorization": "Splunk %s" % session_key, "Content-Type": "application/json"}

    try:
        response, response_code = request("GET", collections_url, "", headers)
        if response_code == 200:
            response = json.loads(response)

        else:
            raise Exception("Could not connect to server: Error %s" % response_code)

        for entry in response["entry"]:
            entry_app = entry["acl"]["app"]
            entry_collection = entry["name"]

            if selected_app == entry_app:
                c = [entry_app, entry_collection]
                collections.append(c)
                ew.log(EventWriter.INFO, f"Added {entry_app}/{entry_collection} to list")
    except BaseException as e:
        raise Exception(e)

    return collections


def deleteCollection(ew, remote_uri, remote_session_key, app, collection):
    """Deletes the collection on remote_uri

    Args:
        logger (_type_): _description_
        remote_uri (_type_): _description_
        remote_session_key (_type_): _description_
        app (_type_): _description_
        collection (_type_): _description_

    Raises:
        Exception: _description_

    Returns:
        _type_: _description_
    """

    # Build the URL for deleting the collection
    url_tmpl = "%(server_uri)s/servicesNS/%(owner)s/%(app)s/storage/collections/data/%(collection)s/?output_mode=json"
    delete_url = url_tmpl % dict(
        server_uri=remote_uri, owner="nobody", app=app, collection=collection
    )

    # Set request headers
    headers = {
        "Authorization": "Splunk %s" % remote_session_key,
        "Content-Type": "application/json",
    }

    hostname = getHostname(remote_uri)

    # Delete the collection contents
    try:
        response, response_code = request("DELETE", delete_url, "", headers)
        ew.log(
            EventWriter.DEBUG,
            f"Server response for collection deletion: {delete_url} {response_code} {response}",
        )
        return response_code
    except BaseException as e:
        raise Exception(
            "Failed to delete collection %s/%s from %s: %s" % (app, collection, hostname, repr(e))
        )


def copyCollection(
    ew, source_session_key, source_uri, target_session_key, target_uri, app, collection
) -> dict:
    """
    Copy collection from local system to remote system

    Args:
        ew (_type_): _description_
        source_session_key (_type_): session key of source system
        source_uri (_type_): source url
        target_session_key (_type_): session key of target system
        target_uri (_type_): target url
        app (_type_): target app
        collection (_type_): collection to be copied

    Raises:
        Exception: _description_

    Returns:
        dict: _description_
    """

    source_host = getHostname(source_uri)
    target_host = getHostname(target_uri)
    download_dt = None
    delete_dt = None
    upload_dt = None
    posted = 0

    ew.log(
        EventWriter.DEBUG,
        f"source host is {source_host}, target host is {target_host}, app is {app}, collection is {collection}",
    )
    # Download the collection
    staging_dir = os.path.expandvars(os.path.join(TA_PATH, "staging"))

    ts = time.time()
    st = datetime.fromtimestamp(ts).strftime("%Y%m%d_%H%M%S")

    # Set the filename and location for the output (expanding environment variables)
    output_filename = app + "#" + collection + "#" + st + ".json.gz"
    output_file = os.path.join(staging_dir, output_filename)
    output_file = os.path.expandvars(output_file)

    # Create the directory recursively if it does not exist
    os.makedirs(staging_dir, exist_ok=True)

    # Download the collection to a file (compressed)
    try:
        download_dt = time.time()
        result, _, record_count = downloadCollection(
            ew, source_uri, source_session_key, app, collection, output_file, True
        )
        ew.log(
            EventWriter.INFO,
            f"result from downloading collection {collection}, is {result} and source uri is {source_uri}",
        )
        download_dt = str(timedelta(seconds=(time.time() - download_dt)))

        # Delete the target collection prior to uploading
        delete_dt = time.time()
        response_code = deleteCollection(ew, target_uri, target_session_key, app, collection)

        ew.log(
            EventWriter.INFO,
            f"Response code from deleting collection {collection} is {response_code}",
        )

        if result == "success":
            upload_dt = time.time()
            result, _, posted = uploadCollection(
                ew, target_uri, target_session_key, app, collection, output_file
            )
            ew.log(
                EventWriter.DEBUG,
                f"result from uploading collection {collection} is {result} and target uri is {target_uri}",
            )
        elif result == "skipped":
            result = "empty"
        else:
            result = "error"

        # Delete the output file
        if os.path.exists(output_file):
            os.remove(output_file)

        if delete_dt > 0:
            delete_dt = str(timedelta(seconds=(time.time() - delete_dt)))
        if upload_dt > 0:
            upload_dt = str(timedelta(seconds=(time.time() - upload_dt)))

        stats = {
            "app": app,
            "collection": collection,
            "result": result,
            "download_time": download_dt,
            "delete_time": delete_dt,
            "upload_time": upload_dt,
            "download_count": record_count,
            "upload_count": posted,
        }

        ew.log(EventWriter.INFO, f"Stats for copy collection {collection} is {stats}")

    except BaseException as e:
        raise Exception(
            "Error copying the collection from %s to %s: %s" % (source_host, target_host, repr(e))
        )


def downloadCollection(
    ew, remote_uri, remote_session_key, app, collection, output_file, compress=False
):
    """Download collection from app locally

    Args:
        ew (_type_): _description_
        remote_uri (_type_): _description_
        remote_session_key (_type_): _description_
        app (_type_): _description_
        collection (_type_): _description_
        output_file (_type_): _description_
        compress (bool, optional): _description_. Defaults to False.

    Returns:
        _type_: _description_
    """
    # Set request headers
    headers = {
        "Authorization": "Splunk %s" % remote_session_key,
        "Content-Type": "application/json",
    }

    # Counters
    loop_record_count = None
    total_record_count = 0

    # Config options
    batch_size = 5000
    limits_cfg = cli.getConfStanza("limits", "kvstore")
    maxrows = int(limits_cfg.get("max_rows_per_query", 5000))
    url_tmpl_collection_download = "%(server_uri)s/servicesNS/%(owner)s/%(app)s/storage/collections/data/%(collection)s?limit=%(limit)s&skip=%(skip)s&output_mode=json"

    try:
        cursor = 0
        if compress:
            f = gzip.open(output_file, "wb")  # Requires bytes
        else:
            f = open(output_file, "w")  # Requires string

        # If the loop record count is equal to batch size, we hit the limit. Keep going.
        while loop_record_count is None or loop_record_count == batch_size:
            # Build the URL
            remote_data_url = url_tmpl_collection_download % dict(
                server_uri=remote_uri,
                owner="nobody",
                app=app,
                collection=collection,
                limit=batch_size,
                skip=cursor,
            )

            # Download the data from the collection
            response = request("GET", remote_data_url, "", headers)[0]
            response = response.decode("utf-8")
            # Remove the first and last characters ( [ and ] )
            response = response[1:-1]
            # Insert line breaks in between records -- "}, {"
            response = response.replace("}, {", "}, \n{")
            # Count the number of _key values
            loop_record_count = response.count('"_key"')
            total_record_count += loop_record_count
            ew.log(
                EventWriter.INFO,
                f"Counted {total_record_count} total records and {loop_record_count} in this loop.",
            )

            # Append the records to the variable
            if loop_record_count > 0:
                ## Write the leading [ or comma delimiter (between batches)
                # Start of the collection
                if cursor == 0 and compress:
                    f.write("[".encode())
                elif cursor == 0 and not compress:
                    f.write("[")

                # Middle of the collection
                elif cursor != 0 and compress:
                    f.write(",".encode())
                else:
                    f.write(",")

                # Response body
                if compress:
                    f.write(response.encode())
                else:
                    f.write(response)

                # End of the collection
                if loop_record_count < batch_size and compress:
                    f.write("]".encode())
                elif loop_record_count < batch_size and not compress:
                    f.write("]")
            cursor += loop_record_count
        f.close()

        ew.log(EventWriter.DEBUG, f"Retrieved {total_record_count} records from {collection}")

        if total_record_count > 0:
            if total_record_count == maxrows:
                ew.log(
                    EventWriter.INFO,
                    f"Downloaded rows equal to configured limit: {app}/{collection}",
                )
                result = "warning"
                message = "Downloaded rows equal to configured limit. Possible incomplete backup."
            if batch_size > maxrows and total_record_count > maxrows:
                ew.log(
                    EventWriter.INFO,
                    f"Downloaded KV store collection with batches exceeded the limit: {app}/{collection}",
                )
                result = "warning"
                message = (
                    "Batch size greater than configured query limit. Possible incomplete backup."
                )
            else:
                ew.log(
                    EventWriter.INFO,
                    f"Downloaded KV store collection successfully: {app}/{collection}",
                )
                result = "success"
                message = "Downloaded collection"
        else:
            ew.log(EventWriter.INFO, f"Skipping collection: {collection}")
            result = "skipped"
            message = "Collection is empty"

    except BaseException as e:
        ew.log(EventWriter.ERROR, f"Failed to download collection: {e}")
        result = "error"
        message = repr(e)
        total_record_count = 0
        if os.path.isfile(output_file):
            os.remove(output_file)

    return result, message, total_record_count


def uploadCollection(ew, remote_uri, remote_session_key, app, collection, file_path):
    # Set request headers
    headers = {
        "Authorization": "Splunk %s" % remote_session_key,
        "Content-Type": "application/json",
    }

    limits_cfg = cli.getConfStanza("limits", "kvstore")

    limit = int(limits_cfg.get("max_documents_per_batch_save", 100))

    try:
        file_name = re.search(r"(.*)(?:\/|\\)([^\/\\]+)", file_path).group(2)

        # Open the file using standard or gzip libs
        if file_path.endswith(".json"):
            fh = open(file_path, "r")
        elif file_path.endswith(".json.gz"):
            fh = gzip.open(file_path, "rb")

        # Read the file data and parse with JSON loader
        contents = json.loads(fh.read(), strict=False)
    except BaseException as e:
        # Account for a bug in prior versions where the record count could be wrong if "_key" was in the data and the ] would not get appended.
        ew.log(
            EventWriter.ERROR, f"Error reading file: {e}\n\tAttempting modification (Append ']')."
        )

        try:
            # Reset the file cursor to 0
            fh.seek(0)
            contents = json.loads(fh.read() + b"]", strict=False)
        except BaseException:
            ew.log(
                EventWriter.ERROR,
                f"[Append ']'] Error reading modified json input.\n\tAttempting modification (Strip '[]')",
            )
            try:
                # Reset the file cursor to 0
                fh.seek(0)
                contents = json.loads(fh.read().strip(b"[]"), strict=False)
            except BaseException as e:
                ew.log(
                    EventWriter.ERROR,
                    f"[Strip '[]'] Error reading modified json input for file {file_path}.  Aborting.",
                )
                status = "error"
                message = "Unable to read file"
                return status, message, 0

    content_len = len(contents)
    ew.log(EventWriter.DEBUG, f"File {file_name} entries: {content_len}")

    i = 0
    batch_number = 1
    posted = 0

    # Build the URL for updating the collection

    url_tmpl_batch = "%(server_uri)s/servicesNS/%(owner)s/%(app)s/storage/collections/data/%(collection)s/batch_save?output_mode=json"

    record_url = url_tmpl_batch % dict(
        server_uri=remote_uri, owner="nobody", app=app, collection=collection
    )
    ew.log(
        EventWriter.DEBUG,
        f"Server url to which POST will happen from uploadCollection is {record_url}",
    )
    result = None
    while i < content_len:
        # Get the lesser number between (limit-1) and (content_len)
        last = batch_number * limit
        last = min(last, content_len)
        batch = contents[i:last]
        i += limit

        ew.log(
            EventWriter.DEBUG,
            f"Batch number: {batch_number} ({sys.getsizeof(batch)} bytes / {len(batch)} records)",
        )

        # Upload the restored records to the server
        try:
            _, response_code = request(
                "POST", record_url, json.dumps(batch), headers
            )  # pylint: disable=unused-variable
            batch_number += 1
            posted += len(batch)
            if response_code != 200:
                raise Exception("Error %d when posting collection contents" % response_code)

        except BaseException as e:
            result = "error"
            message = "Failed to upload collection: %s" % repr(e)
            ew.log(EventWriter.DEBUG, f"{message}")
            i = content_len

    if result is None:
        result = "success"
        message = "Restored %d records to %s/%s" % (posted, app, collection)
        # Collection now fully restored
    return result, message, posted


def getHostname(uri):
    return re.sub(r"https?://([^:]+):.*", r"\1", uri)


__all__ = [
    "getHostname",
    "uploadCollection",
    "downloadCollection",
    "deleteCollection",
    "copyCollection",
    "getCollections",
]
