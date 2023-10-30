# Illumio Technical Add-On for Splunk

* [Overview](#overview)
* [Splunk Architecture](#splunk-architecture)
* [Installation](#installation)
    * [Configuration](#configuration)
* [Upgrade Steps](#upgrade-steps)
* [Workload Quarantine Action](#workload-quarantine-action)
* [Troubleshooting](#troubleshooting)
    * [Testing the PCE Connection](#testing-the-pce-connection)
* [Uninstalling](#uninstalling)
* [Release Notes](#release-notes)
* [EULA](#eula)
* [Support](#support)
* [License](#license)

## Overview  

The [Illumio Add-on for Splunk]((https://splunkbase.splunk.com/app/3657)) integrates with the Illumio Policy Compute Engine (PCE). It enriches Illumio data with Common Information Model (CIM) fields for compatibility with other Splunk products and add-ons.

### Version - 4.0.0  

**Supported Splunk versions**  
* 8.1.x
* 8.2.x
* 9.0.x
* 9.1.x

**Supported versions of the Illumio Policy Compute Engine (PCE)**  
* 21.5.x
* 22.2.x
* 22.5.x
* 23.2.x
* Illumio SaaS PCE (latest)

**Supported Splunk Common Information Model (CIM) versions**  
* 4.x
* 5.x

## Splunk Architecture  

The `TA-Illumio` add-on can be installed in either a standalone or distributed Splunk environment.  

> [!NOTE]
> Recommendations for the configuration and topology of a distributed Splunk environment are outside the scope of this document. See the documentation on [Splunk Validated Architectures](https://docs.splunk.com/Documentation/SVA/current/Architectures/Introduction) for suggestions on topology for distributed deployments.  

* For a standalone deployment, install and configure the TA as described in the [Installation](#installation) section below.  

* For a distributed environment, install the TA to a Splunk Heavy Forwarder.  

> [!IMPORTANT]
> The `TA-Illumio` add-on cannot be installed on a Universal Forwarder.  

## Installation  

**Splunk UI**  

1. In the Splunk UI, navigate to the "Manage Apps" page via the Apps drop-down in the top-left, or by clicking the Gear icon next to "Apps" on the Splunk homepage
2. Click the **Browse More Apps** button, and search for `TA-Illumio`
3. Click **Install**
4. Enter your Splunk login credentials when prompted, then click **Agree and Install**
5. When prompted, restart Splunk

**Splunkbase download**  

1. Navigate to the [`TA-Illumio`](https://splunkbase.splunk.com/app/3657) app in Splunkbase
2. Log in using your Splunk credentials
3. Click **Download** 
4. Read through and accept the EULA and Terms and Conditions, then click **Agree to Download**
5. Transfer the downloaded `.tgz` or `.spl` file to the Splunk server
6. Install the app manually:

using the Splunk binary  

```sh
$SPLUNK_HOME/bin/splunk install app /path/to/TA-Illumio.spl
```

OR by extracting directly under `/apps`  

```sh
tar zxf /path/to/TA-Illumio.spl -C $SPLUNK_HOME/etc/apps/
```

7. Restart Splunk

### Configuration  

**Creating a PCE API key**  

To create a User-scoped API key:

1. In the PCE, open the user menu dropdown at the top-right of the page and select **My API keys**
2. Click **Add**. Note down the **Org ID** shown in the dialog and enter a display name for the key
3. Click `Create`. Copy or download the API key credentials and store them somewhere secure

To create a Service Account API key:

> The Org ID value is not shown when creating a Service Account key - you can find it when creating a User API key as described above.

1. In the PCE, open the **Access** submenu on the left side of the screen and select **Service Accounts**
2. Click **Add**. Enter a display name and one or more Roles to assign to the key. The `TA-Illumio` add-on requires readonly access to policy object endpoints, so the **Global Viewer** role should be sufficient

> [!NOTE]
> To use the [workload quarantine action](#workload-quarantine-action), the API key used for the input must have write permission for workloads.  

3. Click **Save**. Copy or download the API key credentials and store them somewhere secure

> [!WARNING]
> Service Account API keys have a default lifetime of 90 days - take note of the expiry date for your key and replace it before it expires to avoid disruption.

**Setting up the Illumio modular input**  

1. Navigate to Settings -> Data inputs and find the `Illumio` input type
2. Click the **+ Add New** action to create a new input
3. Enter a display name for the input and the connection details for your PCE. Enter the Organization ID and API key username and secret values copied from the steps above
4. (On-prem only) To receive syslog events forwarded from an on-prem PCE, a TCP input must be configured in Splunk. Setting the **Syslog Port (TCP)** value will automatically create one when the input runs if it does not already exist. The **Enable TCP-SSL** option determines whether a `[tcp-ssl]` or `[tcp]` stanza will be created (see below for more details on TCP SSL configuration)
5. Adjust any of the remaining parameters as needed. Make sure that the index is set correctly (found by selecting the **More settings** checkbox). To enable automated quarantine using the [`illumio_quarantine`](#workload-quarantine-action) action, specify one or more labels that make up a quarantine policy scope in the PCE in the **Quarantine Labels** field
6. Click **Next**. If an error dialog appears, double-check the field values and refer to the [Troubleshooting](#troubleshooting) section below

**TCP SSL Configuration**  

To configure syslog forwarding encrypted with TLS, both a `[tcp-ssl]` stanza and an `[SSL]` stanza must be configured in `$SPLUNK_HOME/etc/apps/TA-Illumio/local/inputs.conf`.  

The TCP-SSL stanza will be created automatically as described above, but the `[SSL]` stanza must be created manually. This step only needs to be done once for any number of Illumio inputs.  

When using an existing certificate authority, generate a server certificate for Splunk with the CN or SAN set to the Splunk instance hostname or IP address.  

When using a self-signed certificate, refer to the [Splunk documentation](https://docs.splunk.com/Documentation/Splunk/9.1.1/Security/Howtoself-signcertificates) on generating and configuring self-signed TLS certificates. Make sure that the root CA certificate is created with extensions and the ca flag is set to true (checked by syslog-ng validation).  

1. Create the SSL stanza with the following fields:
```
[SSL]
serverCert  = /path/to/my/splunk_server.crt
sslPassword = splunk_server_cert_pass
```
2. Restart Splunk

> [!WARNING]
> Do NOT use the Splunk default certificates when configuring SSL.

**Configuring Syslog Forwarding for On-Prem PCEs**  

1. In the PCE, open the **Settings** submenu on the left side of the screen and select **Event Settings**
2. Click **Add** to create a new Event Forwarding rule
3. Select the event types to forward to Splunk
4. Click **Add Repository**
5. Enter a description for the repository and the Splunk hostname/IP and the port value of the TCP stanza created for the `Illumio` input. Leave the protocol value as **TCP**
6. If TCP-SSL is configured in Splunk for the target port, set the TLS field to **Enabled** and upload a certificate bundle containing the root and any intermediate certificates in the chain for your CA

> [!NOTE]
> If enabling TLS, the address value must match the CN or SAN of the Splunk server certificate  

7. Select the **Verify TLS** option to ensure that your certificates and TLS configuration are valid
8. Click **Add** and select the radio button option for the created repository
9. Click **Save**. A test event will be sent to Splunk to verify the connection
10. In Splunk, run the following search to make sure the test event arrived

```
index=illumio_index sourcetype="illumio:pce" "Testing syslog connection from PCE"
```

**Configuring Syslog Forwarding for Cloud PCEs**  

1. Reach out to Illumio Customer Support to configure Syslog event forwarding to AWS S3. The target bucket can be internal or managed by Illumio
2. Once the bucket is configured, make sure the Syslog files are being sent
3. Install the [AWS S3 TA](https://splunkbase.splunk.com/app/1876) from Splunkbase
4. Follow the configuration instructions for Generic S3 inputs in the [AWS S3 TA documentation](https://docs.splunk.com/Documentation/AddOns/released/AWS/S3)
5. Create two inputs, one for auditable events and one for collector (traffic flow) events
6. Each input should specify a Log File/S3 Key Prefix with the path to either auditable or collector event logs within the S3 bucket

## Upgrade Steps  

### v3.2.3 to v4.0.0  

1. The updated `Illumio` modular input in v4.0.0 is incompatible with previous versions. Remove all inputs created with previous versions of the TA
2. Remove `passwords.conf` entries for Illumio API keys and secrets created for `Illumio` modular inputs by previous versions of the TA
3. Remove the `$SPLUNK_HOME/var/log/TA-Illumio` directory - TA logs are now written to `splunkd.log`
4. Update the TA in-place following the installation instructions above
5. Restart Splunk
6. Remove unnecessary files from `$SPLUNK_HOME/etc/apps/TA-Illumio/bin`
    * `/splunklib/` and `/lib/` - lib files have been moved to `/TA-Illumio/lib`
    * `get_data.py`
    * `IllumioUtil.py`
    * `markquarantine.py`
    * `README`
7. Syslog events in v4.0.0 are transformed at index-time to strip the syslog prefix so that JSON KV extraction can be used. Due to this change, events indexed before the v4.0.0 upgrade are incompatible and require different search operations and filters. **Any custom searches, alerts, reports, and dashboards created for previous versions of the TA will need to be rewritten for the updated format**
8. If existing event data indexed by previous versions of the TA need to be retained, they can be written to a file and reindexed:
    1. **Start by creating a new index for the v4.0.0 events**
    2. Using the Splunk CLI, run a search to output all Illumio syslog events from the desired time range to a file. For example, to get all events from the past week:

    ```
    > $SPLUNK_HOME/bin/splunk search "index=illumio_index earliest=-1w latest=now" -output rawdata -maxout 2000000 > ~/.splunk/illumio_rawdata_backup.txt
    ```

    3. In Splunk, select **Settings -> Add Data**
    4. Click **Upload** and select the output file created above
    5. Click **Next**
    6. Open the **Source type** dropdown, enter **illumio:pce** in the search bar, and select it from the menu
    7. Make sure the timestamp extractions are correct and the data is properly formatted in the output sample
    8. Click **Next**
    9. Set the index to the one created above for v4.0.0 events, and the host value to the PCE FQDN
    10. Click **Review**
    11. Review the configuration and click **Submit**
    12. Run a search against the target index to make sure the events were assigned the correct timestamps and search-time extractions are working as expected

    ```
    index=illumio_v4_index sourcetype="illumio:pce*"
    ```

### >= v3.0.0 up to v3.2.3  

* No steps required

### <= v2.2.0 to 2.2.1  

If using the "IP Address of PCE Node" field of Data Inputs page for Private IP addresses then follow the below steps after upgrading to version 2.2.1:  

1. Go to Settings -> Data Inputs -> Illumio
2. Select the input name which had private ip addresses configured
3. Add hostname corresponding to configured ip addresses in "Hostname of PCE Node" field
4. Update the input

### v2.0.1 to v2.1.0 >= v2.2.0  

When using a custom index for ingesting Illumio data into Splunk, update the `illumio_index` event type:

1. Go to Settings -> Event types
2. Search for the `illumio_index` event type
3. Update the search string for `illumio_index` to `index="custom_index_name"`

## Workload Quarantine Action  

The `TA-Illumio` add-on provides a scripted alert action to move a workload into a configured quarantine zone. Policy and labels for this quarantine zone must first be defined on the PCE.  

The action takes the following parameters:  

* `workload_href` - PCE workload HREF of the workload to move into quarantine
* `pce_fqdn` - PCE fully-qualified domain name
* `org_id` - PCE organization ID. Defaults to `1`

When triggered, the alert action script looks up the modular input matching the given `pce_fqdn` and `org_id` and uses the configured PCE connection details when updating the specified workload.  

> [!IMPORTANT]
> For the action to run successfully, the API key configured for the input MUST have write permission for workloads.  

**Manually Run the Action**  

The following search can be run from the Splunk UI to quarantine the workload with the specified HREF:  

```
| makeresults 1 | sendalert illumio_quarantine param.workload_href="/orgs/1/workloads/00f13a7b-0386-4943-a96c-cfd71d4096dd" param.pce_fqdn="my.pce.com" param.org_id=1
```

## Known Issues  

**Service Account API keys**  

* Service Account keys have a default expiration of 90 days - make sure to rotate them before expiration
* For some versions of the PCE (21.5) some API endpoints may return a 403 despite the Service Account key having the necessary permissions - when seeing 403 errors in the TA logs, create a new key or use a User-scoped API key instead

**Supercluster**

* The `illumio_*` metadata collections set the **pce_fqdn** field value to be the domain name of the PCE referenced in the input configuration. This could lead to these metadata objects having different **pce_fqdn** values from syslog events pushed by individual SC members

## Troubleshooting  

When encountering an issue with the TA, start by checking the TA logs in `splunkd.log`. This can be done by running the following search in the Splunk UI:  

```
index=_internal sourcetype=splunkd TA-Illumio
```

or by searching the log directly from the filesystem:

```sh
tail -c100000 $SPLUNK_HOME/var/log/splunk/splunkd.log | grep -i TA-Illumio
```

If the `Illumio` input is not running
* For Splunk versions below 8.1, make sure the **python.version** value for the server and input are set to **python3**
* Check that the input interval is not set too high
* Make sure the input is enabled under Settings -> Data Inputs -> Illumio
* Check Splunk logs for any issues that may cause modular inputs to fail
* Check that you aren't hitting your Splunk license limits
* Restart Splunk to force the input to run

**Event Forwarding (On-Prem PCEs)**  

If you see a validation error when configuring Event Forwarding using TLS:
* Make sure the CA certificate being used contains the entire CA chain, including the root and any intermediate certificates
* Check that the PCE can resolve the Splunk server using a tool like `nslookup` or `dig`
* Make sure the `[tcp-ssl]` stanza in Splunk is correct and the Splunk server is listening on the specified port. For example, to check that Splunk is listening on port 514:

```sh
sudo lsof -i -n -P | grep TCP | grep 514
```

* Verify that the hostname or IP address used for the connection is set as the CN or a SAN in the Splunk server certificate:

```sh
openssl x509 -text -noout -in $SPLUNK_HOME/etc/certs/splunk.pem
```

* Test the TLS connection from the PCE to Splunk

```
openssl s_client -connect my.splunk.com:8443 -CAPath /path/to/ca/certificates/
```

If forwarded events are not showing up in Splunk
* Make sure that the **index** value configured for the `Illumio` input is correct
* Check that all desired event types are selected in the PCE's Event Forwarding settings
* Check for errors in the `syslog-ng` logs in `/var/log/messages` on the PCE
* If TLS is enabled for the connection, make sure the `[tcp-ssl]` and `[SSL]` stanzas are configured correctly in `inputs.conf`
* Make sure the TCP input has `sourcetype = illumio:pce`

**KVStores**

If data is not showing up in the `illumio_*` metadata stores
* If using a distributed Splunk environment, make sure to set `replicate = true` for all collections in `$SPLUNK_HOME/etc/apps/TA-Illumio/local/collections.conf` to enable replication across all indexers
* Check `$SPLUNK_HOME/var/log/splunk/mongod.log` for any startup or runtime errors with mongodb
* Call the [Splunk API endpoint](https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/kvstore/usetherestapitomanagekv/) for the collection to check if objects are being stored
* Check that the `transforms.conf` stanza for the collection lookupis configured correctly

### Testing the PCE Connection  

When an `Illumio` modular input is created, the connection to the PCE is validated, and any connection issues will be presented to the user in the error dialog on the input configuration page. Additional error logs can be found in `splunkd.log`. If the cause still can't be determined from the logs, try the following:

* Use a tool like `nslookup` or `dig` from the Splunk server to make sure the PCE host is resolvable and there is no issue with the DNS nameserver
* Use `curl` or `wget` to establish an HTTP connection from the Splunk server to the PCE:

```
> curl -L -U "<api_key>:<api_secret>" "https://my.pce.com:8443/api/v2/health"
```

* Make sure the API key used for the connection is valid and has read access to policy objects
* If using internal or self-signed certificates, make sure Splunk is using the correct CA chain

**Using `illumio_connection_test.py`**  

The `illumio_connection_test.py` script is provided as a way to validate the PCE connection from the command line:  

```
> python $SPLUNK_HOME/etc/apps/TA-Illumio/bin/illumio_connection_test.py
Enter PCE hostname: my.pce.com
Enter PCE port: 8443
Enter PCE org ID: 1
Username or API key ID: api_...
Password or API key secret: ...
```

Alternatively, these values can be set using the following environment variables:  

```sh
export ILLUMIO_PCE_HOST=my.pce.com
export ILLUMIO_PCE_PORT=8443
export ILLUMIO_PCE_ORG_ID=1
export ILLUMIO_API_KEY_USERNAME=api_...
export ILLUMIO_API_KEY_SECRET=...
```

The script output should help to narrow down the cause of the connection failure.  

## Uninstalling  

To uninstall the Illumio Technical Add-On for Splunk, follow these steps:  

1. Access the filesystem of the Splunk server where the app is installed
2. Navigate to `$SPLUNK_HOME/etc/apps`
3. Remove the `TA-Illumio` folder and all of its contents
4. Restart Splunk

## Release Notes  

### Version 4.0.0  

> [!IMPORTANT]
> Due to this change, the serch-time extractions and transforms for version 4.0.0 are incompatible with data indexed by previous versions of the TA. See the [v4.0.0 upgrade steps](#v323-to-v400) above for more detailed instructions for upgrading from an earlier version.

**New Features**

* Added support for label types beyond the default RAEL dimensions
    * Static RAEL field extractions have been removed
* The TA now seamlessly supports inputs for multiple PCEs as well as multiple organizations within the same PCE cluster
* Added support for HTTP proxy values when connecting to the PCE
* Added retry and timeout values for the PCE connection
* Added flag to specify `[tcp]` or `[tcp-ssl]` when creating a new TCP stanza for receiving syslog events
* System health and PCE status events are now filtered under the new **illumio:pce:health** sourcetype

**Improvements**

* **Syslog prefixes are stripped at index-time for JSON-formatted events**
    * These events now use JSON KV mode
    * The **json_data** field has been removed
* The TA now supports CIM v5.x
* Updated PCE and Splunk versions supported
* Updated to the latest version of the Splunk SDK for python
* Illumio PCE Superclusters are treated the same as any other PCEs for configuration purposes. The input URL may point to a top-level Supercluster FQDN, leader PCE, or member PCE
* The `markquarantine` alert action has been renamed `illumio_quarantine`, and can now be configured with any number of label dimensions
    * The **Quarantine Labels** parameter in the `Illumio` input accepts a list of label key:value pairs that form the quarantine policy scope on the PCE. See the [workload quarantine action](#workload-quarantine-action) section above for details

**Removed Features**

* **Python 2.7 is no longer supported**
    * The TA now supports python v3.7+
* Removed the following fields from the modular input spec:
    * **private_ip** - vestigial field with no functionality in 3.x
    * **hostname** - no longer necessary due to Supercluster changes
    * **api_secret** - writing the API secret to `passwords.conf` now happens via the Splunk REST API when saving the input
    * **enabled** - inputs can be enabled or disabled from the Splunk UI or by setting the **disabled** field
* The `illumio.conf` custom configuration file has been removed
    * This file previously stored HREF values for quarantine labels, but is no longer needed
* Removed the following files from `TA-Illumio/bin`:
    * `IllumioUtil.py` - replaced with `illumio_pce_utils.py` and `illumio_splunk_utils.py`
    * `get_data.py` - the TA now uses the [`illumio`](https://pypi.org/project/illumio/) python library for the PCE API client
    * `lib/` and `splunklib/` - python libs have been moved under `TA-Illumio/lib`
    * `markquarantine.py` - renamed `illumio_quarantine.py` as the `markquarantine` action has been renamed `illumio_quarantine`
* Removed the **illumio:pce:metadata** and **illumio:pce:ps_details** sourcetypes
    * **Illumio IP list, Label, Service, and Workload objects are no longer indexed as events**
    * Indexing these static objects as events was expensive and could lead to confusing search results. Instead, these objects are added KV stores which are updated on each run of the TA
    > [!NOTE] 
    > By default, KV store replication is **disabled** for these object stores. It is up to the Splunk administrators to determine if replication is necessary for their environments, and override the local collections.conf with `replicate = true`
    * Similarly, port scan details are written to the **illumio_port_scan_settings** collection rather than being indexed as events
* The `$SPLUNK_HOME/var/log/TA-Illumio` log directory has been removed. TA logs are now sent to `splunkd.log` per Splunk best practices for modular inputs
* The following field extractions have been removed:
    * **json_data** - no longer relevant with stripped syslog prefixes & JSON KV mode
    * **workload_href**, **agent_href**, **created_href** - where relevant, replaced with CIM field **object_id**
    * **pce_hostname** - superceded by **pce_fqdn**
    * **created_hostname**, **workloads_affected_after**, **changes_labels_deleted** - convenience extractions that are no longer used. If needed, these values are simple to extract manually at search-time using the **spath** command
    * **src_role_label**, **src_app_label**, **src_env_label**, **src_loc_label** - replaced with **src_label_pairs**
    * **dest_role_label**, **dest_app_label**, **dest_env_label**, **dest_loc_label** - replaced with **dest_label_pairs**

### Version 3.2.3  

* Update Splunk SDK version to latest (1.7.3)

### Version 3.2.2  

* Added support for SaaS PCE

### Version 3.2.1  

* Removed eventgen.conf from "Illumio Add-on for Splunk" package

### Version 3.2.0  

* Modified data collection code to support the supercluster
* Added supercluster_members.conf file to add members of the supercluster
* Added "leader_fqdn" field in events only if configured PCE is part of the supercluster
* Made port number field to be optional during input configuration
* Enhanced CIM field extractions

### Version 3.1.0  

* Modified data collection code to handle Service Unavailable error
* Changed the input created of type [tcp] to [tcp-ssl]
* Extracted new fields for Illumio PCE health data

### Version 3.0.0  

* Splunk 8 Support.
* Made Add-on Python23 compatible.

### Version 2.3.0  

* Changed API version from v1 to v2
* Added support of S3 data
* Added two API calls services and ip_lists for Alert Configuration dashboard
* Added some field extraction for Alert Configuration dashboard
* Changed time extraction and used timestamp field for _time

### Version 2.2.2  

* Fixed the bug while saving the data input

### Version 2.2.1  

* Extracted pce_fqdn field for illumio:pce:metadata source type
* Removed "IP Adress of PCE Node" field from Data Inputs page
* Added "Hostname of PCE Node" field on Data Inputs page

### Version 2.2.0  

* Extracted new fields for source and destination labels
* Added encryption for "API Secret"
* Added Validation for "Allowed port scanner Source IP addresses"
* Removed "dnslookup" custom command

### Version 2.1.0  

* Added support of Illumio PCE 18.3.1, 19.1
* For Illumio Cloud data coming from S3, added support of JSON data format for illumio:pce and illumio:pce:collector source types
* Added test script to check the connection with Illumio server

### Version 2.0.2  

* Added support of Illumio PCE 18.2.1, 18.2.2, 18.2.3

### Version 2.0.1  

* Fixed the issue of fqdn in host_details_lookup table when PCE URL contains special characters.

### Version 2.0.0  

* This version of TA is only compatible with Illumio PCE 18.2.0
* This version of TA is not compatible with Illumio PCE 17.X

## EULA  

See the EULA document on the [Illumio Integrations docs site](https://docs.illumio.com/LandingPages/Categories/illumio-integrations.htm).  

## Support  

* Access questions and answers specific to Illumio Add-On For Splunk at https://answers.splunk.com.
* Support Offered: Yes
* Support Email: app-integrations@illumio.com
* Please visit https://answers.splunk.com, and ask your question regarding Illumio Add-on for Splunk. Please tag your question with the correct App Tag, and your question will be attended to.

## License  

Copyright 2023 Illumio, Inc. All rights reserved.  

```
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```
