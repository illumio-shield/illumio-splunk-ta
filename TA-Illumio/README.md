# OVERVIEW

* The Illumio Add-on for Splunk integrates with the Illumio Policy Compute Engine (PCE). It enriches Illumio data with Common Information Model (CIM) fields and enables Illumio data to be easily used with Splunk Enterprise Security, Splunk App for PCI Compliance, etc.
* For dashboards with Illumio data, please install the Illumio App for Splunk available at https://splunkbase.splunk.com
* Version: 3.2.3
* Supports Splunk versions are 8.1+ and 9.0
* Supports PCE Versions 21.2, 21.5, 22.2, 22.5
* Supports the latest PCE SaaS version (22.5)


# Release Notes

* **Version 3.2.4**
    * Update Splunk SDK version to latest (2.1.0)

* **Version 3.2.3**
    * Update Splunk SDK version to latest (1.7.3)

* **Version 3.2.2**
    * Added support for SaaS PCE.

* **Version 3.2.1**
    * Removed eventgen.conf from "Illumio Add-on for Splunk" package.

* **Version 3.2.0**
    * Modified data collection code to support the supercluster.
    * Added supercluster_members.conf file to add members of the supercluster. 
    * Added "leader_fqdn" field in events only if configured PCE is part of the supercluster. 
    * Made port number field to be optional during input configuration..
    * Enhanced CIM field extractions.

* **Version 3.1.0**
    * Modified data collection code to handle Service Unavailable error.
    * Changed the input created of type [tcp] to [tcp-ssl]
    * Extracted new fields for Illumio PCE health data.

* **Version 3.0.0**
    * Splunk 8 Support.
    * Made Add-on Python23 compatible.

* **Version: 2.3.0**
    * Changed API version from v1 to v2.
    * Added support of S3 data.
    * Added two API calls services and ip_lists for Alert Configuration dashboard.
    * Added some field extraction for Alert Configuration dashboard.
    * Changed time extraction and used timestamp field for _time.

* **Version: 2.2.2**
    * Fixed the bug while saving the data input.

* **Version: 2.2.1**
    * Extracted pce_fqdn field for illumio:pce:metadata source type.
    * Removed "IP Adress of PCE Node" field from Data Inputs page.
    * Added "Hostname of PCE Node" field on Data Inputs page.

* **Version: 2.2.0**
    * Extracted new fields for source and destination labels.
    * Added encryption for "API Secret".
    * Added Validation for "Allowed port scanner Source IP addresses".
    * Removed "dnslookup" custom command.

* **Version: 2.1.0**
    * Added support of Illumio PCE 18.3.1, 19.1
    * For Illumio Cloud data coming from S3, added support of JSON data format for illumio:pce and illumio:pce:collector source types. 
    * Added test script to check the connection with Illumio server.

* **Version: 2.0.2**
    * Added support of Illumio PCE 18.2.1, 18.2.2, 18.2.3

* **Version: 2.0.1**
    * Fixed the issue of fqdn in host_details_lookup table when PCE URL contains special characters.

* **Version: 2.0.0**
    * This version of TA (2.0.0) is only compatible with Illumio PCE 18.2.0
    * This version of TA (2.0.0) is not compatible with Illumio PCE 17.X

# RECOMMENDED SYSTEM CONFIGURATION

* Standard Splunk configuration of Search Head, Indexer, and Forwarder.

# TOPOLOGY AND SETTING UP SPLUNK ENVIRONMENT

* This app has been distributed in two parts.

    1) Add-on app, which listens for Syslog messages from Illumio PCE and collects Illumio metadata using REST API Calls.
    
    2) The main app for visualizing Illumio PCE data.

* This App can be set up in two ways:

1) __Standalone Mode__:
  
    Install the main app and Add-on app.

   * Here both the app resides on a single machine.
   * The main app uses the data collected by Add-on app and builds dashboard on it.

2) __Distributed Environment__: 
  
    a) With heavy forwarder

    Install the main app and Add-on app on search head. Add-on app on heavy forwarder.
        
    * Configure Add-on app on heavy forwarder.
    * The main app on search head uses the received data and builds dashboards on it.
            
    b) With Splunk Universal Forwarder

    Install the main app and Add-on app on search head. Add-on app on universal forwarder and indexer.
 
    1. Configure Splunk Universal Forwarder to collect data from Illumio Server.
        * TCP SSL configuration
            * Create TCP-SSL stanza in $SPLUNK_HOME/etc/system/local/inputs.conf file.
                ```
                [tcp-ssl://<PORT>]
                index=<INDEX-NAME>
                sourcetype=illumio:pce
                ```              
            * Then Create a SSL stanza in $SPLUNK_HOME/etc/system/local/inputs.conf file.
                ```
                [SSL]
                serverCert = <path>
                sslPassword = <password>
                ```

                * To use Splunk default certificate add 
                    ```
                    [SSL]
                    serverCert = $SPLUNK_HOME/etc/auth/server.pem
                    sslPassword can be found in $SPLUNK_HOME/etc/system/local/server.conf or $SPLUNK_HOME/etc/system/default/server.conf under [sslConfig]
                    stanza
                    ```
            * Restart Splunk.

        * If you are using on-prem Splunk instance and you want to configure TCP instead of TCP-SSL follow below steps:
            * Remove -SSL from TCP-SSL stanza in $SPLUNK_HOME/etc/system/local/inputs.conf file.
            * Restart Splunk.


    2. Configure the Splunk Universal Forwarder to send the data to Splunk Indexer.
        * Execute below command on SUF.
     	    * $SPLUNK_HOME/bin/splunk add forward-server <IP>:<PORT> (Splunk Indexer IP and Listening Port)

    3. Configure Splunk Indexer to receive data from SUF.
        * Create below stanza in $SPLUNK_HOME/etc/system/local/inputs.conf file.
            ```
            [splunktcp://<PORT>]
            ```

# INSTALLATION IN SPLUNK CLOUD

* Same as on-premise setup.

# INSTALLATION OF APP

* This app can be installed through UI using "Manage Apps" or from the command line using the following command:

    ```sh
    $SPLUNK_HOME/bin/splunk install app $PATH_TO_SPL/TA-Illumio.spl/
    ```

* User can directly extract SPL file into $SPLUNK_HOME/etc/apps/ folder.


# USING SAMPLE DATA

* This app contains sample data in "sample" folder for ILLUMIO PCE 18.2.0, PCE 18.2.3 and PCE 19.1 which can be used to test visualization dashboards of Illumio App for Splunk application by populating sample data using SA-Eventgen app. Sample event data will be generated in index=main by default.
* To collect sample data, the user needs to place eventgen.conf at the following location:
  
    * $SPLUNK_HOME/etc/apps/TA-Illumio/local/eventgen.conf

* To get the required eventgen.conf, contact over provided support email below.

# Upgrade

### From v3.2.3 to v3.2.4
* No steps required.

### From v3.2.2 to v3.2.3
* No steps required.

### From v3.2.1 to v3.2.2
* No steps required.

### From v3.2.0 to v3.2.1
* No steps required.

### From v3.1.0 to v3.2.0
* No steps required.

### From v3.0.0 to v3.1.0
* No steps required.

### From v2.2.0 or below to 2.2.1

* If you are using "IP Address of PCE Node" field of Data Inputs page for Private IP addresses then follow the below steps after upgrading to version 2.2.1:

1. Go to Settings->Data Inputs->Illumio
2. Select the input name which had private ip addresses configured.
3. Add hostname corresponding to configured ip addresses in "Hostname of PCE Node" field.
4. Update the input.

### From v2.0.1 to v2.1.0 or above

* If you are using custom index for ingesting Illumio data into Splunk then kindly update "illumio_index" event type by following the below steps:

1. Go to Settings->Event types
2. Search for 'illumio_index' event type.
3. Edit search string for 'illumio_index' to index="custome_index_name". 

# APPLICATION SETUP

* After installation:

1. Go to Settings->Data inputs->Illumio
2. Enter all required information.
3. For TCP SSL configuration follow the below steps:

    1) Create a SSL stanza in $SPLUNK_HOME/etc/apps/<app_name>/local/inputs.conf file.
            
            [SSL]
            serverCert = <path>
            sslPassword = <password>
                
    2) To use Splunk default certificate add 
        
            [SSL]
            serverCert = $SPLUNK_HOME/etc/auth/server.pem
            sslPassword can be found in $SPLUNK_HOME/etc/system/local/server.conf or $SPLUNK_HOME/etc/system/default/server.conf under [sslConfig]
            stanza
         
    3) Restart Splunk.

4. If you want to configure TCP instead of TCP-SSL  follow below steps:

    1) Remove -SSL from TCP-SSL stanza in $SPLUNK_HOME/etc/system/local/inputs.conf file.
    2) Restart Splunk.

5. If you want to collect data over secure network with certificate check follow below steps:

    Steps to get root certificate:

    1) Copy the URL of Illumio and paste it into your browser. These instructions are for Firefox.
    2) Click View Page Info > Security > View Certificate > Details.
    3) Click on the root certificate.
    4) Export PEM file and use it in the configuration.

* Note: By default, all data is indexed to the main index. If you are using Illumio App for Splunk for visualization purpose and want to use a custom index then kindly update "illumio_get_index" macro in Illumio App for Splunk.

# APPLICATION SETUP for SaaS PCE:
* After installation:

1. Go to Settings->Data inputs->Illumio
2. Enter all required information.
3. Users can create AWS S3 input with the help of the following link: [How to create AWS S3 Inputs.](https://docs.splunk.com/Documentation/AddOns/released/AWS/S3)
4. SaaS users need to disable 'Illumio_Host_Details' and enable 'Illumio_Host_Details_S3' savedsearch in order to populate dashboards with SaaS PCE data.
> **NOTE** : Some dashboards/panels in the Illumio app may not populate when input is configured with SaaS PCE. Please refer to App's readme to check the list of affected dashboards.

# Custom Alert Action
* This application will add custom alert action named Mark Workload Quarantine Custom Alert Action. The user can configure this action on saved search. The user can pass following parameters to Mark Workload Quarantine:
    1) workload_uuid: workload_uuid in the incident.

# TEST ILLUMIO SERVER CONNECTION

* Follow the below steps to check the connection with Illumio Server.

	* Go to path $SPLUNK_HOME/etc/apps/TA-Illumio/bin
	* Run illumio_connection_test.py file with splunk cmd using this command: $SPLUNK_HOME/bin/splunk cmd python illumio_connection_test.py
	* Enter PCE URL, Username, Secret Key and Cert Path.
	* Appropriate connection Message will be printed on console.

# TROUBLESHOOTING

* Environment variable SPLUNK_HOME must be set.
* To troubleshoot Illumio application, check $SPLUNK_HOME/var/log/TA-Illumio/ta-illumio.log file.
* If data input is not getting saved then to check connection follow the steps described under "TEST ILLUMIO SERVER CONNECTION" section.
* If dashboards are not populating in the Illumio app when input is configured with SaaS PCE:
    * Make sure that you have configured AWS S3 input properly and data is being collected.

## UNINSTALL ADD-ON

To uninstall an add-on, user can follow below steps: SSH to the Splunk instance -> Go to folder apps ($SPLUNK_HOME/etc/apps) -> Remove the TA-Illumio folder from apps directory -> Restart Splunk

# EULA

* Custom EULA for Illumio. https://www.illumio.com/splunk-license-agreement

# SUPPORT

* Access questions and answers specific to Illumio App For Splunk at https://answers.splunk.com.
* Support Offered: Yes
* Support Email: splunkapp-support@illumio.com
* Please visit https://answers.splunk.com, and ask your question regarding Illumio Add-on for Splunk. Please tag your question with the correct App Tag, and your question will be attended to.

Copyright 2021 Illumio, Inc. All rights reserved.