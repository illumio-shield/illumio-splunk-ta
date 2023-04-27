[illumio://<name>]
* Data input to pull object metadata as events from the Illumio PCE into Splunk.
* The name must be unique.

pce_url = <value>
* The full URL of the Illumio PCE to connect to.
* Example value: https://my.pce.com:8443

api_key_id = <value>
* The API key ID to use when connecting to the PCE.
* Example value: api_145a5c788e63c30a3

org_id = <value>
* The ID of the Illumio PCE organization to connect to.
* Default: 1

port_number = <value>
* Designates a port on the Splunk instance to receive syslog events from the
  Illumio PCE. There must not be an existing TCP input for the given port. Only
  used for direct push from the PCE; syslogs pulled from AWS S3 must be
  configured separately.

cnt_port_scan = <value>
* Along with time_interval_port, defines a threshold that will trigger an alert
  when more than cnt_port_scan ports are scanned within time_interval_port
  seconds.

time_interval_port = <value>
* The threshold, in seconds, within which cnt_port_scan scanned ports will
  trigger an alert.

self_signed_cert_path = <value>
* Optional self-signed CA PEM file to use when connecting to the PCE.

http_proxy = <value>
* Optional HTTP proxy address to use when connecting to the PCE.

https_proxy = <value>
* Optional HTTPS proxy address to use when connecting to the PCE.

quarantine_labels = <value>
*

allowed_ips = <value>
* Comma-separated list of IP addresses to exempt from the port scan alerts.

interval = <value>
* How often to run the modular input. The value can be an integer (representing
  the number of seconds between each run) or a cron expression.
* Default: 3600 (seconds)
