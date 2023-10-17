[illumio://<name>]
    * Data input to pull object metadata as events from the Illumio PCE into Splunk.
    * The name must be unique.

pce_url = <value>
    * The full URL of the Illumio PCE to connect to. If a scheme is not provided,
      https:// is used by default.
    * If a port is not provided, it is assumed to be the default for the given
      scheme (80 for HTTP, 443 for HTTPS).
    * Example value: https://my.pce.com:8443

api_key_id = <value>
    * The API key ID to use when connecting to the PCE.
    * Example value: api_145a5c788e63c30a3

org_id = <value>
    * The ID of the Illumio PCE organization to connect to.
    * Default: 1

port_number = <value>
    * Designates a port on the Splunk instance to receive syslog events from the
      Illumio PCE.
    * There must not be an existing TCP input for the given port.
    * Only used for direct forwarding from the PCE; syslogs pulled from AWS S3
      must be configured separately.

enable_tcp_ssl = <value>
    * Toggles SSL for the TCP syslog input. The [SSL] stanza must be configured
      separately.
    * Default: 1

port_scan_threshold = <value>
    * Defines a threshold that will trigger an alert when more than `port_scan_threshold`
      ports are scanned within `port_scan_interval` seconds.
    * Default: 10

port_scan_interval = <value>
    * The interval, in seconds, within which `port_scan_threshold` scanned ports will
      trigger an alert.
    * Default: 60

quarantine_labels = <value>
    * Optional comma-separated list of label key:value pairs representing a quarantine
      zone scope in the PCE.
    * Configured labels are applied to selected workloads when the `illumio_quarantine`
      action is run.
    * The labels must exist in the PCE and any policy restricing access to the
      quarantine zone must be defined separately.
    * Must be of the form key1:value1,...,keyN:valueN
    * Keys and values are case-sensitive.

self_signed_cert_path = <value>
    * Optional self-signed CA PEM file to use when connecting to the PCE.

http_proxy = <value>
    * Optional HTTP proxy address to use when connecting to the PCE.

https_proxy = <value>
    * Optional HTTPS proxy address to use when connecting to the PCE.

http_retry_count = <value>
    * Number of times to retry HTTP requests to the PCE. Each retry has an
      incremental backoff, starting at 1 second, then 2, then increasing
      exponentially with subsequent retries.
    * Default: 5

http_request_timeout = <value>
    * Total HTTP request timeout in seconds. Regardless of the retry count, if the
      request has been unsuccessful for more than this many seconds, it will fail
      with a timeout error.
    * Default: 30 (seconds)

allowed_ips = <value>
    * Comma-separated list of source IP addresses to exempt from port scan alerts.

interval = <value>
    * How often to run the modular input. The value can be an integer (representing
      the number of seconds between each run) or a cron expression.
    * Default: 1800 (seconds)
