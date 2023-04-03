[markquarantine]
param._cam = <json>
	* Json specification for classifying response actions.
    * Used in AR.
    * For more information refer Appendix A of Splunk_SA_CIM.
    * Defaults to None.

param.workload_uuid = <string>
	* Field defines workload_uuid in Illumio
	* Defaults to "workload_uuid from Incident"

param.host = <string>
	* Field defines host in Illumio
	* Defaults to "host from Incident"

param.orig_host = <string>
	* Field defines orig_host in Illumio
	* Defaults to "orig_host from Incident"

param.fqdn = <string>
	* Field defines fqdn in Illumio
	* Defaults to "fqdn from Incident"