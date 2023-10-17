[illumio_quarantine]

param._cam = <json>
    * JSON specification for specifying response actions.
    * For more information, refer to Appendix A of the Splunk_SA_CIM app.

param.workload_href = <string>
    * HREF of the workload to quarantine.
    * Required.
    * Must be of the form "/orgs/<org_id>/workloads/<UUID>"

param.pce_fqdn = <string>
    * PCE fully-qualified domain name.
    * Required.
    * Must correspond to the PCE domain name configured for an illumio modular input.

param.org_id = <int>
    * PCE organization ID to identify the PCE tenant.
    * Required.
    * Must be an integer >= 1, and must correspond to the org ID configured for an illumio modular input.
    * Defaults to 1.
