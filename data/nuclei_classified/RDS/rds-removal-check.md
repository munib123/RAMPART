# Vulnerability: RDS Removal Check
**Classification:** RDS
**Source:** Nuclei Template (`rds-removal-check.yaml`)

## Description
Ensure that Remote Data Services (RDS) are either removed or not configured to reduce the risk of denial-of-service attacks or remote execution of administrative commands.
Compliance is met if any of the following conditions are true:
- IIS is not installed or in use,
- The default website does not include the /msadc virtual directory, or
- The relevant ADCLaunch registry keys associated with RDS are not present.

## Secure Mitigation
To mitigate RDS-related risks, take the following actions:
  - Remove the /msadc virtual directory from the default website.
  - Delete these registry keys:
    - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\RDSServer.DataFactory
    - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\AdvancedDataFactory
    - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\VbBusObj.VbBusObjCls

