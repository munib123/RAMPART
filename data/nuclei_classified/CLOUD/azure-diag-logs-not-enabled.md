# Vulnerability: Diagnostic Logs Not Enabled for Azure Resources
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-diag-logs-not-enabled.yaml`)

## Description
Ensure that Diagnostic Logs are enabled for all the supported Azure resources to log interactions within your cloud resources. Logging every access request and operation to your cloud resources is a security best practice.

## Secure Mitigation
Enable Diagnostic Logs for all Azure resources and ensure logs are sent to a storage account and Log Analytics Workspace or an equivalent system. Logs should be kept in accessible storage for at least one year, then moved to cold storage.

