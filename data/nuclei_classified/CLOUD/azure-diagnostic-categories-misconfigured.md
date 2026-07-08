# Vulnerability: Diagnostic Settings Categories on Azure Resources not configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-diagnostic-categories-misconfigured.yaml`)

## Description
Ensure that diagnostic settings are configured to log the appropriate activities from the Azure Monitor control/management plane. Proper configuration of diagnostic settings is crucial for effective monitoring and capturing essential management activities performed by resources on the Azure platform.

## Secure Mitigation
Configure diagnostic settings for each Azure resource to log necessary activities from the control/management plane, ensuring that all important events are captured and reviewed regularly for anomalies.

