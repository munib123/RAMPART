# Vulnerability: Unrestricted Outbound Network Access in Google Cloud Functions
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-func-unrestricted-outbound.yaml`)

## Description
Ensure that your Google Cloud functions are not configured to allow unrestricted outbound network access in order to prevent security vulnerabilities and minimize cloud costs. To ensure that your function's outbound traffic is restricted to internal IP ranges and can't communicate with external networks or the public Internet, set the VpcConnectorEgressSettings parameter to PRIVATE_RANGES_ONLY.

## Secure Mitigation
Configure the VpcConnectorEgressSettings of your Google Cloud functions to PRIVATE_RANGES_ONLY to ensure all outgoing traffic is limited to internal IP ranges only.

