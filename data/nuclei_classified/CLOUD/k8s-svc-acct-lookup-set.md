# Vulnerability: Ensure service-account-lookup set
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-svc-acct-lookup-set.yaml`)

## Description
Checks if the service-account-lookup argument is set to true in the API server configuration, which is essential for verifying service accounts against the stored secrets.

## Secure Mitigation
Set the service-account-lookup argument to true in the API server's startup arguments or configuration file to ensure proper verification of service accounts.

