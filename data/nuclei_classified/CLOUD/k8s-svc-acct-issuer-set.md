# Vulnerability: Checks if service-account-issuer is correctly configured
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-svc-acct-issuer-set.yaml`)

## Description
Checks if the service-account-issuer argument is correctly configured in the API server, critical for issuing valid service tokens.

## Secure Mitigation
Set the service-account-issuer argument to a valid issuer URL in the API server's startup arguments or configuration file. This ensures the tokens issued are trusted across services.

