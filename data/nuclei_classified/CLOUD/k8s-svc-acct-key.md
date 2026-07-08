# Vulnerability: Ensure service-account-key-file set
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-svc-acct-key.yaml`)

## Description
Checks if the service-account-key-file argument is properly set in the API server configuration, which is critical for validating service account tokens.

## Secure Mitigation
Configure the API server to use a service-account-key-file that points to a valid private key used to sign service account tokens. This setting should be part of the API server startup arguments or in its configuration file.

