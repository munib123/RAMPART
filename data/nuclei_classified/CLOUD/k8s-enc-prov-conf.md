# Vulnerability: Ensure that encryption providers are configured
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-enc-prov-conf.yaml`)

## Description
Checks if encryption providers are appropriately configured in Kubernetes, ensuring that data at rest is secured.

## Secure Mitigation
Ensure that the encryption provider configuration file is set up correctly and referenced properly in the API server configuration. Encryption should be enabled and configured according to the security best practices.

