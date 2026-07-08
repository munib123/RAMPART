# Vulnerability: Ensure TLS config appropriately set
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-tls-config-set.yaml`)

## Description
Checks if the tls-cert-file and tls-private-key-file arguments are properly set in the API server configuration, which is essential for secure communication.

## Secure Mitigation
Configure the API server to use tls-cert-file and tls-private-key-file that point to a valid certificate and key file respectively. This setting should be part of the API server startup arguments or in its configuration file.

