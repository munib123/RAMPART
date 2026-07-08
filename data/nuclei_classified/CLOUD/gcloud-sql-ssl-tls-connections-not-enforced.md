# Vulnerability: Allow SSL/TLS Connections Only
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-ssl-tls-connections-not-enforced.yaml`)

## Description
Ensure that all incoming connections to your Cloud SQL database instances are encrypted with SSL/TLS to protect against eavesdropping and unauthorized access. The SSL enforcement mode must be set to "ENCRYPTED_ONLY" to enforce secure connections.

## Secure Mitigation
Set the SSL enforcement mode to "ENCRYPTED_ONLY" for all Cloud SQL database instances to ensure all incoming connections use SSL/TLS encryption.

