# Vulnerability: SSL/TLS Not Enforced for Cloud SQL Incoming Connections
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-ssl-not-enforced.yaml`)

## Description
Enforce all incoming connections to your Cloud SQL database instances to use SSL/TLS only. If the SSL/TLS protocol is not enforced for all Cloud SQL connections, clients without a valid certificate are allowed to connect to the database, leading to potential security vulnerabilities.

## Secure Mitigation
Enable SSL/TLS for all incoming connections to your Cloud SQL instances. Update the SSL_MODE configuration to allow only encrypted connections.

