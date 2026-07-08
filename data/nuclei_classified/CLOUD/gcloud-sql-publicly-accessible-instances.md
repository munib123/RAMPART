# Vulnerability: Publicly Accessible Cloud SQL Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-publicly-accessible-instances.yaml`)

## Description
Ensure that your Google Cloud SQL database instances are configured to accept connections only from trusted networks and IP addresses. Publicly accessible instances may expose sensitive data to unauthorized access.

## Secure Mitigation
Configure your Cloud SQL database instances to accept connections only from trusted IP addresses and networks by limiting access to known authorized networks.

