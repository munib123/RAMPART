# Vulnerability: Azure Redis Cache In-Transit Encryption Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-redis-nonssl-port-disabled.yaml`)

## Description
Ensure that the SSL connection to your Azure Redis Cache servers is enabled in order to meet cloud security and compliance requirements. Enforcing an SSL connection helps prevent unauthorized users from reading sensitive data that is intercepted as it travels through the network, between clients/applications and cache servers, known as data in transit.

## Secure Mitigation
Enable SSL on your Azure Redis Cache servers and ensure the non-SSL port (6379) is disabled to enforce encryption in transit.

