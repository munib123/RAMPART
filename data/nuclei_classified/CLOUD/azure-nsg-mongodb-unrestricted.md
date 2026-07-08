# Vulnerability: Unrestricted MongoDB Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-mongodb-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted inbound access on TCP ports 27017, 27018, and 27019, used by MongoDB, to prevent unauthorized database access.

## Secure Mitigation
Modify NSG rules to restrict access on TCP ports 27017, 27018, and 27019. Only allow known IPs and implement database encryption and other security measures.

