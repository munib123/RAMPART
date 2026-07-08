# Vulnerability: Unrestricted MySQL Database Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-mysql-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted ingress access on TCP port 3306, used by MySQL Database, to prevent unauthorized database access and potential data breaches.

## Secure Mitigation
Modify NSG rules to restrict access on TCP port 3306. Allow connections only from trusted and necessary IP addresses to secure the MySQL databases against unauthorized access.

