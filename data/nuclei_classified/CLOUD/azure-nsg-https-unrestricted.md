# Vulnerability: Unrestricted HTTPS Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-https-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted access on TCP port 443, used for HTTPS, to protect against unauthorized access and data breaches.

## Secure Mitigation
Modify NSG rules to restrict access on TCP port 443. Only allow known IPs, and consider using advanced security measures such as Web Application Firewalls.

