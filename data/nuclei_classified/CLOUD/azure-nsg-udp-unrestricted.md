# Vulnerability: Unrestricted UDP Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-udp-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted inbound access on UDP ports to prevent unauthorized access and potential exploitation of vulnerabilities.

## Secure Mitigation
Restrict access to UDP ports by configuring NSG rules to only allow trusted sources and necessary traffic. Implement additional security measures where possible.

