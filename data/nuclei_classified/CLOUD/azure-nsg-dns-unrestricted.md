# Vulnerability: Unrestricted DNS Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-dns-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted inbound access on TCP and UDP port 53 to prevent DNS amplification attacks and other DNS-related threats.

## Secure Mitigation
Restrict access to DNS services by configuring NSG rules to only allow trusted sources and necessary traffic on TCP and UDP port 53.

