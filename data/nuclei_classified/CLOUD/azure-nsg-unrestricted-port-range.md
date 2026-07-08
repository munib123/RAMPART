# Vulnerability: Restricted Port Range in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-unrestricted-port-range.yaml`)

## Description
Ensure that Azure network security groups (NSGs) do not have ranges of ports configured to allow inbound traffic, which can expose associated virtual machines to Denial-of-Service (DoS) or brute-force attacks. Only specific ports required by your application should be open following cloud security best practices.

## Secure Mitigation
Modify the NSG rules to only allow inbound traffic on necessary ports specific to your application requirements. This practice minimizes potential attack vectors.

