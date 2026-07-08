# Vulnerability: Unrestricted ICMP Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-icmp-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted inbound access using Internet Control Message Protocol (ICMP) to prevent potential network-related attacks.

## Secure Mitigation
Configure NSG rules to restrict ICMP traffic. Only allow necessary ICMP types and codes and monitor ICMP activity to detect unusual patterns.

