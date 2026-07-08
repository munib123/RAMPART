# Vulnerability: Unrestricted RPC Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-rpc-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted access on TCP port 135, used by Remote Procedure Call (RPC), to prevent unauthorized access and potential exploitation of network services.

## Secure Mitigation
Configure NSG rules to restrict access on TCP port 135. Ensure only necessary systems can initiate RPC, and apply strict monitoring and logging to detect unusual activities.

