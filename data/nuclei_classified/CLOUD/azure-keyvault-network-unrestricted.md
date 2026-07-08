# Vulnerability: Unrestricted Network Access to Azure Key Vaults
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-keyvault-network-unrestricted.yaml`)

## Description
Ensure that your Microsoft Azure Key Vaults are configured to deny access to traffic from all networks (including the public Internet). By restricting the public access to your Azure Key Vaults, you add an important layer of security, since the default action is to accept connections from clients on any network. To limit access to trusted networks and/or IP addresses, you must change the Key Vault firewall default action from "Allow" to "Deny" and configure the appropriate access.

## Secure Mitigation
Modify Key Vault network settings to deny access from all networks by default. Configure network rules to allow access only from specific trusted IPs or networks.

