# Vulnerability: Key Vault Trusted Microsoft Services Access Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-keyvault-trusted-ms-unrestricted.yaml`)

## Description
Ensure that "Allow trusted Microsoft services to bypass this firewall" exception is enabled within your Azure Key Vault network firewall configuration settings in order to grant vault access to trusted Azure cloud services. The trusted Microsoft services must also be given explicit permissions within the access policies associated with the Key Vault.

## Secure Mitigation
Enable the "Allow trusted Microsoft services to bypass this firewall" setting in your Key Vault network configuration to allow trusted services access.

