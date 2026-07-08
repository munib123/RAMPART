# Vulnerability: Azure KeyVault Resource Lock Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-keyvault-resource-lock-check.yaml`)

## Description
Ensure that all your mission critical Azure cloud resources have resource locks enabled so that certain users are not able to delete or modify these resources in order to help prevent accidental and malicious changes or deletion.

## Secure Mitigation
Apply resource locks to all critical Azure resources, particularly Key Vaults. Use either the "ReadOnly" or "CanNotDelete" lock levels to prevent unwanted changes or deletions.

