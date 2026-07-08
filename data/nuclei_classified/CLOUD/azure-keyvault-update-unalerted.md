# Vulnerability: Azure Key Vault Update Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-keyvault-update-unalerted.yaml`)

## Description
Ensure that an Azure activity log alert is fired whenever "Update Key Vault" events are triggered within your Microsoft Azure cloud account. Activity log alerts get triggered when a new activity log event that matches the condition specified in the alert configuration occurs. For this conformity rule, the matched condition is "Whenever the Activity Log has an event with Category='Administrative', Signal name='Update Key Vault (vaults)'".

## Secure Mitigation
Configure alert rules to monitor and notify of "Update Key Vault" events by setting the alert condition to "Microsoft.KeyVault/vaults/write" and ensuring that an action group is attached for managing notifications.

