# Vulnerability: Azure Key Vault Delete Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-key-vault-delete-unalerted.yaml`)

## Description
Ensure that a Microsoft Azure activity log alert is fired whenever a "Delete Key Vault" event is triggered inside your Azure cloud account. An activity log alert fires each time the action event that matches the condition specified in the alert configuration is triggered. The alert condition that this conformity rule checks for is "Whenever the Activity Log has an event with Category='Administrative', Signal name='Delete Key Vault (vaults)'".

## Secure Mitigation
Configure alert rules to monitor and notify whenever "Delete Key Vault" events occur by setting the alert condition to "Microsoft.KeyVault/vaults/delete" and attaching an action group to manage notifications.

