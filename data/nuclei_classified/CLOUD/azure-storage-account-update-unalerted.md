# Vulnerability: Azure Storage Account Create/Update Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-storage-account-update-unalerted.yaml`)

## Description
Ensure that an Azure activity log alert is fired whenever "Create/Update Storage Account" events are triggered in your Microsoft Azure cloud account. Activity log alerts get triggered when a new activity log event that matches the condition specified in the alert configuration occurs. For this conformity rule, the matched condition is `Whenever the Activity Log has an event with Category="Administrative", Signal name="Create/Update Storage Account (Microsoft.Storage/storageAccounts)"`.

## Secure Mitigation
Ensure alert rules are properly configured to monitor and notify on "Create or Update Storage Account" events by setting the alert condition to "Microsoft.Storage/storageAccounts/write" and ensuring that an action group is attached to manage notifications.

