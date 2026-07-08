# Vulnerability: Azure Storage Account Delete Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-storage-account-delete-unalerted.yaml`)

## Description
Ensure that a Microsoft Azure activity log alert is fired whenever a "Delete Storage Account" event is triggered within your cloud account. An Azure activity log alert fires each time the event that matches the condition specified in the alert configuration is triggered. The alert condition that this conformity rule checks for is "Whenever the Administrative Activity Log 'Delete Storage Account (Microsoft.Storage/storageAccounts)' has 'any' Event level, with 'any' status and event is initiated by 'any'".

## Secure Mitigation
Ensure alert rules are configured to fire on "Delete Storage Account" events by setting the alert condition to "Microsoft.Storage/storageAccounts/delete" and ensuring that an action group is attached to manage notifications.

