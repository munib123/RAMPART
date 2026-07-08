# Vulnerability: Azure Log Profile Missing Critical Activity Categories
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-log-profile-all-activities.yaml`)

## Description
Ensure that the Log Profile created for your Azure cloud activity log is configured to collect logs for all the control and management activity categories, i.e. "Write", "Delete", and "Action", for security and compliance purposes. A Log Profile controls how the activity log is exported and retained within your Microsoft Azure cloud account.

## Secure Mitigation
Configure the Azure Log Profile to include all necessary activity categories such as "Write", "Delete", and "Action" to ensure comprehensive logging and compliance with security policies.

