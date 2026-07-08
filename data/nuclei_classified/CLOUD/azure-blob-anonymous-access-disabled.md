# Vulnerability: Azure Blob Anonymous Access Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-blob-anonymous-access-disabled.yaml`)

## Description
Ensure that public (anonymous) access is disabled for all the blob containers available within your Microsoft Azure storage accounts in order to protect your data against unauthorized access. Disabling public access at the storage account level overrides the public access setting configured for the individual blob containers in that storage account.

## Secure Mitigation
Disable public (anonymous) access to all blob containers in Azure storage accounts to protect your data against unauthorized access.

