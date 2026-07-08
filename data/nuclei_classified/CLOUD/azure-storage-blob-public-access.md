# Vulnerability: Azure Storage Blob Public Access Not Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-storage-blob-public-access.yaml`)

## Description
Ensure that public (anonymous) access is disabled for all the blob containers available within your Microsoft Azure storage accounts in order to protect your data against unauthorized access. Disabling public access at the storage account level overrides the public access setting configured for the individual blob containers in that storage account.

## Secure Mitigation
Disable public access to all storage accounts containing blob containers to prevent unauthorized data access.

