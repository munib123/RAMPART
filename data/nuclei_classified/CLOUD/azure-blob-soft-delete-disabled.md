# Vulnerability: Azure Blob Storage Soft Delete Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-blob-soft-delete-disabled.yaml`)

## Description
Ensure that Soft Delete feature is enabled for all your Microsoft Azure Storage blob objects (blobs and snapshots). Soft Delete enables you to save and recover blob data in case your Azure Storage blobs or blob snapshots are deleted. This extra layer of protection also extends to the Microsoft Azure blob data that is erased as the result of an overwrite operation. With Soft Delete feature enabled, when blob objects are deleted, they are transitioned to a soft deleted state instead of being permanently erased. When blob objects are overwritten, soft deleted snapshots are created to save the state of the overwritten blob data.

## Secure Mitigation
Enable the Soft Delete feature for all blob storage accounts via the Azure Portal or using Azure CLI commands to ensure data is recoverable even after deletion or overwriting.

