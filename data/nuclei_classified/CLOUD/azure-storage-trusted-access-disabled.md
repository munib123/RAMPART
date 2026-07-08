# Vulnerability: Azure Storage Trusted Microsoft Services Access Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-storage-trusted-access-disabled.yaml`)

## Description
Ensure that "Allow trusted Microsoft services to access this storage account" exception is enabled within your Azure Storage account configuration settings to grant access to trusted cloud services.

## Secure Mitigation
Enable the "Allow trusted Microsoft services to access this storage account" exception in the Azure portal under Storage account settings.

