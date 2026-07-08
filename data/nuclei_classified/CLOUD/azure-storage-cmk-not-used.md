# Vulnerability: Azure Storage Account Not Using CMK
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-storage-cmk-not-used.yaml`)

## Description
Ensure that your Microsoft Azure Storage accounts are using Customer Managed Keys (CMKs) instead of Microsoft Managed Keys (i.e., default keys used by Microsoft Azure for data encryption), in order to have more granular control over your Azure Storage data encryption and decryption process.

## Secure Mitigation
Configure your Azure Storage accounts to use Customer Managed Keys for data encryption to enhance security and control.

