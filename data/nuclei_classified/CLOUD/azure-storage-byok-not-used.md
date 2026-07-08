# Vulnerability: Azure Storage Account Not Using BYOK
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-storage-byok-not-used.yaml`)

## Description
Ensure that your Azure Storage accounts are using customer-managed keys (also known as Bring Your Own Keys - BYOKs) instead of service-managed keys (default keys used by Microsoft Azure for data encryption), in order to have a more granular control over your Azure Storage data encryption and decryption process.

## Secure Mitigation
Configure your Azure Storage accounts to use customer-managed keys (BYOK) for data encryption to ensure compliance and enhanced security.

