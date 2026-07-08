# Vulnerability: Azure Storage Minimum TLS Version Not Set to TLS1_2
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-storage-min-tls-version.yaml`)

## Description
Ensure that all your Microsoft Azure Storage accounts are using the latest available version of the TLS protocol in order to enhance the security of the connection between your storage accounts and their clients/applications, and comply with the industry standards.

## Secure Mitigation
Configure all Azure Storage accounts to use TLS version 1.2 as the minimum required version for connections to ensure compliance with industry standards and enhanced security.

