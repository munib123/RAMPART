# Vulnerability: Azure Storage Publicly Accessible Web Containers
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-storage-public-access.yaml`)

## Description
Ensure that the Microsoft Azure storage container where the exported activity log files are saved is not publicly accessible from the Internet, in order to avoid exposing sensitive data and minimize security risks.

## Secure Mitigation
Ensure that the Azure storage containers storing activity log files are configured to deny public access. Review and modify the public access settings of your storage accounts to protect sensitive data.

