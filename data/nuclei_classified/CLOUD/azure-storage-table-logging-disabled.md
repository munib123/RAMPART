# Vulnerability: Azure Storage Table Logging Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-storage-table-logging-disabled.yaml`)

## Description
Ensure that Azure Storage Table service logging is enabled for read, write, and delete requests. The Azure Storage Table service stores structured NoSQL data in the cloud, providing a key/attribute store with a schema-less design. Storage logging is performed server-side and allows details for both successful and failed requests to be recorded in the associated storage account.

## Secure Mitigation
Enable logging for read, write, and delete requests in the Azure Storage Table service through the Azure portal or using the Azure CLI.

