# Vulnerability: Azure Storage Queue Logging Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-storage-queue-logging-disabled.yaml`)

## Description
Ensure that Microsoft Azure Storage Queue service logging is enabled for read, write, and delete requests. The Storage Queue service records details of both successful and failed requests, including end-to-end latency, server latency, and authentication information, which is crucial for security and compliance.

## Secure Mitigation
Enable logging for read, write, and delete requests in Azure Storage Queue service to ensure compliance and improve security monitoring.

