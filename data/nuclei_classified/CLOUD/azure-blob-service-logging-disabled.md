# Vulnerability: Azure Storage Blob Service Logging Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-blob-service-logging-disabled.yaml`)

## Description
Ensure that Azure Storage Blob service logging is enabled for read, write, and delete requests. The Storage Blob service provides scalable, cost-efficient objective storage in the Azure cloud. Storage logging is performed server-side and allows details for both successful and failed requests to be recorded in the associated storage account. These logs contain the following information about the individual requests: timing information such as start time, end-to-end latency, server latency, authentication details, concurrency information, and the size of the request/response.

## Secure Mitigation
Enable logging for the Azure Storage Blob service by setting the 'read', 'write', and 'delete' attributes to true in the storage account settings.

