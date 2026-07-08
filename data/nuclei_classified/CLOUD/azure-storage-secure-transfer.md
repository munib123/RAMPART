# Vulnerability: Azure Storage Secure Transfer Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-storage-secure-transfer.yaml`)

## Description
Ensure that all data transferred between clients and your Azure Storage account is encrypted using the HTTPS protocol. A Microsoft Azure Storage account contains data objects such as files, blobs, queues, tables, and disks. The storage account provides a unique namespace for your Azure Storage data that is accessible from anywhere in the world over HTTP/HTTPS. All data stored within your Azure Storage account is secure, scalable, durable, and highly available.

## Secure Mitigation
Enable "Secure transfer required" in your Azure Storage account settings to enforce HTTPS traffic only, ensuring all data in transit is encrypted.

