# Vulnerability: Azure Storage Overly Permissive Stored Access Policies
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-storage-overly-permissive-sap.yaml`)

## Description
Ensure that your Microsoft Azure Storage shared access signatures don't have full access to your storage account resources (i.e. blob objects, files, tables, and queues) via stored access policies. A stored access policy provides an additional level of control over service-level shared access signatures, enhancing security by managing constraints for one or more shared access signatures.

## Secure Mitigation
Review and restrict the permissions in your stored access policies to ensure they align with the principle of least privilege.

