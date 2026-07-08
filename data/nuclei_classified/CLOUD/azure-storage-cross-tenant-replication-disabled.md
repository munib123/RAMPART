# Vulnerability: Azure Storage Cross-Tenant Replication Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-storage-cross-tenant-replication-disabled.yaml`)

## Description
Ensure that the Cross-Tenant Replication feature is disabled for your Azure Storage accounts in order to prevent object replication across Microsoft Entra tenants. Cross-Tenant Replication enables replication of data across different Microsoft Entra tenants, allowing for redundancy and disaster recovery across organizational boundaries. Although advantageous for data accessibility and sharing, this feature also poses a significant security risk if not properly managed. Potential risks include unauthorized data access, data leakage, and compliance breaches.

## Secure Mitigation
Disable the Cross-Tenant Replication feature for Azure Storage accounts to ensure data is not replicated across different Microsoft Entra tenants without authorization.

