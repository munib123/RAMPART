# Vulnerability: Azure Blob Storage Lifecycle Management Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-blob-lifecycle-not-enabled.yaml`)

## Description
Ensure there is a lifecycle management policy configured for your Microsoft Azure Blob Storage data in order to meet compliance requirements when it comes to security and cost optimization. Azure Storage lifecycle management offers a rich, rule-based policy for general purpose and blob storage accounts. Use the lifecycle management policy to transition your Azure cloud data to the appropriate access tiers or expire it at the end of the data's lifecycle.

## Secure Mitigation
Configure a lifecycle management policy for your Azure Blob Storage accounts to enable automatic transitioning or expiration of data as appropriate.

