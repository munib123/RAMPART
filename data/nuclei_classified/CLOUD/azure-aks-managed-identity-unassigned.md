# Vulnerability: Use System-Assigned Managed Identities for AKS Clusters
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-aks-managed-identity-unassigned.yaml`)

## Description
Ensure that your Azure Kubernetes Service (AKS) clusters are using system-assigned managed identities to allow secure application access to other Azure cloud resources such as load balancers, managed disks, and key vaults.

## Secure Mitigation
Ensure that all AKS clusters are configured to use system-assigned managed identities. This can be set during the AKS cluster creation or can be updated on existing clusters.

