# Vulnerability: Azure AKS Managed Identity Not User-Assigned
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-aks-not-user-assigned.yaml`)

## Description
Ensure that your Azure Kubernetes Service (AKS) clusters are using user-assigned managed identities for fine-grained control over access permissions.

## Secure Mitigation
Configure your AKS clusters to use user-assigned managed identities by updating the identity type in the AKS cluster settings and specifying the appropriate managed identities.

