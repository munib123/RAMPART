# Vulnerability: Azure AKS RBAC Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-aks-rbac-unconfigured.yaml`)

## Description
Ensure that Kubernetes Role-Based Access Control (RBAC) is enabled for all Azure Kubernetes Service (AKS) clusters in order to achieve fine-grained control over AKS cluster resources. The Kubernetes Role-Based Access Control (RBAC) represents an efficient method of regulating access to Azure Kubernetes Service resources based on the roles of individual users or groups within an organization.

## Secure Mitigation
Ensure that Kubernetes Role-Based Access Control (RBAC) is enabled for each AKS cluster by configuring it during cluster creation or modifying existing clusters to enable RBAC settings.

