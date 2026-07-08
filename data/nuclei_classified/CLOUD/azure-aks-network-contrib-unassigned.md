# Vulnerability: Azure AKS Network Contributor Role Unassigned
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-aks-network-contrib-unassigned.yaml`)

## Description
Ensure that Azure Kubernetes Service (AKS) clusters are using the Network Contributor role for managing networking resources and accessing other Azure services within an Azure Virtual Network (VNet). The Network Contributor role enables seamless network management, facilitates service integration, and enhances overall security.

## Secure Mitigation
Ensure that the Network Contributor role is assigned to your AKS clusters within Azure to enable proper management of networking resources. This can be configured in the IAM settings of the Azure portal.

