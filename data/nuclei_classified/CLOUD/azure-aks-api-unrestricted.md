# Vulnerability: Azure AKS API Server Access Unrestricted
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-aks-api-unrestricted.yaml`)

## Description
Ensure that Azure Kubernetes Service (AKS) clusters are configured to use the API Server Authorized IP Address Ranges feature in order to limit which IP addresses and CIDRs can access the Kubernetes control plane.

## Secure Mitigation
Configure the AKS clusters to use API Server Authorized IP Address Ranges by setting the appropriate IP ranges in the AKS configuration to ensure that only authorized IPs have access to the Kubernetes control plane.

