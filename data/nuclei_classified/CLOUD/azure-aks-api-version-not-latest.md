# Vulnerability: Azure AKS Kubernetes API Version Not Latest
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-aks-api-version-not-latest.yaml`)

## Description
To maximize the benefits of your Azure Kubernetes Service (AKS) clusters, it is important to ensure they are running on the latest Kubernetes version. By doing so, you gain access to new and improved features, as well as the latest security patches. The Kubernetes API upgrade becomes fully available only after it is approved by Microsoft Azure.

## Secure Mitigation
Upgrade the Kubernetes API version of your AKS clusters by following the Azure documentation to apply the latest approved updates and ensure all clusters are consistently using the most recent version available.

