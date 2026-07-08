# Vulnerability: Azure AKS Not Using CNI Mode
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-aks-cni-not-configured.yaml`)

## Description
Ensure that Azure Kubernetes Service (AKS) clusters are configured to use the Azure Container Networking Interface (CNI) mode instead of the default Kubenet networking mode to enhance the segregation of resources and controls in an enterprise environment.

## Secure Mitigation
Configure AKS clusters to use Azure CNI by setting the networkProfile.networkPlugin to 'azure' during AKS cluster setup or update the existing AKS clusters to use Azure CNI.

