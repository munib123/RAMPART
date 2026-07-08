# Vulnerability: Azure AKS Encryption at Rest Not Using Private Key Vault
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-aks-use-private-kv.yaml`)

## Description
Ensure that your Azure Kubernetes Service (AKS) clusters are configured with encryption at rest for Kubernetes secrets in etcd using a private Azure Key Vault.

## Secure Mitigation
Configure your AKS clusters to use private Azure Key Vaults for encryption at rest by setting the 'azureKeyVaultKms.keyVaultNetworkAccess' to 'Private'.

