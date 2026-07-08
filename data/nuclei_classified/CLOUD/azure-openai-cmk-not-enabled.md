# Vulnerability: Azure OpenAI Encryption using Customer-Managed Keys Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-openai-cmk-not-enabled.yaml`)

## Description
Ensure that your Microsoft Azure OpenAI service instances are using Customer-Managed Keys (CMKs) instead of Microsoft-managed encryption keys (i.e., default keys used by Microsoft Azure for encryption at rest) in order to have a more granular control over your Azure OpenAI data encryption and decryption process.

## Secure Mitigation
Configure your Azure OpenAI instances to use Customer-Managed Keys by setting up encryption key attributes in the Azure Key Vault and then linking them to your OpenAI service instances.

