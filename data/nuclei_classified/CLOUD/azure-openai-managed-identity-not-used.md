# Vulnerability: Azure OpenAI Service Instance Managed Identity Not Used
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-openai-managed-identity-not-used.yaml`)

## Description
Ensure that your Azure OpenAI service instances are using system-assigned and/or user-assigned managed identities to allow secure access to other cloud protected resources such as Azure key vaults. Managed identities minimizes risks, simplifies management, and maintains compliance with evolving cloud services.

## Secure Mitigation
Configure your Azure OpenAI service instances to use either system-assigned or user-assigned managed identities to enhance security and simplify resource access management.

