# Vulnerability: Azure API Management Service System-Assigned Managed Identity Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-apim-system-assigned-identity-unconfigured.yaml`)

## Description
Ensure that your Azure API Management service instances are using system-assigned managed identities in order to allow secure access to other Microsoft Azure protected resources such as Azure Key Vaults. Using system-assigned managed identities minimizes risks, simplifies management, and maintains compliance with evolving cloud services.

## Secure Mitigation
Enable system-assigned managed identities for your Azure API Management service instances through the Azure portal or by configuring the ARM template of your instance to include a system-assigned identity.

