# Vulnerability: Azure API Management User-Assigned Managed Identity Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-apim-user-assigned-id-not-used.yaml`)

## Description
Ensure that your Azure API Management service instances are using user-assigned managed identities for fine-grained control over access permissions. This helps in maintaining proper security practices by providing specific identities for applications.

## Secure Mitigation
Configure user-assigned managed identities for your Azure API Management service instances to ensure only the necessary permissions are granted to each service.

