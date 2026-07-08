# Vulnerability: System-Assigned Managed Identities for Azure Functions
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-functionapp-system-assigned-missing.yaml`)

## Description
Ensure that functions managed with Azure Function App are using system-assigned managed identities in order to allow secure application access to other Microsoft Azure cloud resources such as SQL databases, storage accounts, and key vaults. Using system-assigned managed identities minimizes risks, simplifies management, and maintains compliance with evolving Azure cloud services.

## Secure Mitigation
Enable system-assigned managed identities for your Azure Function Apps to enhance security and simplify the management of resource access.

