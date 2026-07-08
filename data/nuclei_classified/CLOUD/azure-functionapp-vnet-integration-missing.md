# Vulnerability: Virtual Network Integration for Azure Functions Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-functionapp-vnet-integration-missing.yaml`)

## Description
To follow Azure networking best practices and securely access cloud resources available within your Azure Virtual Network (VNet), ensure that Virtual Network integration is enabled for your Microsoft Azure Function Apps. With Virtual Network integration, you can restrict your Function App outbound connections to specific, trusted VNets only.

## Secure Mitigation
Enable Virtual Network integration for your Azure Function Apps to secure connections to trusted Virtual Networks.

