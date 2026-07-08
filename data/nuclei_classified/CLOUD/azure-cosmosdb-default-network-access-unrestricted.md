# Vulnerability: Azure Cosmos DB Default Network Access Unrestricted
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-cosmosdb-default-network-access-unrestricted.yaml`)

## Description
Ensure that your Azure Cosmos DB accounts are configured to deny access to traffic from all networks, including the public Internet. By restricting the public access to your Azure Cosmos DB accounts, you add an additional layer of security to the account resources, as the default action is to accept requests from any source. To limit access to trusted networks and/or IP addresses only, you must update the firewall and the virtual network configuration for your Cosmos DB accounts.

## Secure Mitigation
Update the firewall settings and enable Virtual Network filtering on your Azure Cosmos DB accounts to restrict access to trusted networks and IP addresses only.

