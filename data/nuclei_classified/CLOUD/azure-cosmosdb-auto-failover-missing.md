# Vulnerability: Azure Cosmos DB Automatic Failover Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-cosmosdb-auto-failover-missing.yaml`)

## Description
Ensure that your Microsoft Azure Cosmos DB accounts are using the Automatic Failover feature in order to enable resource replication and fault tolerance at the account level. Automatic failover allows Azure Cosmos DB to failover to the Azure cloud region with the highest failover priority when the source region becomes unavailable, without any additional action from the application or the user. The Cosmos DB account must have two or more regions configured in order to enable the feature.

## Secure Mitigation
Enable the Automatic Failover feature on your Azure Cosmos DB accounts to ensure high availability and fault tolerance across multiple regions.

