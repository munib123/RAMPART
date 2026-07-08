# Vulnerability: ElastiCache Redis Multi-AZ - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`cache-redis-multiaz-disabled.yaml`)

## Description
Ensure that your Amazon ElastiCache Redis cache clusters are using a Multi-AZ deployment configuration to enhance reliability through automatic failover.

## Secure Mitigation
Enable Multi-AZ replication in the ElastiCache Redis settings or create a new cluster with Multi-AZ enabled to ensure high availability.

