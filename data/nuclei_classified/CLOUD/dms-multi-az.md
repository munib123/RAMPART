# Vulnerability: DMS Multi-AZ Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`dms-multi-az.yaml`)

## Description
Ensure that your Amazon Database Migration Service (DMS) replication instances are using Multi-AZ deployment configurations to provide High Availability (HA) through automatic failover to standby replicas in the event of a failure such as an Availability Zone (AZ) outage, an internal hardware or network outage, a software failure or in case of a planned maintenance session

## Secure Mitigation
Enable Multi-AZ support for your Database Migration Service to enhance availability and resilience, ensuring automatic failover and reducing downtime during outages.

