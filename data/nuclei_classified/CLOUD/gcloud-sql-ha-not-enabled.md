# Vulnerability: High Availability Not Enabled for Cloud SQL Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-ha-not-enabled.yaml`)

## Description
Ensure that all your production and mission-critical Google Cloud SQL database instances are configured for High Availability (HA) and automatic failover support. Configuring HA ensures database reliability and minimizes downtime in the event of an outage.

## Secure Mitigation
Update the configuration of your Google Cloud SQL database instances to use High Availability (REGIONAL) instead of the default ZONAL configuration to enable automatic failover and ensure minimal downtime.

