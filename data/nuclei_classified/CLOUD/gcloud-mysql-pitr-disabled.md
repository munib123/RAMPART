# Vulnerability: Point-in-Time Recovery Disabled for MySQL Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-mysql-pitr-disabled.yaml`)

## Description
Ensure that the Point-in-Time Recovery (PITR) feature is enabled for all MySQL database instances deployed within your Google Cloud Platform (GCP) account. This feature allows you to recover data from a specific point in time at a minimal cost. Automated backups and binary logging must be enabled for your MySQL database instances to use PITR.

## Secure Mitigation
Enable binary logging and configure automated backups for your MySQL database instances to ensure that the PITR feature is enabled.

