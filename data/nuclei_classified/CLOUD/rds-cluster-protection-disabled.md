# Vulnerability: RDS Cluster Deletion Protection - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`rds-cluster-protection-disabled.yaml`)

## Description
Ensure that all your provisioned Amazon Aurora database clusters are protected from accidental deletion by having the Deletion Protection feature enabled at the Aurora cluster level.

## Secure Mitigation
Enable deletion protection for the RDS cluster via the AWS Management Console, CLI, or API to prevent accidental deletion.

