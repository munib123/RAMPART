# Vulnerability: IAM Database Authentication
**Classification:** CLOUD
**Source:** Nuclei Template (`iam-db-auth.yaml`)

## Description
Ensure IAM Database Authentication is enabled for RDS instances, allowing IAM service to manage database access, thereby removing the need to store user credentials within database configurations.

## Secure Mitigation
Enable IAM Database Authentication for MySQL and PostgreSQL RDS database instances to leverage IAM for secure, token-based access control.

