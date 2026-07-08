# Vulnerability: RDS Publicly Accessible - Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`rds-public-access.yaml`)

## Description
Check for any public-facing Amazon RDS database instances provisioned within your AWS cloud account and restrict unauthorized access in order to minimize security risks.

## Secure Mitigation
To restrict access to a publicly accessible database instance, you must disable the PubliclyAccessible configuration flag, and update the security group associated with the database instance.

