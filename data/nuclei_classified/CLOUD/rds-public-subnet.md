# Vulnerability: RDS Instance Private Subnet
**Classification:** CLOUD
**Source:** Nuclei Template (`rds-public-subnet.yaml`)

## Description
Ensure Amazon RDS database instances are not provisioned in VPC public subnets to avoid direct Internet exposure.

## Secure Mitigation
Migrate RDS instances to private subnets within the VPC and ensure proper network ACLs and security group settings are in place to restrict access.

