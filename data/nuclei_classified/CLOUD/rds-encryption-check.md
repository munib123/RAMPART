# Vulnerability: RDS Instance Encryption
**Classification:** CLOUD
**Source:** Nuclei Template (`rds-encryption-check.yaml`)

## Description
Ensure that your Amazon RDS database instances are encrypted to fulfill compliance requirements for data-at-rest encryption.

## Secure Mitigation
Enable encryption for your Amazon RDS instances by modifying the instance and setting the "Storage Encrypted" option to true. For new instances, enable encryption within the launch wizard.

