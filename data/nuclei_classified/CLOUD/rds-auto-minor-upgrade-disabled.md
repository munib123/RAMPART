# Vulnerability: RDS Auto Minor Version Upgrade - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`rds-auto-minor-upgrade-disabled.yaml`)

## Description
Ensure that your Amazon RDS database instances have the Auto Minor Version Upgrade flag enabled in order to receive automatically minor engine upgrades during the specified maintenance window.

## Secure Mitigation
Enable auto minor version upgrades for the RDS instance through the AWS Management Console, CLI, or API to ensure timely application of security patches and updates.

