# Vulnerability: RDS Copy Tags to Snapshots - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`rds-copy-snap.yaml`)

## Description
Ensure that your Amazon RDS database instances make use of the Copy Tags to Snapshots feature in order to allow tags set on your database instances to be automatically copied to any automated or manual database snapshots that are created from these RDS instances.

## Secure Mitigation
Enable the "Copy Tags to Snapshots" option for the RDS instance in the AWS Management Console, CLI, or API to ensure that tags are automatically applied to any created snapshots.

