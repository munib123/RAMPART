# Vulnerability: RDS Public Snapshot Exposure
**Classification:** CLOUD
**Source:** Nuclei Template (`rds-public-snapshot.yaml`)

## Description
Checks if AWS RDS database snapshots are publicly accessible, risking exposure of sensitive data.

## Secure Mitigation
Modify the snapshot's visibility settings to ensure it is not public, only shared with specific AWS accounts.

