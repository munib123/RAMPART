# Vulnerability: Aurora Snapshot Tag Copy
**Classification:** CLOUD
**Source:** Nuclei Template (`aurora-copy-tags-snap.yaml`)

## Description
Ensures Amazon Aurora clusters have Copy Tags to Snapshots feature enabled to automatically copy tags from clusters to snapshots.

## Secure Mitigation
Enable Copy Tags to Snapshots for Aurora clusters via the AWS Management Console or modify the DB cluster to include this feature using AWS CLI.

