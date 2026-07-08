# Vulnerability: ElastiCache Automatic Backups - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`cache-automatic-backups-disabled.yaml`)

## Description
Ensure that Amazon ElastiCache is configured to take automatic daily backups for Redis cache clusters.

## Secure Mitigation
enable automatic backups in the AWS Management Console for your ElastiCache Redis or Memcached cluster to ensure regular snapshots for data recovery.

