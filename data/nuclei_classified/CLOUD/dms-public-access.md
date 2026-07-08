# Vulnerability: Publicly Accessible DMS Replication Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`dms-public-access.yaml`)

## Description
Ensure that your Amazon Database Migration Service (DMS) are not publicly accessible from the Internet in order to avoid exposing private data and minimize security risks.

## Secure Mitigation
Restrict access to your DMS replication instances by configuring security groups and network access controls to allow connections only from trusted IP addresses and private subnets, ensuring that they are not publicly accessible.

