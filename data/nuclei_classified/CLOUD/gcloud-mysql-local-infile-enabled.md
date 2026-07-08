# Vulnerability: Local Infile Enabled in MySQL Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-mysql-local-infile-enabled.yaml`)

## Description
Ensure that the local_infile database flag is disabled for your Google Cloud MySQL database instances in order to follow data security best practices. The local_infile flag allows loading data from a local file to a database table, which could pose a security risk if misused.

## Secure Mitigation
Disable the local_infile flag in your MySQL database instance configuration to enhance security and prevent potential misuse of the feature.

