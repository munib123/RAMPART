# Vulnerability: CloudTrail MFA Delete
**Classification:** CLOUD
**Source:** Nuclei Template (`cloudtrail-mfa-delete.yaml`)

## Description
Ensure Amazon CloudTrail buckets have MFA Delete enabled to protect log file deletion.

## Secure Mitigation
Enable MFA Delete on CloudTrail buckets via the S3 console or AWS CLI.

