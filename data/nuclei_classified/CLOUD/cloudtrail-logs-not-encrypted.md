# Vulnerability: CloudTrail Logs Not Encrypted
**Classification:** CLOUD
**Source:** Nuclei Template (`cloudtrail-logs-not-encrypted.yaml`)

## Description
Ensure Amazon CloudTrail logs are encrypted at rest using AWS Key Management Service (KMS) to secure log data.

## Secure Mitigation
Enable Server-Side Encryption (SSE) for CloudTrail logs using an AWS KMS key through the CloudTrail console or AWS CLI.

