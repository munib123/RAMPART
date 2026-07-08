# Vulnerability: CloudTrail S3 Object Lock
**Classification:** CLOUD
**Source:** Nuclei Template (`s3-object-lock-not-enabled.yaml`)

## Description
Ensure Amazon CloudTrail S3 buckets have Object Lock enabled to prevent log deletion and ensure regulatory compliance.

## Secure Mitigation
Enable S3 Object Lock in Governance mode with a retention period that meets your compliance requirements for CloudTrail S3 buckets.

