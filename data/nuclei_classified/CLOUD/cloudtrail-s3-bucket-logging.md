# Vulnerability: CloudTrail S3 Logging
**Classification:** CLOUD
**Source:** Nuclei Template (`cloudtrail-s3-bucket-logging.yaml`)

## Description
Ensure AWS CloudTrail logs are captured in S3 buckets with Server Access Logging enabled for audit and forensic purposes.

## Secure Mitigation
Enable Server Access Logging on the S3 bucket used by CloudTrail. Configure the logging feature to capture all requests made to the CloudTrail bucket.

