# Vulnerability: Public CloudTrail Buckets
**Classification:** CLOUD
**Source:** Nuclei Template (`cloudtrail-public-buckets.yaml`)

## Description
Identifies AWS CloudTrail S3 buckets that are publicly accessible, risking exposure of sensitive log data.

## Secure Mitigation
Restrict S3 bucket access using bucket policies or IAM policies to ensure that CloudTrail logs are not publicly accessible.

