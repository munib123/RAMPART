# Vulnerability: S3 Bucket with Public READ_ACP Access
**Classification:** CLOUD
**Source:** Nuclei Template (`s3-public-read-acp.yaml`)

## Description
Verifies that Amazon S3 buckets do not permit public 'READ_ACP' (LIST) access to anonymous users, protecting against unauthorized data exposure

