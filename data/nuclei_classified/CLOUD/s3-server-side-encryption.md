# Vulnerability: Server-Side Encryption on Amazon S3 Buckets
**Classification:** CLOUD
**Source:** Nuclei Template (`s3-server-side-encryption.yaml`)

## Description
This template verifies if Amazon S3 buckets have server-side encryption enabled for protecting sensitive content at rest, using either AWS S3-managed keys (SSE-S3) or AWS KMS-managed keys (SSE-KMS).

