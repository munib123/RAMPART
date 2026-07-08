# Vulnerability: SQS Queue Exposed
**Classification:** CLOUD
**Source:** Nuclei Template (`sqs-queue-exposed.yaml`)

## Description
Identify any publicly accessible Amazon SQS queues and update their permissions in order to protect against unauthorized users.

## Secure Mitigation
Restrict access to the SQS Queue using IAM policies, ensuring only authorized users and services have necessary permissions, and enable server-side encryption for data protection.

