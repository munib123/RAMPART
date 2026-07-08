# Vulnerability: Queue Server Side Encryption - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`sqs-encryption-disabled.yaml`)

## Description
Ensure that your Amazon Simple Queue Service (SQS) queues are protecting the contents of their messages with Server-Side Encryption (SSE). Amazon SQS service uses a KMS Customer Master Key (CMK) to generate data keys required for the encryption/decryption process of the SQS messages.

## Secure Mitigation
Enable Server-Side Encryption (SSE) on the queue to protect sensitive data by encrypting it at rest using AWS KMS.

