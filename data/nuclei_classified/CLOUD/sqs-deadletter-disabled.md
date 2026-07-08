# Vulnerability: SQS Dead Letter Queue - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`sqs-deadletter-disabled.yaml`)

## Description
Identify any publicly accessible Amazon SQS queues and update their permissions in order to protect against unauthorized users.

## Secure Mitigation
Enable and configure a Dead Letter Queue (DLQ) to capture and isolate undelivered messages for troubleshooting and retries.

