# Vulnerability: Server-Side Encryption with Customer Managed Key - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`sse-cmk-disabled.yaml`)

## Description
Ensure that Server-Side Encryption (SSE) is using customer-managed keys (CMKs) instead of service-managed keys to protect your OSS data at rest. SSE with customer-managed keys (also known as Bring Your Own Key - BYOK) enables you to have full control over the encryption and decryption process and meet strict compliance requirements.

