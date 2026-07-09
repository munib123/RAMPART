# Nuclei Template: AWS Credentials - Detect
**Template ID:** aws-credentials
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`aws-credentials.yaml`)

## Vulnerability Information & PoC

## Description
AWS credentials found via /.aws/credentials endpoint.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.aws/credentials
```

## References
- https://aws.amazon.com/blogs/security/what-to-do-if-you-inadvertently-expose-an-aws-access-key/
