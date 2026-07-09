# Nuclei Template: Amazon Web Services S3 Explorer - Detect
**Template ID:** aws-s3-explorer
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`aws-s3-explorer.yaml`)

## Vulnerability Information & PoC

## Description
Amazon Web Services S3 Explorer page was detected. Page contains links to sensitive information.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.html
```

## References
- https://www.exploit-db.com/ghdb/7967
