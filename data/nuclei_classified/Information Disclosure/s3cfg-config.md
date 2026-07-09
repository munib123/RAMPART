# Nuclei Template: S3CFG Configuration - Detect
**Template ID:** s3cfg-config
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`s3cfg-config.yaml`)

## Vulnerability Information & PoC

## Description
S3CFG configuration file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.s3cfg
```

## References
- https://s3tools.org/kb/item14.htm
