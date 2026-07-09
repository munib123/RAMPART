# Nuclei Template: AWS Configuration - Detect
**Template ID:** aws-config
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`aws-config.yaml`)

## Vulnerability Information & PoC

## Description
AWS config found via /.aws/config.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.aws/config
```

