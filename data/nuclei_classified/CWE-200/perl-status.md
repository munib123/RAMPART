# Vulnerability: Apache Mod_perl Status Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`perl-status.yaml`)

## Description
Apache mod_perl status page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/perl-status
```

