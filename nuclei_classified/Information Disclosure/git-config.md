# Nuclei Template: Git Configuration - Detect
**Template ID:** git-config
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`git-config.yaml`)

## Vulnerability Information & PoC

## Description
Git configuration was detected via the pattern /.git/config and log file on passed URLs.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.git/config
```

