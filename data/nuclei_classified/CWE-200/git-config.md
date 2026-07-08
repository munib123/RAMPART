# Vulnerability: Git Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`git-config.yaml`)

## Description
Git configuration was detected via the pattern /.git/config and log file on passed URLs.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.git/config
```

