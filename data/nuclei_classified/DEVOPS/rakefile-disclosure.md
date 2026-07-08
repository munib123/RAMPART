# Vulnerability: Rakefile - File Disclosure
**Classification:** DEVOPS
**Source:** Nuclei Template (`rakefile-disclosure.yaml`)

## Description
Rakefile configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Rakefile
```

