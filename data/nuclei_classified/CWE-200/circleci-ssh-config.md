# Vulnerability: CircleCI SSH Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`circleci-ssh-config.yaml`)

## Description
CircleCI ssh-config file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.circleci/ssh-config
```

