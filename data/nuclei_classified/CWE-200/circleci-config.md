# Vulnerability: CircleCI Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`circleci-config.yaml`)

## Description
CircleCI config.yml file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.circleci/config.yml
```

