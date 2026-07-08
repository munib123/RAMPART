# Vulnerability: Dockerrun AWS Configuration Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`amazon-docker-config.yaml`)

## Description
Dockerrun AWS configuration page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Dockerrun.aws.json
```

