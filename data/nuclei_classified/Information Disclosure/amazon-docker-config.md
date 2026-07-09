# Nuclei Template: Dockerrun AWS Configuration Page - Detect
**Template ID:** amazon-docker-config
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`amazon-docker-config.yaml`)

## Vulnerability Information & PoC

## Description
Dockerrun AWS configuration page was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/Dockerrun.aws.json
```

