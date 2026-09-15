# Nuclei Template: Configuration File - Detect
**Template ID:** config-json
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`config-json.yaml`)

## Vulnerability Information & PoC

## Description
Multiple configuration files were detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/config/default.json
GET {{BaseURL}}/config.json
GET {{BaseURL}}/config/config.json
GET {{BaseURL}}/credentials/config.json
```

