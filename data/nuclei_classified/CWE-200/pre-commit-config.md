# Vulnerability: Pre-commit Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pre-commit-config.yaml`)

## Description
Pre-commit configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.pre-commit-config.yaml
GET {{BaseURL}}/pre-commit-config.yaml
```

