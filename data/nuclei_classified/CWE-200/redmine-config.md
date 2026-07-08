# Vulnerability: Redmine Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`redmine-config.yaml`)

## Description
Redmine configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/configuration.yml
GET {{BaseURL}}/config/configuration.yml
GET {{BaseURL}}/redmine/config/configuration.yml
```

