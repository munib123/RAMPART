# Vulnerability: Symfony Security Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`symfony-security-config.yaml`)

## Description
Symfony security configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config/packages/security.yaml
GET {{BaseURL}}/app/config/security.yml
```

