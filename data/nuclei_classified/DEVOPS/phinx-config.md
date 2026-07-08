# Vulnerability: Phinx Configuration Exposure
**Classification:** DEVOPS
**Source:** Nuclei Template (`phinx-config.yaml`)

## Description
Phinx configuration file was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/phinx.yml
```

