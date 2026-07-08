# Vulnerability: application.yaml detection
**Classification:** MISCONFIG
**Source:** Nuclei Template (`application-yaml.yaml`)

## Description
Finds Application YAML files which often contain sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/app.yaml
GET {{BaseURL}}/app.yml
GET {{BaseURL}}/application.yaml
GET {{BaseURL}}/application.yml
```

