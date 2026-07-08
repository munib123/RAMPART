# Vulnerability: Docker Compose - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`docker-compose-config.yaml`)

## Description
Multiple Docker Compose configuration files were detected. The configuration allows deploy, combine and configure operations on multiple containers at the same time. The default is to outsource each process to its own container, which is then publicly accessible.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/docker-compose.yml
GET {{BaseURL}}/docker-compose.prod.yml
GET {{BaseURL}}/docker-compose.production.yml
GET {{BaseURL}}/docker-compose.staging.yml
GET {{BaseURL}}/docker-compose.dev.yml
GET {{BaseURL}}/docker-compose-dev.yml
GET {{BaseURL}}/docker-compose.override.yml
```

