# Nuclei Template: Docker Compose - Detect
**Template ID:** docker-compose-config
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`docker-compose-config.yaml`)

## Vulnerability Information & PoC

## Description
Multiple Docker Compose configuration files were detected. The configuration allows deploy, combine and configure operations on multiple containers at the same time. The default is to outsource each process to its own container, which is then publicly accessible.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/docker-compose.yml
GET {{BaseURL}}/docker-compose.prod.yml
GET {{BaseURL}}/docker-compose.production.yml
GET {{BaseURL}}/docker-compose.staging.yml
GET {{BaseURL}}/docker-compose.dev.yml
GET {{BaseURL}}/docker-compose-dev.yml
GET {{BaseURL}}/docker-compose.override.yml
```

