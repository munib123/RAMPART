# Vulnerability: Docker Cloud Yaml - File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`docker-cloud.yaml`)

## Description
Docker cloud internal yaml file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/docker-cloud.yml
```

