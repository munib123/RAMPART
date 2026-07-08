# Vulnerability: Ruby on Rails secrets.yml File Exposure
**Classification:** CLOUD
**Source:** Nuclei Template (`secrets-file.yaml`)

## Description
Ruby on Rails internal secret file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/secrets.yml
GET {{BaseURL}}/config/secrets.yml
GET {{BaseURL}}/test/config/secrets.yml
GET {{BaseURL}}/redmine/config/secrets.yml
```

