# Vulnerability: Ruby on Rails Database Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`rails-database-config.yaml`)

## Description
Ruby on Rails database configuration file was detected, which may contain database credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config/database.yml
```

