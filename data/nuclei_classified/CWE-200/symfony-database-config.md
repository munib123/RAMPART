# Vulnerability: Symfony Database Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`symfony-database-config.yaml`)

## Description
Symfony database configuration file was detected and may contain database credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config/databases.yml
```

