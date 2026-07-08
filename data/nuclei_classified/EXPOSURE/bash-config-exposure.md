# Vulnerability: Bash Configuration - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`bash-config-exposure.yaml`)

## Description
Detected exposed bash configuration on web servers that could have contained sensitive information such as credentials, API keys, database connection strings, or internal paths.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.bashrc
GET {{BaseURL}}/.bash_profile
GET {{BaseURL}}/.profile
GET {{BaseURL}}/.zshrc
```

