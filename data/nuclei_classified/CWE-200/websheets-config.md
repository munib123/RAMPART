# Vulnerability: Websheets Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`websheets-config.yaml`)

## Description
Websheets configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ws-config.json
GET {{BaseURL}}/ws-config.example.json
```

