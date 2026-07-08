# Vulnerability: Hikvision Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hikvision-info-leak.yaml`)

## Description
Hikvision configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config/user.xml
```

