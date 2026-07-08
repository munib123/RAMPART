# Vulnerability: Ventrilo Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ventrilo-config.yaml`)

## Description
Ventrilo configuration file was detected, The file discloses the application's Adminpassword and Password.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ventrilo_srv.ini
```

