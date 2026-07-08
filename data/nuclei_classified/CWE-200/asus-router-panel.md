# Vulnerability: Asus Router Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`asus-router-panel.yaml`)

## Description
Asus router login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Main_Login.asp
```

