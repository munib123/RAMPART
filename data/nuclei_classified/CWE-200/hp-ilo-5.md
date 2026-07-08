# Vulnerability: Hewlett Packard Integrated Lights Out 5 Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hp-ilo-5.yaml`)

## Description
Hewlett Packard Integrated Lights Out 5 login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/html/login.html
```

