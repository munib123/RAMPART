# Vulnerability: Dell Wyse Management Suite Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dell-wyse-login.yaml`)

## Description
Dell Wyse Management Suite login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ccm-web/
```

