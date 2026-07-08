# Vulnerability: Oracle E-Business Suite Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`oracle-ebusiness-panel.yaml`)

## Description
Oracle E-Business Suite login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/OA_HTML/AppsLogin
```

