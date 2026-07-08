# Vulnerability: Fuel CMS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fuelcms-panel.yaml`)

## Description
Fuel CMS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/fuel/login
```

