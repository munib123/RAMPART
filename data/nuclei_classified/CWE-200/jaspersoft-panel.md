# Vulnerability: TIBCO Jaspersoft Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jaspersoft-panel.yaml`)

## Description
TIBCO Jaspersoft login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jasperserver/login.html?error=1
GET {{BaseURL}}/jasperserver-pro/login.html?error=1
```

