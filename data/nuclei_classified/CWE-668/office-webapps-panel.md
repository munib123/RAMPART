# Vulnerability: Office Web Apps Server Panel - Detect
**Classification:** CWE-668
**Source:** Nuclei Template (`office-webapps-panel.yaml`)

## Description
Microsoft Office Web App Login Panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/op/generate.aspx
GET {{BaseURL}}/op/wrongfiletype.htm
```

