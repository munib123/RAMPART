# Vulnerability: CentreStack Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gladinet-centrestack-panel.yaml`)

## Description
Gladinet CentreStack login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/portal/loginpage.aspx
```

