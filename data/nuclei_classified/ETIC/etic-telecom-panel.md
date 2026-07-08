# Vulnerability: ETIC Telecom Device Login - Panel
**Classification:** ETIC
**Source:** Nuclei Template (`etic-telecom-panel.yaml`)

## Description
ETIC Telecom device login panel was discovered

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.htm
GET {{BaseURL}}/common.etic_cgi_portal/login.html
```

