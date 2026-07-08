# Vulnerability: MobileIron Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mobileiron-login.yaml`)

## Description
MobileIron login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mifs/login.jsp
GET {{BaseURL}}/mifs/user/login.jsp
GET {{BaseURL}}/mifs/c/d/android.html
```

