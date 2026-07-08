# Vulnerability: BigAnt Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bigant-login-panel.yaml`)

## Description
BigAnt admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php/Home/login/index.html
```

