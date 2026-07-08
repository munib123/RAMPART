# Vulnerability: Anaqua Login - Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`anaqua-login-panel.yaml`)

## Description
Checks for the presence of Anaqua login page

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/anaqua/Public/Login.aspx?ReturnUrl=%2fanaqua%2f
```

