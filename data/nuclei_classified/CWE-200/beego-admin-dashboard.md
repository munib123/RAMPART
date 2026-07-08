# Vulnerability: Beego Admin Dashboard Panel- Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`beego-admin-dashboard.yaml`)

## Description
Beego Admin Dashboard panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/listconf?command=conf
```

