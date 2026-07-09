# Nuclei Template: Beego Admin Dashboard Panel- Detect
**Template ID:** beego-admin-dashboard
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`beego-admin-dashboard.yaml`)

## Vulnerability Information & PoC

## Description
Beego Admin Dashboard panel was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/listconf?command=conf
```

## References
- https://github.com/beego
- https://twitter.com/shaybt12/status/1584112903577567234/photo/1
