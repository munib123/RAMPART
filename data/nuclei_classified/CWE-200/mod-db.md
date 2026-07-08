# Vulnerability: Mod DB User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mod-db.yaml`)

## Description
Mod DB user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.moddb.com/members/{{user}}
```

