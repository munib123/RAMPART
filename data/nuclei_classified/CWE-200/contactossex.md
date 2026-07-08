# Vulnerability: Contactos.sex User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`contactossex.yaml`)

## Description
Contactos.sex user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.contactossex.com/profile/{{user}}
```

