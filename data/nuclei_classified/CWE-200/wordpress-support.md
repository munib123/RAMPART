# Vulnerability: WordPress Support User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wordpress-support.yaml`)

## Description
WordPress Support user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://wordpress.org/support/users/{{user}}/
```

