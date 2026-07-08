# Vulnerability: Social msdn User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`social-msdn.yaml`)

## Description
Social msdn user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://social.msdn.microsoft.com/profile/{{user}}
```

