# Vulnerability: Archive Of Our Own Account User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`archive-of-our-own-account.yaml`)

## Description
Archive Of Our Own Account user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://archiveofourown.org/users/{{user}}
```

